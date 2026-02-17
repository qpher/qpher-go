package qpher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const sdkVersion = "0.1.0"

var retryableStatusCodes = map[int]bool{
	429: true,
	502: true,
	503: true,
	504: true,
}

type httpClient struct {
	apiKey     string
	baseURL    string
	timeout    time.Duration
	maxRetries int
	client     *http.Client
}

func newHTTPClient(apiKey string, opts *ClientOptions) *httpClient {
	timeout := time.Duration(opts.Timeout) * time.Second
	return &httpClient{
		apiKey:     apiKey,
		baseURL:    opts.BaseURL,
		timeout:    timeout,
		maxRetries: opts.MaxRetries,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (h *httpClient) doRequest(ctx context.Context, method, path string, body interface{}, params map[string]string) ([]byte, error) {
	fullURL := h.baseURL + path

	if len(params) > 0 {
		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}
		fullURL = fullURL + "?" + values.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	var lastErr error
	for attempt := 0; attempt <= h.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("x-api-key", h.apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "qpher-go/"+sdkVersion)

		// Reset body reader for retries
		if body != nil && attempt > 0 {
			jsonBody, _ := json.Marshal(body)
			req.Body = io.NopCloser(bytes.NewReader(jsonBody))
		}

		resp, err := h.client.Do(req)
		if err != nil {
			// Handle timeout/connection errors
			if ctx.Err() != nil {
				return nil, newError("Request cancelled", "ERR_CANCELLED", 499, "")
			}
			lastErr = err
			if attempt < h.maxRetries {
				h.backoff(attempt)
				continue
			}
			return nil, newError("Connection failed", "ERR_SERVICE_001", 503, "")
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		if resp.StatusCode >= 400 {
			apiErr := h.parseErrorResponse(respBody, resp.StatusCode)
			if retryableStatusCodes[resp.StatusCode] && attempt < h.maxRetries {
				lastErr = apiErr
				h.backoff(attempt)
				continue
			}
			return nil, apiErr
		}

		return respBody, nil
	}

	if lastErr != nil {
		if apiErr, ok := lastErr.(*Error); ok {
			return nil, apiErr
		}
		return nil, newError("Request failed after retries", "ERR_SERVICE_001", 503, "")
	}
	return nil, newError("Unexpected error", "ERR_INTERNAL_001", 500, "")
}

func (h *httpClient) get(ctx context.Context, path string, params map[string]string) ([]byte, error) {
	return h.doRequest(ctx, http.MethodGet, path, nil, params)
}

func (h *httpClient) post(ctx context.Context, path string, body interface{}) ([]byte, error) {
	return h.doRequest(ctx, http.MethodPost, path, body, nil)
}

func (h *httpClient) parseErrorResponse(body []byte, statusCode int) *Error {
	var errResp errorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return newError(
			fmt.Sprintf("HTTP %d", statusCode),
			fmt.Sprintf("ERR_UNKNOWN_%d", statusCode),
			statusCode,
			"",
		)
	}

	code := errResp.Error.ErrorCode
	if code == "" {
		code = fmt.Sprintf("ERR_UNKNOWN_%d", statusCode)
	}

	message := errResp.Error.Message
	if message == "" {
		message = fmt.Sprintf("HTTP %d", statusCode)
	}

	return newError(message, code, statusCode, errResp.RequestID)
}

func (h *httpClient) backoff(attempt int) {
	delay := time.Duration(500*pow2(attempt)) * time.Millisecond
	if delay > 10*time.Second {
		delay = 10 * time.Second
	}
	time.Sleep(delay)
}

func pow2(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 2
	}
	return result
}

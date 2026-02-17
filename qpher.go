// Package qpher provides the official Go SDK for the Qpher Post-Quantum Cryptography API.
//
// Example usage:
//
//	client := qpher.NewClient("qph_live_abc123", nil)
//
//	result, err := client.KEM.Encrypt(ctx, &qpher.EncryptInput{
//	    Plaintext:  []byte("Hello, Quantum World!"),
//	    KeyVersion: 2,
//	})
//	if err != nil {
//	    var qErr *qpher.Error
//	    if errors.As(err, &qErr) {
//	        log.Printf("Qpher error: %s (request: %s)", qErr.Code, qErr.RequestID)
//	    }
//	    return err
//	}
//
//	fmt.Println("Ciphertext:", result.Ciphertext)
package qpher

import (
	"errors"
	"strings"
)

const (
	// DefaultBaseURL is the default Qpher API base URL.
	DefaultBaseURL = "https://api.qpher.ai"
	// DefaultTimeout is the default request timeout in seconds.
	DefaultTimeout = 30
	// DefaultMaxRetries is the default number of retry attempts.
	DefaultMaxRetries = 3
)

// ClientOptions contains optional configuration for the Qpher client.
type ClientOptions struct {
	// BaseURL is the API base URL. Defaults to "https://api.qpher.ai".
	BaseURL string
	// Timeout is the request timeout in seconds. Defaults to 30.
	Timeout int
	// MaxRetries is the maximum number of retry attempts. Defaults to 3.
	MaxRetries int
}

// Client is the Qpher API client.
type Client struct {
	// KEM provides Kyber768 KEM encrypt/decrypt operations.
	KEM *KEMService
	// Signatures provides Dilithium3 sign/verify operations.
	Signatures *SignaturesService
	// Keys provides key lifecycle management operations.
	Keys *KeysService

	http *httpClient
}

// NewClient creates a new Qpher API client.
//
// The apiKey must start with "qph_" (e.g., "qph_live_abc123" or "qph_test_xyz789").
// Pass nil for opts to use default configuration.
func NewClient(apiKey string, opts *ClientOptions) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("qpher: api_key is required")
	}
	if !strings.HasPrefix(apiKey, "qph_") {
		return nil, errors.New("qpher: api_key must start with 'qph_'")
	}

	if opts == nil {
		opts = &ClientOptions{}
	}
	if opts.BaseURL == "" {
		opts.BaseURL = DefaultBaseURL
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxRetries == 0 {
		opts.MaxRetries = DefaultMaxRetries
	}

	// Strip trailing slash from base URL
	opts.BaseURL = strings.TrimSuffix(opts.BaseURL, "/")

	h := newHTTPClient(apiKey, opts)

	return &Client{
		KEM:        &KEMService{http: h},
		Signatures: &SignaturesService{http: h},
		Keys:       &KeysService{http: h},
		http:       h,
	}, nil
}

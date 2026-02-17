package qpher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ================== Client Tests ==================

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		apiKey  string
		opts    *ClientOptions
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid live API key",
			apiKey:  "qph_live_abc123",
			opts:    nil,
			wantErr: false,
		},
		{
			name:    "valid test API key",
			apiKey:  "qph_test_xyz789",
			opts:    nil,
			wantErr: false,
		},
		{
			name:    "empty API key",
			apiKey:  "",
			opts:    nil,
			wantErr: true,
			errMsg:  "api_key is required",
		},
		{
			name:    "invalid API key prefix",
			apiKey:  "invalid_key_12345",
			opts:    nil,
			wantErr: true,
			errMsg:  "api_key must start with 'qph_'",
		},
		{
			name:   "custom base URL",
			apiKey: "qph_live_abc123",
			opts: &ClientOptions{
				BaseURL: "https://custom.api.qpher.ai",
			},
			wantErr: false,
		},
		{
			name:   "custom timeout",
			apiKey: "qph_live_abc123",
			opts: &ClientOptions{
				Timeout: 60,
			},
			wantErr: false,
		},
		{
			name:   "custom max retries",
			apiKey: "qph_live_abc123",
			opts: &ClientOptions{
				MaxRetries: 5,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.apiKey, tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if client == nil {
					t.Error("expected client, got nil")
				} else {
					if client.KEM == nil {
						t.Error("KEM service is nil")
					}
					if client.Signatures == nil {
						t.Error("Signatures service is nil")
					}
					if client.Keys == nil {
						t.Error("Keys service is nil")
					}
				}
			}
		})
	}
}

func TestClientDefaultOptions(t *testing.T) {
	client, err := NewClient("qph_test_key", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.http.baseURL != DefaultBaseURL {
		t.Errorf("expected base URL %q, got %q", DefaultBaseURL, client.http.baseURL)
	}
	if client.http.maxRetries != DefaultMaxRetries {
		t.Errorf("expected max retries %d, got %d", DefaultMaxRetries, client.http.maxRetries)
	}
}

func TestClientStripTrailingSlash(t *testing.T) {
	client, err := NewClient("qph_test_key", &ClientOptions{
		BaseURL: "https://api.qpher.ai/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.HasSuffix(client.http.baseURL, "/") {
		t.Error("base URL should not have trailing slash")
	}
}

// ================== KEM Tests ==================

func TestKEMEncrypt(t *testing.T) {
	tests := []struct {
		name       string
		input      *EncryptInput
		response   map[string]interface{}
		statusCode int
		wantErr    bool
	}{
		{
			name: "successful encrypt",
			input: &EncryptInput{
				Plaintext:  []byte("Hello, Quantum World!"),
				KeyVersion: 2,
			},
			response: map[string]interface{}{
				"data": map[string]interface{}{
					"ciphertext":  base64.StdEncoding.EncodeToString([]byte("encrypted_data")),
					"key_version": 2,
					"algorithm":   "Kyber768",
				},
				"request_id": "req-123",
				"timestamp":  "2026-02-15T10:30:45.123Z",
			},
			statusCode: 200,
			wantErr:    false,
		},
		{
			name: "encrypt with deterministic mode",
			input: &EncryptInput{
				Plaintext:  []byte("Test data"),
				KeyVersion: 1,
				Mode:       "deterministic",
				Salt:       make([]byte, 32),
			},
			response: map[string]interface{}{
				"data": map[string]interface{}{
					"ciphertext":  base64.StdEncoding.EncodeToString([]byte("ct")),
					"key_version": 1,
					"algorithm":   "Kyber768",
				},
				"request_id": "req-123",
				"timestamp":  "2026-02-15T10:30:45.123Z",
			},
			statusCode: 200,
			wantErr:    false,
		},
		{
			name: "key not found",
			input: &EncryptInput{
				Plaintext:  []byte("data"),
				KeyVersion: 99,
			},
			response: map[string]interface{}{
				"error": map[string]interface{}{
					"error_code": "ERR_KEM_005",
					"message":    "Key version 99 not found",
				},
				"request_id": "req-123",
			},
			statusCode: 404,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.URL.Path != "/api/v1/kem/encrypt" {
					t.Errorf("expected /api/v1/kem/encrypt, got %s", r.URL.Path)
				}
				if r.Header.Get("x-api-key") != "qph_test_key" {
					t.Errorf("expected x-api-key header")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			client, _ := NewClient("qph_test_key", &ClientOptions{
				BaseURL:    server.URL,
				MaxRetries: 0,
			})

			result, err := client.KEM.Encrypt(context.Background(), tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result == nil {
					t.Error("expected result, got nil")
				} else {
					if result.KeyVersion != tt.input.KeyVersion {
						t.Errorf("expected key version %d, got %d", tt.input.KeyVersion, result.KeyVersion)
					}
					if result.Algorithm != "Kyber768" {
						t.Errorf("expected algorithm Kyber768, got %s", result.Algorithm)
					}
				}
			}
		})
	}
}

func TestKEMDecrypt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"plaintext":   base64.StdEncoding.EncodeToString([]byte("decrypted_data")),
				"key_version": 2,
				"algorithm":   "Kyber768",
			},
			"request_id": "req-123",
		})
	}))
	defer server.Close()

	client, _ := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})

	result, err := client.KEM.Decrypt(context.Background(), &DecryptInput{
		Ciphertext: []byte("encrypted_data"),
		KeyVersion: 2,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Plaintext) != "decrypted_data" {
		t.Errorf("expected plaintext 'decrypted_data', got %q", string(result.Plaintext))
	}
}

// ================== Signatures Tests ==================

func TestSignaturesSign(t *testing.T) {
	signature := make([]byte, 3293) // Dilithium3 signature size
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/signature/sign" {
			t.Errorf("expected /api/v1/signature/sign, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"signature":   base64.StdEncoding.EncodeToString(signature),
				"key_version": 1,
				"algorithm":   "Dilithium3",
			},
			"request_id": "req-123",
		})
	}))
	defer server.Close()

	client, _ := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})

	result, err := client.Signatures.Sign(context.Background(), &SignInput{
		Message:    []byte("Invoice #12345"),
		KeyVersion: 1,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Signature) != 3293 {
		t.Errorf("expected signature length 3293, got %d", len(result.Signature))
	}
	if result.Algorithm != "Dilithium3" {
		t.Errorf("expected algorithm Dilithium3, got %s", result.Algorithm)
	}
}

func TestSignaturesVerify(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"valid signature", true},
		{"invalid signature", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"valid":       tt.valid,
						"key_version": 1,
						"algorithm":   "Dilithium3",
					},
					"request_id": "req-123",
				})
			}))
			defer server.Close()

			client, _ := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})

			result, err := client.Signatures.Verify(context.Background(), &VerifyInput{
				Message:    []byte("Invoice #12345"),
				Signature:  []byte("signature"),
				KeyVersion: 1,
			})

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Valid != tt.valid {
				t.Errorf("expected valid=%v, got %v", tt.valid, result.Valid)
			}
		})
	}
}

// ================== Keys Tests ==================

func TestKeysGenerate(t *testing.T) {
	publicKey := []byte("public_key_bytes")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/kms/keys/generate" {
			t.Errorf("expected /api/v1/kms/keys/generate, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"key_version": 1,
				"algorithm":   "Kyber768",
				"status":      "active",
				"public_key":  base64.StdEncoding.EncodeToString(publicKey),
				"created_at":  "2026-02-15T10:30:45.123Z",
			},
			"request_id": "req-123",
		})
	}))
	defer server.Close()

	client, _ := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})

	result, err := client.Keys.Generate(context.Background(), &GenerateInput{
		Algorithm: "Kyber768",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeyVersion != 1 {
		t.Errorf("expected key version 1, got %d", result.KeyVersion)
	}
	if result.Status != "active" {
		t.Errorf("expected status 'active', got %s", result.Status)
	}
}

func TestKeysRotate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"key_version":     2,
				"algorithm":       "Kyber768",
				"public_key":      base64.StdEncoding.EncodeToString([]byte("new_key")),
				"old_key_version": 1,
			},
			"request_id": "req-123",
		})
	}))
	defer server.Close()

	client, _ := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})

	result, err := client.Keys.Rotate(context.Background(), &RotateInput{
		Algorithm: "Kyber768",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeyVersion != 2 {
		t.Errorf("expected key version 2, got %d", result.KeyVersion)
	}
	if result.OldKeyVersion != 1 {
		t.Errorf("expected old key version 1, got %d", result.OldKeyVersion)
	}
}

func TestKeysGetActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("algorithm") != "Kyber768" {
			t.Errorf("expected algorithm=Kyber768 query param")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"key_version": 2,
				"algorithm":   "Kyber768",
				"status":      "active",
				"public_key":  base64.StdEncoding.EncodeToString([]byte("key")),
				"created_at":  "2026-02-15T10:30:45.123Z",
			},
			"request_id": "req-123",
		})
	}))
	defer server.Close()

	client, _ := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})

	result, err := client.Keys.GetActive(context.Background(), &GetActiveInput{
		Algorithm: "Kyber768",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeyVersion != 2 {
		t.Errorf("expected key version 2, got %d", result.KeyVersion)
	}
	if result.Status != "active" {
		t.Errorf("expected status 'active', got %s", result.Status)
	}
}

func TestKeysList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"key_version": 1,
						"algorithm":   "Kyber768",
						"status":      "retired",
						"public_key":  base64.StdEncoding.EncodeToString([]byte("key1")),
						"created_at":  "2026-02-10T10:30:45.123Z",
					},
					{
						"key_version": 2,
						"algorithm":   "Kyber768",
						"status":      "active",
						"public_key":  base64.StdEncoding.EncodeToString([]byte("key2")),
						"created_at":  "2026-02-15T10:30:45.123Z",
					},
				},
				"total": 2,
			},
			"request_id": "req-123",
		})
	}))
	defer server.Close()

	client, _ := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})

	result, err := client.Keys.List(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected total 2, got %d", result.Total)
	}
	if len(result.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(result.Keys))
	}
}

func TestKeysListWithFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("algorithm") != "Dilithium3" {
			t.Errorf("expected algorithm=Dilithium3 query param")
		}
		if r.URL.Query().Get("status") != "active" {
			t.Errorf("expected status=active query param")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys":  []map[string]interface{}{},
				"total": 0,
			},
			"request_id": "req-123",
		})
	}))
	defer server.Close()

	client, _ := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})

	_, err := client.Keys.List(context.Background(), &ListKeysInput{
		Algorithm: "Dilithium3",
		Status:    "active",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKeysRetire(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"key_version": 1,
				"algorithm":   "Kyber768",
				"status":      "retired",
				"public_key":  base64.StdEncoding.EncodeToString([]byte("key")),
				"created_at":  "2026-02-10T10:30:45.123Z",
			},
			"request_id": "req-123",
		})
	}))
	defer server.Close()

	client, _ := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})

	result, err := client.Keys.Retire(context.Background(), &RetireInput{
		Algorithm:  "Kyber768",
		KeyVersion: 1,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "retired" {
		t.Errorf("expected status 'retired', got %s", result.Status)
	}
}

// ================== Error Tests ==================

func TestErrorMethods(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		method     string
		expected   bool
	}{
		{"authentication error", 401, "IsAuthenticationError", true},
		{"validation error", 400, "IsValidationError", true},
		{"not found error", 404, "IsNotFoundError", true},
		{"forbidden error", 403, "IsForbiddenError", true},
		{"rate limit error", 429, "IsRateLimitError", true},
		{"server error", 500, "IsServerError", true},
		{"timeout error", 504, "IsTimeoutError", true},
		{"connection error", 503, "IsConnectionError", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &Error{
				Message:    "Test error",
				Code:       "ERR_TEST",
				StatusCode: tt.statusCode,
			}

			var result bool
			switch tt.method {
			case "IsAuthenticationError":
				result = err.IsAuthenticationError()
			case "IsValidationError":
				result = err.IsValidationError()
			case "IsNotFoundError":
				result = err.IsNotFoundError()
			case "IsForbiddenError":
				result = err.IsForbiddenError()
			case "IsRateLimitError":
				result = err.IsRateLimitError()
			case "IsServerError":
				result = err.IsServerError()
			case "IsTimeoutError":
				result = err.IsTimeoutError()
			case "IsConnectionError":
				result = err.IsConnectionError()
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestErrorString(t *testing.T) {
	err := &Error{
		Message:    "Test error",
		Code:       "ERR_TEST_001",
		StatusCode: 400,
		RequestID:  "req-123",
	}

	errStr := err.Error()

	if !strings.Contains(errStr, "Test error") {
		t.Error("error string should contain message")
	}
	if !strings.Contains(errStr, "ERR_TEST_001") {
		t.Error("error string should contain code")
	}
	if !strings.Contains(errStr, "req-123") {
		t.Error("error string should contain request ID")
	}
}

// ================== HTTP Client Tests ==================

func TestHTTPClientAuthHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "qph_test_secret_key" {
			t.Errorf("expected x-api-key 'qph_test_secret_key', got %q", r.Header.Get("x-api-key"))
		}
		if !strings.Contains(r.Header.Get("User-Agent"), "qpher-go") {
			t.Error("User-Agent should contain 'qpher-go'")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"key_version": 1,
				"algorithm":   "Kyber768",
				"status":      "active",
				"public_key":  base64.StdEncoding.EncodeToString([]byte("key")),
				"created_at":  "2026-02-15T10:30:45.123Z",
			},
			"request_id": "req-123",
		})
	}))
	defer server.Close()

	client, _ := NewClient("qph_test_secret_key", &ClientOptions{BaseURL: server.URL})

	_, err := client.Keys.GetActive(context.Background(), &GetActiveInput{
		Algorithm: "Kyber768",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

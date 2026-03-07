package qpher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ================== Wrap Tests ==================

func TestWrap(t *testing.T) {
	symmetricKey := make([]byte, 32)
	for i := range symmetricKey {
		symmetricKey[i] = byte(i)
	}
	wrappedKey := make([]byte, 1200)
	for i := range wrappedKey {
		wrappedKey[i] = byte(i % 256)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/kem/key/wrap" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var reqBody struct {
			SymmetricKey string `json:"symmetric_key"`
			KeyVersion   int    `json:"key_version"`
			Algorithm    string `json:"algorithm"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		if reqBody.KeyVersion != 2 {
			t.Errorf("expected key_version 2, got %d", reqBody.KeyVersion)
		}
		if reqBody.SymmetricKey == "" {
			t.Error("expected symmetric_key in request")
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"wrapped_key":     base64.StdEncoding.EncodeToString(wrappedKey),
				"key_version":     2,
				"algorithm":       "Kyber768",
				"wrapping_method": "KEM-DEM",
			},
			"request_id": "req-wrap-001",
			"timestamp":  "2026-03-06T10:00:00Z",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	result, err := client.KEM.Wrap(context.Background(), &KeyWrapInput{
		SymmetricKey: symmetricKey,
		KeyVersion:   2,
	})
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	if len(result.WrappedKey) != 1200 {
		t.Errorf("expected wrapped key length 1200, got %d", len(result.WrappedKey))
	}
	if result.KeyVersion != 2 {
		t.Errorf("expected key_version 2, got %d", result.KeyVersion)
	}
	if result.Algorithm != "Kyber768" {
		t.Errorf("expected algorithm Kyber768, got %s", result.Algorithm)
	}
	if result.WrappingMethod != "KEM-DEM" {
		t.Errorf("expected wrapping_method KEM-DEM, got %s", result.WrappingMethod)
	}
	if result.RequestID != "req-wrap-001" {
		t.Errorf("expected request_id req-wrap-001, got %s", result.RequestID)
	}
}

func TestWrapWithXWing(t *testing.T) {
	wrappedKey := make([]byte, 1500)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody struct {
			Algorithm string `json:"algorithm"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		if reqBody.Algorithm != "X-Wing" {
			t.Errorf("expected algorithm X-Wing, got %s", reqBody.Algorithm)
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"wrapped_key":     base64.StdEncoding.EncodeToString(wrappedKey),
				"key_version":     1,
				"algorithm":       "X-Wing",
				"wrapping_method": "KEM-DEM",
			},
			"request_id": "req-wrap-xwing",
			"timestamp":  "2026-03-06T10:00:00Z",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	result, err := client.KEM.Wrap(context.Background(), &KeyWrapInput{
		SymmetricKey: make([]byte, 32),
		KeyVersion:   1,
		Algorithm:    "X-Wing",
	})
	if err != nil {
		t.Fatalf("wrap with X-Wing failed: %v", err)
	}

	if result.Algorithm != "X-Wing" {
		t.Errorf("expected algorithm X-Wing, got %s", result.Algorithm)
	}
}

func TestWrapInvalidAlgorithm(t *testing.T) {
	client, _ := NewClient("qph_test_key", nil)
	_, err := client.KEM.Wrap(context.Background(), &KeyWrapInput{
		SymmetricKey: make([]byte, 32),
		KeyVersion:   1,
		Algorithm:    "InvalidAlgo",
	})
	if err == nil {
		t.Fatal("expected error for invalid algorithm")
	}
}

// ================== Unwrap Tests ==================

func TestUnwrap(t *testing.T) {
	symmetricKey := make([]byte, 32)
	for i := range symmetricKey {
		symmetricKey[i] = byte(i + 10)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/kem/key/unwrap" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"symmetric_key": base64.StdEncoding.EncodeToString(symmetricKey),
				"key_version":   3,
				"algorithm":     "Kyber768",
			},
			"request_id": "req-unwrap-001",
			"timestamp":  "2026-03-06T10:00:00Z",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	result, err := client.KEM.Unwrap(context.Background(), &KeyUnwrapInput{
		WrappedKey: make([]byte, 1200),
		KeyVersion: 3,
	})
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}

	if len(result.SymmetricKey) != 32 {
		t.Errorf("expected symmetric key length 32, got %d", len(result.SymmetricKey))
	}
	if result.KeyVersion != 3 {
		t.Errorf("expected key_version 3, got %d", result.KeyVersion)
	}
	if result.Algorithm != "Kyber768" {
		t.Errorf("expected algorithm Kyber768, got %s", result.Algorithm)
	}
	if result.RequestID != "req-unwrap-001" {
		t.Errorf("expected request_id req-unwrap-001, got %s", result.RequestID)
	}
}

func TestUnwrapSendsCorrectRequest(t *testing.T) {
	wrappedKey := make([]byte, 1200)
	for i := range wrappedKey {
		wrappedKey[i] = byte(i % 256)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/kem/key/unwrap" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var reqBody struct {
			WrappedKey string `json:"wrapped_key"`
			KeyVersion int    `json:"key_version"`
			Algorithm  string `json:"algorithm"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		if reqBody.WrappedKey == "" {
			t.Error("expected wrapped_key in request")
		}
		if reqBody.KeyVersion != 5 {
			t.Errorf("expected key_version 5, got %d", reqBody.KeyVersion)
		}

		// Verify the wrapped key round-trips correctly via base64
		decoded, err := base64.StdEncoding.DecodeString(reqBody.WrappedKey)
		if err != nil {
			t.Fatalf("failed to decode wrapped_key: %v", err)
		}
		if len(decoded) != 1200 {
			t.Errorf("expected decoded wrapped_key length 1200, got %d", len(decoded))
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"symmetric_key": base64.StdEncoding.EncodeToString(make([]byte, 32)),
				"key_version":   5,
				"algorithm":     "Kyber768",
			},
			"request_id": "req-unwrap-002",
			"timestamp":  "2026-03-06T10:00:00Z",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.KEM.Unwrap(context.Background(), &KeyUnwrapInput{
		WrappedKey: wrappedKey,
		KeyVersion: 5,
	})
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}
}

func TestUnwrapError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"error_code": "ERR_KEM_005",
				"message":    "Key version 99 not found",
			},
			"request_id": "req-err-001",
		})
	}))
	defer server.Close()

	client, _ := NewClient("qph_test_key", &ClientOptions{
		BaseURL:    server.URL,
		MaxRetries: 0,
	})

	_, err := client.KEM.Unwrap(context.Background(), &KeyUnwrapInput{
		WrappedKey: make([]byte, 1200),
		KeyVersion: 99,
	})
	if err == nil {
		t.Fatal("expected error for key not found")
	}
}

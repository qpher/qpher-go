package qpher

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ================== SignHash Tests ==================

func TestSignHash(t *testing.T) {
	hash := sha256.Sum256([]byte("test document content"))
	signature := make([]byte, 3309)
	for i := range signature {
		signature[i] = byte(i % 256)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/signature/sign-hash" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var reqBody struct {
			Hash          string `json:"hash"`
			HashAlgorithm string `json:"hash_algorithm"`
			KeyVersion    int    `json:"key_version"`
			Algorithm     string `json:"algorithm"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		if reqBody.HashAlgorithm != "SHA-256" {
			t.Errorf("expected hash_algorithm SHA-256, got %s", reqBody.HashAlgorithm)
		}
		if reqBody.KeyVersion != 1 {
			t.Errorf("expected key_version 1, got %d", reqBody.KeyVersion)
		}
		if reqBody.Hash == "" {
			t.Error("expected hash in request")
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"signature":      base64.StdEncoding.EncodeToString(signature),
				"key_version":    1,
				"algorithm":      "Dilithium3",
				"hash_algorithm": "SHA-256",
				"signature_type": "detached",
			},
			"request_id": "req-signhash-001",
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

	result, err := client.Signatures.SignHash(context.Background(), &SignHashInput{
		Hash:          hash[:],
		HashAlgorithm: "SHA-256",
		KeyVersion:    1,
	})
	if err != nil {
		t.Fatalf("sign-hash failed: %v", err)
	}

	if len(result.Signature) != 3309 {
		t.Errorf("expected signature length 3309, got %d", len(result.Signature))
	}
	if result.KeyVersion != 1 {
		t.Errorf("expected key_version 1, got %d", result.KeyVersion)
	}
	if result.Algorithm != "Dilithium3" {
		t.Errorf("expected algorithm Dilithium3, got %s", result.Algorithm)
	}
	if result.HashAlgorithm != "SHA-256" {
		t.Errorf("expected hash_algorithm SHA-256, got %s", result.HashAlgorithm)
	}
	if result.SignatureType != "detached" {
		t.Errorf("expected signature_type detached, got %s", result.SignatureType)
	}
	if result.RequestID != "req-signhash-001" {
		t.Errorf("expected request_id req-signhash-001, got %s", result.RequestID)
	}
}

func TestSignHashWithCompositeMLDSA(t *testing.T) {
	hash := sha256.Sum256([]byte("composite test"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody struct {
			Algorithm string `json:"algorithm"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		if reqBody.Algorithm != "Composite-ML-DSA" {
			t.Errorf("expected algorithm Composite-ML-DSA, got %s", reqBody.Algorithm)
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"signature":      base64.StdEncoding.EncodeToString(make([]byte, 4000)),
				"key_version":    2,
				"algorithm":      "Composite-ML-DSA",
				"hash_algorithm": "SHA-256",
				"signature_type": "detached",
			},
			"request_id": "req-signhash-composite",
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

	result, err := client.Signatures.SignHash(context.Background(), &SignHashInput{
		Hash:          hash[:],
		HashAlgorithm: "SHA-256",
		KeyVersion:    2,
		Algorithm:     "Composite-ML-DSA",
	})
	if err != nil {
		t.Fatalf("sign-hash with Composite-ML-DSA failed: %v", err)
	}

	if result.Algorithm != "Composite-ML-DSA" {
		t.Errorf("expected algorithm Composite-ML-DSA, got %s", result.Algorithm)
	}
}

func TestSignHashInvalidHashAlgorithm(t *testing.T) {
	client, _ := NewClient("qph_test_key", nil)
	_, err := client.Signatures.SignHash(context.Background(), &SignHashInput{
		Hash:          make([]byte, 32),
		HashAlgorithm: "MD5",
		KeyVersion:    1,
	})
	if err == nil {
		t.Fatal("expected error for invalid hash algorithm")
	}
}

// ================== VerifyHash Tests ==================

func TestVerifyHashValid(t *testing.T) {
	hash := sha256.Sum256([]byte("verify this"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/signature/verify-hash" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"valid":          true,
				"key_version":    1,
				"algorithm":      "Dilithium3",
				"hash_algorithm": "SHA-256",
			},
			"request_id": "req-verifyhash-001",
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

	result, err := client.Signatures.VerifyHash(context.Background(), &VerifyHashInput{
		Hash:          hash[:],
		HashAlgorithm: "SHA-256",
		Signature:     make([]byte, 3309),
		KeyVersion:    1,
	})
	if err != nil {
		t.Fatalf("verify-hash failed: %v", err)
	}

	if !result.Valid {
		t.Error("expected valid=true, got false")
	}
	if result.KeyVersion != 1 {
		t.Errorf("expected key_version 1, got %d", result.KeyVersion)
	}
	if result.Algorithm != "Dilithium3" {
		t.Errorf("expected algorithm Dilithium3, got %s", result.Algorithm)
	}
	if result.HashAlgorithm != "SHA-256" {
		t.Errorf("expected hash_algorithm SHA-256, got %s", result.HashAlgorithm)
	}
	if result.RequestID != "req-verifyhash-001" {
		t.Errorf("expected request_id req-verifyhash-001, got %s", result.RequestID)
	}
}

func TestVerifyHashInvalid(t *testing.T) {
	hash := sha256.Sum256([]byte("tampered"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"valid":          false,
				"key_version":    1,
				"algorithm":      "Dilithium3",
				"hash_algorithm": "SHA-256",
			},
			"request_id": "req-verifyhash-002",
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

	result, err := client.Signatures.VerifyHash(context.Background(), &VerifyHashInput{
		Hash:          hash[:],
		HashAlgorithm: "SHA-256",
		Signature:     make([]byte, 3309),
		KeyVersion:    1,
	})
	if err != nil {
		t.Fatalf("verify-hash failed: %v", err)
	}

	if result.Valid {
		t.Error("expected valid=false, got true")
	}
}

func TestVerifyHashSendsCorrectRequest(t *testing.T) {
	hash := sha256.Sum256([]byte("request check"))
	sig := make([]byte, 3309)
	for i := range sig {
		sig[i] = byte(i % 256)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/signature/verify-hash" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var reqBody struct {
			Hash          string `json:"hash"`
			HashAlgorithm string `json:"hash_algorithm"`
			Signature     string `json:"signature"`
			KeyVersion    int    `json:"key_version"`
			Algorithm     string `json:"algorithm"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		if reqBody.Hash == "" {
			t.Error("expected hash in request")
		}
		if reqBody.HashAlgorithm != "SHA-512" {
			t.Errorf("expected hash_algorithm SHA-512, got %s", reqBody.HashAlgorithm)
		}
		if reqBody.Signature == "" {
			t.Error("expected signature in request")
		}
		if reqBody.KeyVersion != 3 {
			t.Errorf("expected key_version 3, got %d", reqBody.KeyVersion)
		}

		// Verify hash round-trips correctly via base64
		decoded, err := base64.StdEncoding.DecodeString(reqBody.Hash)
		if err != nil {
			t.Fatalf("failed to decode hash: %v", err)
		}
		if len(decoded) != 32 {
			t.Errorf("expected decoded hash length 32, got %d", len(decoded))
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"valid":          true,
				"key_version":    3,
				"algorithm":      "Dilithium3",
				"hash_algorithm": "SHA-512",
			},
			"request_id": "req-verifyhash-003",
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

	_, err = client.Signatures.VerifyHash(context.Background(), &VerifyHashInput{
		Hash:          hash[:],
		HashAlgorithm: "SHA-512",
		Signature:     sig,
		KeyVersion:    3,
	})
	if err != nil {
		t.Fatalf("verify-hash failed: %v", err)
	}
}

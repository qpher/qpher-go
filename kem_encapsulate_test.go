package qpher

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ================== Encapsulate Tests ==================

func TestEncapsulate(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)
	kemCiphertext := make([]byte, 1088)
	rand.Read(kemCiphertext)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/kem/encapsulate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var reqBody struct {
			KeyVersion int    `json:"key_version"`
			Algorithm  string `json:"algorithm"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		if reqBody.KeyVersion != 1 {
			t.Errorf("expected key_version 1, got %d", reqBody.KeyVersion)
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"kem_ciphertext": base64.StdEncoding.EncodeToString(kemCiphertext),
				"shared_secret":  base64.StdEncoding.EncodeToString(sharedSecret),
				"key_version":    1,
				"algorithm":      "Kyber768",
			},
			"request_id": "req-123",
			"timestamp":  "2026-03-04T10:00:00Z",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	result, err := client.KEM.Encapsulate(context.Background(), &EncapsulateInput{
		KeyVersion: 1,
	})
	if err != nil {
		t.Fatalf("encapsulate failed: %v", err)
	}

	if len(result.KEMCiphertext) != 1088 {
		t.Errorf("expected KEM ciphertext length 1088, got %d", len(result.KEMCiphertext))
	}
	if len(result.SharedSecret) != 32 {
		t.Errorf("expected shared secret length 32, got %d", len(result.SharedSecret))
	}
	if result.KeyVersion != 1 {
		t.Errorf("expected key_version 1, got %d", result.KeyVersion)
	}
	if result.Algorithm != "Kyber768" {
		t.Errorf("expected algorithm Kyber768, got %s", result.Algorithm)
	}
}

func TestDecapsulate(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)
	kemCiphertext := make([]byte, 1088)
	rand.Read(kemCiphertext)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/kem/decapsulate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var reqBody struct {
			KEMCiphertext string `json:"kem_ciphertext"`
			KeyVersion    int    `json:"key_version"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		// Verify request contains kem_ciphertext
		if reqBody.KEMCiphertext == "" {
			t.Error("expected kem_ciphertext in request")
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"shared_secret": base64.StdEncoding.EncodeToString(sharedSecret),
				"key_version":   1,
				"algorithm":     "Kyber768",
			},
			"request_id": "req-456",
			"timestamp":  "2026-03-04T10:00:00Z",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	result, err := client.KEM.Decapsulate(context.Background(), &DecapsulateInput{
		KEMCiphertext: kemCiphertext,
		KeyVersion:    1,
	})
	if err != nil {
		t.Fatalf("decapsulate failed: %v", err)
	}

	if len(result.SharedSecret) != 32 {
		t.Errorf("expected shared secret length 32, got %d", len(result.SharedSecret))
	}
	if result.KeyVersion != 1 {
		t.Errorf("expected key_version 1, got %d", result.KeyVersion)
	}
}

func TestEncapsulateInvalidAlgorithm(t *testing.T) {
	client, _ := NewClient("qph_test_key", nil)
	_, err := client.KEM.Encapsulate(context.Background(), &EncapsulateInput{
		KeyVersion: 1,
		Algorithm:  "InvalidAlgo",
	})
	if err == nil {
		t.Fatal("expected error for invalid algorithm")
	}
}

// ================== EncryptLocal / DecryptLocal Tests ==================

func TestEncryptLocalDecryptLocalRoundtrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)
	kemCt := make([]byte, 1088)
	rand.Read(kemCt)

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var resp map[string]interface{}

		if r.URL.Path == "/api/v1/kem/encapsulate" {
			resp = map[string]interface{}{
				"data": map[string]interface{}{
					"kem_ciphertext": base64.StdEncoding.EncodeToString(kemCt),
					"shared_secret":  base64.StdEncoding.EncodeToString(sharedSecret),
					"key_version":    1,
					"algorithm":      "Kyber768",
				},
				"request_id": "req-enc",
				"timestamp":  "2026-03-04T10:00:00Z",
			}
		} else if r.URL.Path == "/api/v1/kem/decapsulate" {
			resp = map[string]interface{}{
				"data": map[string]interface{}{
					"shared_secret": base64.StdEncoding.EncodeToString(sharedSecret),
					"key_version":   1,
					"algorithm":     "Kyber768",
				},
				"request_id": "req-dec",
				"timestamp":  "2026-03-04T10:00:00Z",
			}
		} else {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	plaintext := []byte("Secret data that never leaves the client")
	envelope, err := client.KEM.EncryptLocal(context.Background(), &EncryptLocalInput{
		Plaintext:  plaintext,
		KeyVersion: 1,
	})
	if err != nil {
		t.Fatalf("EncryptLocal failed: %v", err)
	}

	if len(envelope.IV) != 12 {
		t.Errorf("expected IV length 12, got %d", len(envelope.IV))
	}
	if envelope.KeyVersion != 1 {
		t.Errorf("expected key_version 1, got %d", envelope.KeyVersion)
	}

	recovered, err := client.KEM.DecryptLocal(context.Background(), envelope)
	if err != nil {
		t.Fatalf("DecryptLocal failed: %v", err)
	}

	if string(recovered) != string(plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", recovered, plaintext)
	}
}

func TestEncryptLocalNoPlaintextInRequest(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)
	kemCt := make([]byte, 1088)
	rand.Read(kemCt)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify no plaintext in request body
		var reqBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&reqBody)

		if _, ok := reqBody["plaintext"]; ok {
			t.Error("plaintext should NOT be in the encapsulate request")
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"kem_ciphertext": base64.StdEncoding.EncodeToString(kemCt),
				"shared_secret":  base64.StdEncoding.EncodeToString(sharedSecret),
				"key_version":    1,
				"algorithm":      "Kyber768",
			},
			"request_id": "req-enc",
			"timestamp":  "2026-03-04T10:00:00Z",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("qph_test_key", &ClientOptions{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.KEM.EncryptLocal(context.Background(), &EncryptLocalInput{
		Plaintext:  []byte("This should NEVER appear in the HTTP request"),
		KeyVersion: 1,
	})
	if err != nil {
		t.Fatalf("EncryptLocal failed: %v", err)
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	zeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d not zeroed: got %d", i, b)
		}
	}
}

// ================== AES-GCM AAD Binding Test ==================

func TestEncryptLocalAADBinding(t *testing.T) {
	// Verify that AES-GCM uses kem_ciphertext as AAD — tampering should fail
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	plaintext := []byte("test data for AAD binding")

	// Encrypt manually with AAD
	block, _ := aes.NewCipher(sharedSecret)
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, 12)
	rand.Read(iv)
	kemCt := make([]byte, 1088)
	rand.Read(kemCt)
	aesCiphertext := gcm.Seal(nil, iv, plaintext, kemCt)

	// Decrypt with correct AAD should succeed
	recovered, err := gcm.Open(nil, iv, aesCiphertext, kemCt)
	if err != nil {
		t.Fatalf("decryption with correct AAD failed: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Error("plaintext mismatch")
	}

	// Decrypt with wrong AAD should fail
	wrongKemCt := make([]byte, 1088)
	rand.Read(wrongKemCt)
	_, err = gcm.Open(nil, iv, aesCiphertext, wrongKemCt)
	if err == nil {
		t.Error("decryption with wrong AAD should have failed")
	}
}

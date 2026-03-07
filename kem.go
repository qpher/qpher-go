package qpher

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// Valid KEM algorithms.
var validKEMAlgorithms = map[string]bool{
	"Kyber768": true,
	"X-Wing":   true,
}

// KEMService handles KEM encrypt/decrypt operations (Kyber768, X-Wing).
type KEMService struct {
	http *httpClient
}

type encryptRequest struct {
	Plaintext  string `json:"plaintext"`
	KeyVersion int    `json:"key_version"`
	Mode       string `json:"mode"`
	Salt       string `json:"salt,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`
}

type encryptResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
		KeyVersion int    `json:"key_version"`
		Algorithm  string `json:"algorithm"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

type encapsulateRequest struct {
	KeyVersion int    `json:"key_version"`
	Algorithm  string `json:"algorithm,omitempty"`
}

type encapsulateResponse struct {
	Data struct {
		KEMCiphertext string `json:"kem_ciphertext"`
		SharedSecret  string `json:"shared_secret"`
		KeyVersion    int    `json:"key_version"`
		Algorithm     string `json:"algorithm"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

type decapsulateRequest struct {
	KEMCiphertext string `json:"kem_ciphertext"`
	KeyVersion    int    `json:"key_version"`
	Algorithm     string `json:"algorithm,omitempty"`
}

type decapsulateResponse struct {
	Data struct {
		SharedSecret string `json:"shared_secret"`
		KeyVersion   int    `json:"key_version"`
		Algorithm    string `json:"algorithm"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

type decryptRequest struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"key_version"`
	Algorithm  string `json:"algorithm,omitempty"`
}

type decryptResponse struct {
	Data struct {
		Plaintext  string `json:"plaintext"`
		KeyVersion int    `json:"key_version"`
		Algorithm  string `json:"algorithm"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

// Encrypt encrypts data using KEM (Kyber768 or X-Wing).
func (k *KEMService) Encrypt(ctx context.Context, input *EncryptInput) (*EncryptResult, error) {
	if input.Algorithm != "" && !validKEMAlgorithms[input.Algorithm] {
		return nil, fmt.Errorf("invalid KEM algorithm: %q", input.Algorithm)
	}

	mode := input.Mode
	if mode == "" {
		mode = "standard"
	}

	req := encryptRequest{
		Plaintext:  base64.StdEncoding.EncodeToString(input.Plaintext),
		KeyVersion: input.KeyVersion,
		Mode:       mode,
		Algorithm:  input.Algorithm,
	}

	if input.Salt != nil {
		req.Salt = base64.StdEncoding.EncodeToString(input.Salt)
	}

	body, err := k.http.post(ctx, "/api/v1/kem/encrypt", req)
	if err != nil {
		return nil, err
	}

	var resp encryptResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(resp.Data.Ciphertext)
	if err != nil {
		return nil, newError("Failed to decode ciphertext", "ERR_PARSE_002", 500, "")
	}

	return &EncryptResult{
		Ciphertext: ciphertext,
		KeyVersion: resp.Data.KeyVersion,
		Algorithm:  resp.Data.Algorithm,
		RequestID:  resp.RequestID,
	}, nil
}

// Decrypt decrypts data using KEM (Kyber768 or X-Wing).
func (k *KEMService) Decrypt(ctx context.Context, input *DecryptInput) (*DecryptResult, error) {
	if input.Algorithm != "" && !validKEMAlgorithms[input.Algorithm] {
		return nil, fmt.Errorf("invalid KEM algorithm: %q", input.Algorithm)
	}

	req := decryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(input.Ciphertext),
		KeyVersion: input.KeyVersion,
		Algorithm:  input.Algorithm,
	}

	body, err := k.http.post(ctx, "/api/v1/kem/decrypt", req)
	if err != nil {
		return nil, err
	}

	var resp decryptResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	plaintext, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return nil, newError("Failed to decode plaintext", "ERR_PARSE_002", 500, "")
	}

	return &DecryptResult{
		Plaintext:  plaintext,
		KeyVersion: resp.Data.KeyVersion,
		Algorithm:  resp.Data.Algorithm,
		RequestID:  resp.RequestID,
	}, nil
}

type keyWrapRequest struct {
	SymmetricKey string `json:"symmetric_key"`
	KeyVersion   int    `json:"key_version"`
	Algorithm    string `json:"algorithm,omitempty"`
}

type keyWrapResponse struct {
	Data struct {
		WrappedKey     string `json:"wrapped_key"`
		KeyVersion     int    `json:"key_version"`
		Algorithm      string `json:"algorithm"`
		WrappingMethod string `json:"wrapping_method"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

type keyUnwrapRequest struct {
	WrappedKey string `json:"wrapped_key"`
	KeyVersion int    `json:"key_version"`
	Algorithm  string `json:"algorithm,omitempty"`
}

type keyUnwrapResponse struct {
	Data struct {
		SymmetricKey string `json:"symmetric_key"`
		KeyVersion   int    `json:"key_version"`
		Algorithm    string `json:"algorithm"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

// Wrap wraps a symmetric key using KEM-DEM hybrid encryption.
func (k *KEMService) Wrap(ctx context.Context, input *KeyWrapInput) (*KeyWrapResult, error) {
	if input.Algorithm != "" && !validKEMAlgorithms[input.Algorithm] {
		return nil, fmt.Errorf("invalid KEM algorithm: %q", input.Algorithm)
	}

	req := keyWrapRequest{
		SymmetricKey: base64.StdEncoding.EncodeToString(input.SymmetricKey),
		KeyVersion:   input.KeyVersion,
		Algorithm:    input.Algorithm,
	}

	body, err := k.http.post(ctx, "/api/v1/kem/key/wrap", req)
	if err != nil {
		return nil, err
	}

	var resp keyWrapResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	wrappedKey, err := base64.StdEncoding.DecodeString(resp.Data.WrappedKey)
	if err != nil {
		return nil, newError("Failed to decode wrapped key", "ERR_PARSE_002", 500, "")
	}

	return &KeyWrapResult{
		WrappedKey:     wrappedKey,
		KeyVersion:     resp.Data.KeyVersion,
		Algorithm:      resp.Data.Algorithm,
		WrappingMethod: resp.Data.WrappingMethod,
		RequestID:      resp.RequestID,
	}, nil
}

// Unwrap unwraps a previously wrapped symmetric key.
func (k *KEMService) Unwrap(ctx context.Context, input *KeyUnwrapInput) (*KeyUnwrapResult, error) {
	if input.Algorithm != "" && !validKEMAlgorithms[input.Algorithm] {
		return nil, fmt.Errorf("invalid KEM algorithm: %q", input.Algorithm)
	}

	req := keyUnwrapRequest{
		WrappedKey: base64.StdEncoding.EncodeToString(input.WrappedKey),
		KeyVersion: input.KeyVersion,
		Algorithm:  input.Algorithm,
	}

	body, err := k.http.post(ctx, "/api/v1/kem/key/unwrap", req)
	if err != nil {
		return nil, err
	}

	var resp keyUnwrapResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	symmetricKey, err := base64.StdEncoding.DecodeString(resp.Data.SymmetricKey)
	if err != nil {
		return nil, newError("Failed to decode symmetric key", "ERR_PARSE_002", 500, "")
	}

	return &KeyUnwrapResult{
		SymmetricKey: symmetricKey,
		KeyVersion:   resp.Data.KeyVersion,
		Algorithm:    resp.Data.Algorithm,
		RequestID:    resp.RequestID,
	}, nil
}

// Encapsulate encapsulates a shared secret using tenant's KEM public key.
// The shared secret can be used as an AES-256-GCM key for local encryption.
// Plaintext never leaves your environment.
func (k *KEMService) Encapsulate(ctx context.Context, input *EncapsulateInput) (*EncapsulateResult, error) {
	if input.Algorithm != "" && !validKEMAlgorithms[input.Algorithm] {
		return nil, fmt.Errorf("invalid KEM algorithm: %q", input.Algorithm)
	}

	req := encapsulateRequest{
		KeyVersion: input.KeyVersion,
		Algorithm:  input.Algorithm,
	}

	body, err := k.http.post(ctx, "/api/v1/kem/encapsulate", req)
	if err != nil {
		return nil, err
	}

	var resp encapsulateResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	kemCiphertext, err := base64.StdEncoding.DecodeString(resp.Data.KEMCiphertext)
	if err != nil {
		return nil, newError("Failed to decode KEM ciphertext", "ERR_PARSE_002", 500, "")
	}

	sharedSecret, err := base64.StdEncoding.DecodeString(resp.Data.SharedSecret)
	if err != nil {
		return nil, newError("Failed to decode shared secret", "ERR_PARSE_002", 500, "")
	}

	return &EncapsulateResult{
		KEMCiphertext: kemCiphertext,
		SharedSecret:  sharedSecret,
		KeyVersion:    resp.Data.KeyVersion,
		Algorithm:     resp.Data.Algorithm,
		RequestID:     resp.RequestID,
	}, nil
}

// Decapsulate decapsulates a shared secret using tenant's KEM private key.
func (k *KEMService) Decapsulate(ctx context.Context, input *DecapsulateInput) (*DecapsulateResult, error) {
	if input.Algorithm != "" && !validKEMAlgorithms[input.Algorithm] {
		return nil, fmt.Errorf("invalid KEM algorithm: %q", input.Algorithm)
	}

	req := decapsulateRequest{
		KEMCiphertext: base64.StdEncoding.EncodeToString(input.KEMCiphertext),
		KeyVersion:    input.KeyVersion,
		Algorithm:     input.Algorithm,
	}

	body, err := k.http.post(ctx, "/api/v1/kem/decapsulate", req)
	if err != nil {
		return nil, err
	}

	var resp decapsulateResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	sharedSecret, err := base64.StdEncoding.DecodeString(resp.Data.SharedSecret)
	if err != nil {
		return nil, newError("Failed to decode shared secret", "ERR_PARSE_002", 500, "")
	}

	return &DecapsulateResult{
		SharedSecret: sharedSecret,
		KeyVersion:   resp.Data.KeyVersion,
		Algorithm:    resp.Data.Algorithm,
		RequestID:    resp.RequestID,
	}, nil
}

// zeroBytes zeroes a byte slice. Best-effort memory cleanup.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// EncryptLocal performs client-side encryption: encapsulate + local AES-256-GCM.
// Plaintext NEVER leaves your environment.
func (k *KEMService) EncryptLocal(ctx context.Context, input *EncryptLocalInput) (*EncryptedEnvelope, error) {
	result, err := k.Encapsulate(ctx, &EncapsulateInput{
		KeyVersion: input.KeyVersion,
		Algorithm:  input.Algorithm,
	})
	if err != nil {
		return nil, err
	}
	defer zeroBytes(result.SharedSecret)

	block, err := aes.NewCipher(result.SharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	aesCiphertext := gcm.Seal(nil, iv, input.Plaintext, result.KEMCiphertext)

	return &EncryptedEnvelope{
		KEMCiphertext: result.KEMCiphertext,
		IV:            iv,
		AESCiphertext: aesCiphertext,
		KeyVersion:    result.KeyVersion,
		Algorithm:     result.Algorithm,
		RequestID:     result.RequestID,
	}, nil
}

// DecryptLocal performs client-side decryption: decapsulate + local AES-256-GCM.
// Only the KEM decapsulate request is sent to Qpher.
func (k *KEMService) DecryptLocal(ctx context.Context, envelope *EncryptedEnvelope) ([]byte, error) {
	result, err := k.Decapsulate(ctx, &DecapsulateInput{
		KEMCiphertext: envelope.KEMCiphertext,
		KeyVersion:    envelope.KeyVersion,
		Algorithm:     envelope.Algorithm,
	})
	if err != nil {
		return nil, err
	}
	defer zeroBytes(result.SharedSecret)

	block, err := aes.NewCipher(result.SharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, envelope.IV, envelope.AESCiphertext, envelope.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

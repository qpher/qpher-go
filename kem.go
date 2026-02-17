package qpher

import (
	"context"
	"encoding/base64"
	"encoding/json"
)

// KEMService handles Kyber768 KEM encrypt/decrypt operations.
type KEMService struct {
	http *httpClient
}

type encryptRequest struct {
	Plaintext  string `json:"plaintext"`
	KeyVersion int    `json:"key_version"`
	Mode       string `json:"mode"`
	Salt       string `json:"salt,omitempty"`
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

type decryptRequest struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"key_version"`
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

// Encrypt encrypts data using Kyber768 KEM.
func (k *KEMService) Encrypt(ctx context.Context, input *EncryptInput) (*EncryptResult, error) {
	mode := input.Mode
	if mode == "" {
		mode = "standard"
	}

	req := encryptRequest{
		Plaintext:  base64.StdEncoding.EncodeToString(input.Plaintext),
		KeyVersion: input.KeyVersion,
		Mode:       mode,
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

// Decrypt decrypts data using Kyber768 KEM.
func (k *KEMService) Decrypt(ctx context.Context, input *DecryptInput) (*DecryptResult, error) {
	req := decryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(input.Ciphertext),
		KeyVersion: input.KeyVersion,
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

package qpher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// KeysService handles PQC key lifecycle management.
type KeysService struct {
	http *httpClient
}

type generateRequest struct {
	Algorithm string `json:"algorithm"`
}

type keyResponse struct {
	Data struct {
		KeyVersion int    `json:"key_version"`
		Algorithm  string `json:"algorithm"`
		Status     string `json:"status"`
		PublicKey  string `json:"public_key"`
		CreatedAt  string `json:"created_at"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

type rotateRequest struct {
	Algorithm string `json:"algorithm"`
}

type rotateResponse struct {
	Data struct {
		KeyVersion    int    `json:"key_version"`
		Algorithm     string `json:"algorithm"`
		PublicKey     string `json:"public_key"`
		OldKeyVersion int    `json:"old_key_version"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

type keyListResponse struct {
	Data struct {
		Keys []struct {
			KeyVersion int    `json:"key_version"`
			Algorithm  string `json:"algorithm"`
			Status     string `json:"status"`
			PublicKey  string `json:"public_key"`
			CreatedAt  string `json:"created_at"`
		} `json:"keys"`
		Total int `json:"total"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

type retireRequest struct {
	Algorithm  string `json:"algorithm"`
	KeyVersion int    `json:"key_version"`
}

// Generate generates a new PQC key pair.
func (k *KeysService) Generate(ctx context.Context, input *GenerateInput) (*GenerateResult, error) {
	req := generateRequest{
		Algorithm: input.Algorithm,
	}

	body, err := k.http.post(ctx, "/api/v1/kms/keys/generate", req)
	if err != nil {
		return nil, err
	}

	var resp keyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	publicKey, err := base64.StdEncoding.DecodeString(resp.Data.PublicKey)
	if err != nil {
		return nil, newError("Failed to decode public key", "ERR_PARSE_002", 500, "")
	}

	return &GenerateResult{
		KeyVersion: resp.Data.KeyVersion,
		Algorithm:  resp.Data.Algorithm,
		Status:     resp.Data.Status,
		PublicKey:  publicKey,
		CreatedAt:  resp.Data.CreatedAt,
		RequestID:  resp.RequestID,
	}, nil
}

// Rotate rotates to a new key version. The old active key becomes retired.
func (k *KeysService) Rotate(ctx context.Context, input *RotateInput) (*RotateResult, error) {
	req := rotateRequest{
		Algorithm: input.Algorithm,
	}

	body, err := k.http.post(ctx, "/api/v1/kms/keys/rotate", req)
	if err != nil {
		return nil, err
	}

	var resp rotateResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	publicKey, err := base64.StdEncoding.DecodeString(resp.Data.PublicKey)
	if err != nil {
		return nil, newError("Failed to decode public key", "ERR_PARSE_002", 500, "")
	}

	return &RotateResult{
		KeyVersion:    resp.Data.KeyVersion,
		Algorithm:     resp.Data.Algorithm,
		PublicKey:     publicKey,
		OldKeyVersion: resp.Data.OldKeyVersion,
		RequestID:     resp.RequestID,
	}, nil
}

// GetActive gets the currently active key for an algorithm.
func (k *KeysService) GetActive(ctx context.Context, input *GetActiveInput) (*KeyInfo, error) {
	params := map[string]string{
		"algorithm": input.Algorithm,
	}

	body, err := k.http.get(ctx, "/api/v1/kms/keys/active", params)
	if err != nil {
		return nil, err
	}

	var resp keyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	return parseKeyInfo(&resp.Data)
}

// Get gets a specific key version.
func (k *KeysService) Get(ctx context.Context, input *GetKeyInput) (*KeyInfo, error) {
	path := fmt.Sprintf("/api/v1/kms/keys/%d", input.KeyVersion)
	params := map[string]string{
		"algorithm": input.Algorithm,
	}

	body, err := k.http.get(ctx, path, params)
	if err != nil {
		return nil, err
	}

	var resp keyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	return parseKeyInfo(&resp.Data)
}

// List lists all PQC keys, optionally filtered.
func (k *KeysService) List(ctx context.Context, input *ListKeysInput) (*KeyListResult, error) {
	params := make(map[string]string)
	if input != nil {
		if input.Algorithm != "" {
			params["algorithm"] = input.Algorithm
		}
		if input.Status != "" {
			params["status"] = input.Status
		}
	}

	var paramsArg map[string]string
	if len(params) > 0 {
		paramsArg = params
	}

	body, err := k.http.get(ctx, "/api/v1/kms/keys", paramsArg)
	if err != nil {
		return nil, err
	}

	var resp keyListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	keys := make([]KeyInfo, len(resp.Data.Keys))
	for i, key := range resp.Data.Keys {
		publicKey, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil {
			return nil, newError("Failed to decode public key", "ERR_PARSE_002", 500, "")
		}
		keys[i] = KeyInfo{
			KeyVersion: key.KeyVersion,
			Algorithm:  key.Algorithm,
			Status:     key.Status,
			PublicKey:  publicKey,
			CreatedAt:  key.CreatedAt,
		}
	}

	return &KeyListResult{
		Keys:      keys,
		Total:     resp.Data.Total,
		RequestID: resp.RequestID,
	}, nil
}

// Retire retires a key. Retired keys can decrypt/verify but not encrypt/sign.
func (k *KeysService) Retire(ctx context.Context, input *RetireInput) (*RetireResult, error) {
	req := retireRequest{
		Algorithm:  input.Algorithm,
		KeyVersion: input.KeyVersion,
	}

	body, err := k.http.post(ctx, "/api/v1/kms/keys/retire", req)
	if err != nil {
		return nil, err
	}

	var resp keyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	publicKey, err := base64.StdEncoding.DecodeString(resp.Data.PublicKey)
	if err != nil {
		return nil, newError("Failed to decode public key", "ERR_PARSE_002", 500, "")
	}

	return &RetireResult{
		KeyVersion: resp.Data.KeyVersion,
		Algorithm:  resp.Data.Algorithm,
		Status:     resp.Data.Status,
		PublicKey:  publicKey,
		CreatedAt:  resp.Data.CreatedAt,
		RequestID:  resp.RequestID,
	}, nil
}

func parseKeyInfo(data *struct {
	KeyVersion int    `json:"key_version"`
	Algorithm  string `json:"algorithm"`
	Status     string `json:"status"`
	PublicKey  string `json:"public_key"`
	CreatedAt  string `json:"created_at"`
}) (*KeyInfo, error) {
	publicKey, err := base64.StdEncoding.DecodeString(data.PublicKey)
	if err != nil {
		return nil, newError("Failed to decode public key", "ERR_PARSE_002", 500, "")
	}

	return &KeyInfo{
		KeyVersion: data.KeyVersion,
		Algorithm:  data.Algorithm,
		Status:     data.Status,
		PublicKey:  publicKey,
		CreatedAt:  data.CreatedAt,
	}, nil
}

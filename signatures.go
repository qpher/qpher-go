package qpher

import (
	"context"
	"encoding/base64"
	"encoding/json"
)

// SignaturesService handles Dilithium3 digital signature operations.
type SignaturesService struct {
	http *httpClient
}

type signRequest struct {
	Message    string `json:"message"`
	KeyVersion int    `json:"key_version"`
}

type signResponse struct {
	Data struct {
		Signature  string `json:"signature"`
		KeyVersion int    `json:"key_version"`
		Algorithm  string `json:"algorithm"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

type verifyRequest struct {
	Message    string `json:"message"`
	Signature  string `json:"signature"`
	KeyVersion int    `json:"key_version"`
}

type verifyResponse struct {
	Data struct {
		Valid      bool   `json:"valid"`
		KeyVersion int    `json:"key_version"`
		Algorithm  string `json:"algorithm"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

// Sign signs a message using Dilithium3.
func (s *SignaturesService) Sign(ctx context.Context, input *SignInput) (*SignResult, error) {
	req := signRequest{
		Message:    base64.StdEncoding.EncodeToString(input.Message),
		KeyVersion: input.KeyVersion,
	}

	body, err := s.http.post(ctx, "/api/v1/signature/sign", req)
	if err != nil {
		return nil, err
	}

	var resp signResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	signature, err := base64.StdEncoding.DecodeString(resp.Data.Signature)
	if err != nil {
		return nil, newError("Failed to decode signature", "ERR_PARSE_002", 500, "")
	}

	return &SignResult{
		Signature:  signature,
		KeyVersion: resp.Data.KeyVersion,
		Algorithm:  resp.Data.Algorithm,
		RequestID:  resp.RequestID,
	}, nil
}

// Verify verifies a Dilithium3 signature.
func (s *SignaturesService) Verify(ctx context.Context, input *VerifyInput) (*VerifyResult, error) {
	req := verifyRequest{
		Message:    base64.StdEncoding.EncodeToString(input.Message),
		Signature:  base64.StdEncoding.EncodeToString(input.Signature),
		KeyVersion: input.KeyVersion,
	}

	body, err := s.http.post(ctx, "/api/v1/signature/verify", req)
	if err != nil {
		return nil, err
	}

	var resp verifyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	return &VerifyResult{
		Valid:      resp.Data.Valid,
		KeyVersion: resp.Data.KeyVersion,
		Algorithm:  resp.Data.Algorithm,
		RequestID:  resp.RequestID,
	}, nil
}

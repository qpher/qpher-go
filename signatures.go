package qpher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Valid signature algorithms.
var validSigAlgorithms = map[string]bool{
	"Dilithium3":       true,
	"Composite-ML-DSA": true,
}

// SignaturesService handles digital signature operations (Dilithium3, Composite ML-DSA).
type SignaturesService struct {
	http *httpClient
}

type signRequest struct {
	Message    string `json:"message"`
	KeyVersion int    `json:"key_version"`
	Algorithm  string `json:"algorithm,omitempty"`
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
	Algorithm  string `json:"algorithm,omitempty"`
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

// Sign signs a message (Dilithium3 or Composite ML-DSA).
func (s *SignaturesService) Sign(ctx context.Context, input *SignInput) (*SignResult, error) {
	if input.Algorithm != "" && !validSigAlgorithms[input.Algorithm] {
		return nil, fmt.Errorf("invalid signature algorithm: %q", input.Algorithm)
	}

	req := signRequest{
		Message:    base64.StdEncoding.EncodeToString(input.Message),
		KeyVersion: input.KeyVersion,
		Algorithm:  input.Algorithm,
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

// Verify verifies a signature (Dilithium3 or Composite ML-DSA).
func (s *SignaturesService) Verify(ctx context.Context, input *VerifyInput) (*VerifyResult, error) {
	if input.Algorithm != "" && !validSigAlgorithms[input.Algorithm] {
		return nil, fmt.Errorf("invalid signature algorithm: %q", input.Algorithm)
	}

	req := verifyRequest{
		Message:    base64.StdEncoding.EncodeToString(input.Message),
		Signature:  base64.StdEncoding.EncodeToString(input.Signature),
		KeyVersion: input.KeyVersion,
		Algorithm:  input.Algorithm,
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

// Valid hash algorithms.
var validHashAlgorithms = map[string]bool{
	"SHA-256": true,
	"SHA-384": true,
	"SHA-512": true,
}

type signHashRequest struct {
	Hash          string `json:"hash"`
	HashAlgorithm string `json:"hash_algorithm"`
	KeyVersion    int    `json:"key_version"`
	Algorithm     string `json:"algorithm,omitempty"`
}

type signHashResponse struct {
	Data struct {
		Signature     string `json:"signature"`
		KeyVersion    int    `json:"key_version"`
		Algorithm     string `json:"algorithm"`
		HashAlgorithm string `json:"hash_algorithm"`
		SignatureType string `json:"signature_type"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

type verifyHashRequest struct {
	Hash          string `json:"hash"`
	HashAlgorithm string `json:"hash_algorithm"`
	Signature     string `json:"signature"`
	KeyVersion    int    `json:"key_version"`
	Algorithm     string `json:"algorithm,omitempty"`
}

type verifyHashResponse struct {
	Data struct {
		Valid         bool   `json:"valid"`
		KeyVersion    int    `json:"key_version"`
		Algorithm     string `json:"algorithm"`
		HashAlgorithm string `json:"hash_algorithm"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

// SignHash signs a pre-computed hash digest (detached signature).
func (s *SignaturesService) SignHash(ctx context.Context, input *SignHashInput) (*SignHashResult, error) {
	if input.Algorithm != "" && !validSigAlgorithms[input.Algorithm] {
		return nil, fmt.Errorf("invalid signature algorithm: %q", input.Algorithm)
	}
	if !validHashAlgorithms[input.HashAlgorithm] {
		return nil, fmt.Errorf("invalid hash algorithm: %q", input.HashAlgorithm)
	}

	req := signHashRequest{
		Hash:          base64.StdEncoding.EncodeToString(input.Hash),
		HashAlgorithm: input.HashAlgorithm,
		KeyVersion:    input.KeyVersion,
		Algorithm:     input.Algorithm,
	}

	body, err := s.http.post(ctx, "/api/v1/signature/sign-hash", req)
	if err != nil {
		return nil, err
	}

	var resp signHashResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	signature, err := base64.StdEncoding.DecodeString(resp.Data.Signature)
	if err != nil {
		return nil, newError("Failed to decode signature", "ERR_PARSE_002", 500, "")
	}

	return &SignHashResult{
		Signature:     signature,
		KeyVersion:    resp.Data.KeyVersion,
		Algorithm:     resp.Data.Algorithm,
		HashAlgorithm: resp.Data.HashAlgorithm,
		SignatureType: resp.Data.SignatureType,
		RequestID:     resp.RequestID,
	}, nil
}

// VerifyHash verifies a detached signature against a pre-computed hash.
func (s *SignaturesService) VerifyHash(ctx context.Context, input *VerifyHashInput) (*VerifyHashResult, error) {
	if input.Algorithm != "" && !validSigAlgorithms[input.Algorithm] {
		return nil, fmt.Errorf("invalid signature algorithm: %q", input.Algorithm)
	}
	if !validHashAlgorithms[input.HashAlgorithm] {
		return nil, fmt.Errorf("invalid hash algorithm: %q", input.HashAlgorithm)
	}

	req := verifyHashRequest{
		Hash:          base64.StdEncoding.EncodeToString(input.Hash),
		HashAlgorithm: input.HashAlgorithm,
		Signature:     base64.StdEncoding.EncodeToString(input.Signature),
		KeyVersion:    input.KeyVersion,
		Algorithm:     input.Algorithm,
	}

	body, err := s.http.post(ctx, "/api/v1/signature/verify-hash", req)
	if err != nil {
		return nil, err
	}

	var resp verifyHashResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newError("Failed to parse response", "ERR_PARSE_001", 500, "")
	}

	return &VerifyHashResult{
		Valid:         resp.Data.Valid,
		KeyVersion:    resp.Data.KeyVersion,
		Algorithm:     resp.Data.Algorithm,
		HashAlgorithm: resp.Data.HashAlgorithm,
		RequestID:     resp.RequestID,
	}, nil
}

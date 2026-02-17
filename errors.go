// Package qpher provides the official Go SDK for the Qpher Post-Quantum Cryptography API.
package qpher

import (
	"fmt"
)

// Error represents an API error returned by Qpher.
type Error struct {
	// Message is a human-readable error description.
	Message string `json:"message"`
	// Code is a machine-readable error code like "ERR_KEM_005".
	Code string `json:"error_code"`
	// StatusCode is the HTTP status code.
	StatusCode int `json:"-"`
	// RequestID is the request UUID for support inquiries.
	RequestID string `json:"request_id,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("qpher: %s (code=%s, status=%d, request_id=%s)",
			e.Message, e.Code, e.StatusCode, e.RequestID)
	}
	return fmt.Sprintf("qpher: %s (code=%s, status=%d)", e.Message, e.Code, e.StatusCode)
}

// IsAuthenticationError returns true if the error is an authentication error (401).
func (e *Error) IsAuthenticationError() bool {
	return e.StatusCode == 401
}

// IsValidationError returns true if the error is a validation error (400).
func (e *Error) IsValidationError() bool {
	return e.StatusCode == 400
}

// IsNotFoundError returns true if the error is a not found error (404).
func (e *Error) IsNotFoundError() bool {
	return e.StatusCode == 404
}

// IsForbiddenError returns true if the error is a forbidden error (403).
func (e *Error) IsForbiddenError() bool {
	return e.StatusCode == 403
}

// IsRateLimitError returns true if the error is a rate limit error (429).
func (e *Error) IsRateLimitError() bool {
	return e.StatusCode == 429
}

// IsServerError returns true if the error is a server error (5xx).
func (e *Error) IsServerError() bool {
	return e.StatusCode >= 500 && e.StatusCode < 600
}

// IsTimeoutError returns true if the error is a timeout error (504).
func (e *Error) IsTimeoutError() bool {
	return e.StatusCode == 504 || e.Code == "ERR_TIMEOUT_001"
}

// IsConnectionError returns true if the error is a connection error (503).
func (e *Error) IsConnectionError() bool {
	return e.StatusCode == 503 || e.Code == "ERR_SERVICE_001"
}

// newError creates a new Error with the given parameters.
func newError(message, code string, statusCode int, requestID string) *Error {
	return &Error{
		Message:    message,
		Code:       code,
		StatusCode: statusCode,
		RequestID:  requestID,
	}
}

// errorResponse represents the API error response format.
type errorResponse struct {
	Error struct {
		ErrorCode string `json:"error_code"`
		Message   string `json:"message"`
	} `json:"error"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

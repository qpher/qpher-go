package qpher

// EncryptInput contains parameters for KEM encryption.
type EncryptInput struct {
	// Plaintext is the data to encrypt (max 1MB).
	Plaintext []byte
	// KeyVersion is the active key version to use.
	KeyVersion int
	// Mode is "standard" (default) or "deterministic".
	Mode string
	// Salt is required if Mode="deterministic" (min 32 bytes).
	Salt []byte
}

// EncryptResult contains the result of a KEM encrypt operation.
type EncryptResult struct {
	// Ciphertext is the encrypted data.
	Ciphertext []byte
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used (e.g., "Kyber768").
	Algorithm string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// DecryptInput contains parameters for KEM decryption.
type DecryptInput struct {
	// Ciphertext is the encrypted data from Encrypt().
	Ciphertext []byte
	// KeyVersion is the key version used during encryption.
	KeyVersion int
}

// DecryptResult contains the result of a KEM decrypt operation.
type DecryptResult struct {
	// Plaintext is the decrypted data.
	Plaintext []byte
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used.
	Algorithm string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// SignInput contains parameters for signing.
type SignInput struct {
	// Message is the data to sign (max 1MB).
	Message []byte
	// KeyVersion is the active signing key version.
	KeyVersion int
}

// SignResult contains the result of a signature sign operation.
type SignResult struct {
	// Signature is the signature bytes (3,293 bytes for Dilithium3).
	Signature []byte
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used (e.g., "Dilithium3").
	Algorithm string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// VerifyInput contains parameters for signature verification.
type VerifyInput struct {
	// Message is the original message.
	Message []byte
	// Signature is the signature to verify.
	Signature []byte
	// KeyVersion is the key version used during signing.
	KeyVersion int
}

// VerifyResult contains the result of a signature verify operation.
type VerifyResult struct {
	// Valid is true if the signature is valid.
	Valid bool
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used.
	Algorithm string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// KeyInfo contains information about a PQC key.
type KeyInfo struct {
	// KeyVersion is the version number of the key.
	KeyVersion int
	// Algorithm is "Kyber768" or "Dilithium3".
	Algorithm string
	// Status is "active", "retired", or "archived".
	Status string
	// PublicKey is the public key bytes.
	PublicKey []byte
	// CreatedAt is the ISO 8601 timestamp.
	CreatedAt string
}

// KeyListResult contains the result of a key list operation.
type KeyListResult struct {
	// Keys is the list of keys.
	Keys []KeyInfo
	// Total is the total count.
	Total int
	// RequestID is the request UUID for tracing.
	RequestID string
}

// GenerateInput contains parameters for key generation.
type GenerateInput struct {
	// Algorithm is "Kyber768" or "Dilithium3".
	Algorithm string
}

// GenerateResult contains the result of a key generation operation.
type GenerateResult struct {
	// KeyVersion is the version of the generated key.
	KeyVersion int
	// Algorithm is the algorithm used.
	Algorithm string
	// Status is the key status ("active").
	Status string
	// PublicKey is the public key bytes.
	PublicKey []byte
	// CreatedAt is the ISO 8601 timestamp.
	CreatedAt string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// RotateInput contains parameters for key rotation.
type RotateInput struct {
	// Algorithm is "Kyber768" or "Dilithium3".
	Algorithm string
}

// RotateResult contains the result of a key rotation operation.
type RotateResult struct {
	// KeyVersion is the new key version.
	KeyVersion int
	// Algorithm is the algorithm used.
	Algorithm string
	// PublicKey is the new public key bytes.
	PublicKey []byte
	// OldKeyVersion is the previous active key version.
	OldKeyVersion int
	// RequestID is the request UUID for tracing.
	RequestID string
}

// GetActiveInput contains parameters for getting the active key.
type GetActiveInput struct {
	// Algorithm is "Kyber768" or "Dilithium3".
	Algorithm string
}

// GetKeyInput contains parameters for getting a specific key version.
type GetKeyInput struct {
	// Algorithm is "Kyber768" or "Dilithium3".
	Algorithm string
	// KeyVersion is the version number to retrieve.
	KeyVersion int
}

// ListKeysInput contains parameters for listing keys.
type ListKeysInput struct {
	// Algorithm filters by "Kyber768" or "Dilithium3" (optional).
	Algorithm string
	// Status filters by "active", "retired", or "archived" (optional).
	Status string
}

// RetireInput contains parameters for key retirement.
type RetireInput struct {
	// Algorithm is "Kyber768" or "Dilithium3".
	Algorithm string
	// KeyVersion is the version to retire.
	KeyVersion int
}

// RetireResult contains the result of a key retire operation.
type RetireResult struct {
	// KeyVersion is the retired key version.
	KeyVersion int
	// Algorithm is the algorithm.
	Algorithm string
	// Status is "retired".
	Status string
	// PublicKey is the public key bytes.
	PublicKey []byte
	// CreatedAt is the ISO 8601 timestamp.
	CreatedAt string
	// RequestID is the request UUID for tracing.
	RequestID string
}

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
	// Algorithm is "Kyber768" (default) or "X-Wing" (hybrid).
	Algorithm string
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
	// Algorithm is "Kyber768" (default) or "X-Wing" (hybrid).
	Algorithm string
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

// EncapsulateInput contains parameters for KEM encapsulation.
type EncapsulateInput struct {
	// KeyVersion is the active key version to use.
	KeyVersion int
	// Algorithm is "Kyber768" (default) or "X-Wing" (hybrid).
	Algorithm string
}

// EncapsulateResult contains the result of a KEM encapsulate operation.
type EncapsulateResult struct {
	// KEMCiphertext is the KEM ciphertext (send to decapsulate to recover shared secret).
	KEMCiphertext []byte
	// SharedSecret is the 32-byte ephemeral shared secret — zero after use.
	SharedSecret []byte
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used (e.g., "Kyber768").
	Algorithm string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// DecapsulateInput contains parameters for KEM decapsulation.
type DecapsulateInput struct {
	// KEMCiphertext is the KEM ciphertext from Encapsulate().
	KEMCiphertext []byte
	// KeyVersion is the key version used during encapsulation.
	KeyVersion int
	// Algorithm is "Kyber768" (default) or "X-Wing" (hybrid).
	Algorithm string
}

// DecapsulateResult contains the result of a KEM decapsulate operation.
type DecapsulateResult struct {
	// SharedSecret is the 32-byte ephemeral shared secret — zero after use.
	SharedSecret []byte
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used.
	Algorithm string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// EncryptedEnvelope contains client-side encrypted data.
type EncryptedEnvelope struct {
	// KEMCiphertext is the KEM ciphertext (send to decapsulate to recover shared secret).
	KEMCiphertext []byte
	// IV is the 12-byte AES-GCM nonce.
	IV []byte
	// AESCiphertext is the AES-GCM encrypted data (plaintext + 16-byte GCM tag).
	AESCiphertext []byte
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used.
	Algorithm string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// EncryptLocalInput contains parameters for client-side encryption.
type EncryptLocalInput struct {
	// Plaintext is the data to encrypt locally.
	Plaintext []byte
	// KeyVersion is the active key version to use.
	KeyVersion int
	// Algorithm is "Kyber768" (default) or "X-Wing" (hybrid).
	Algorithm string
}

// SignInput contains parameters for signing.
type SignInput struct {
	// Message is the data to sign (max 1MB).
	Message []byte
	// KeyVersion is the active signing key version.
	KeyVersion int
	// Algorithm is "Dilithium3" (default) or "Composite-ML-DSA" (hybrid).
	Algorithm string
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
	// Algorithm is "Dilithium3" (default) or "Composite-ML-DSA" (hybrid).
	Algorithm string
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

// KeyWrapInput contains parameters for KEM key wrapping.
type KeyWrapInput struct {
	// SymmetricKey is the symmetric key to wrap (16, 24, 32, 48, or 64 bytes).
	SymmetricKey []byte
	// KeyVersion is the active key version to use.
	KeyVersion int
	// Algorithm is "Kyber768" (default) or "X-Wing" (hybrid).
	Algorithm string
}

// KeyWrapResult contains the result of a KEM key wrap operation.
type KeyWrapResult struct {
	// WrappedKey is the wrapped key blob (KEM-DEM ciphertext).
	WrappedKey []byte
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used.
	Algorithm string
	// WrappingMethod is "KEM-DEM".
	WrappingMethod string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// KeyUnwrapInput contains parameters for KEM key unwrapping.
type KeyUnwrapInput struct {
	// WrappedKey is the wrapped key blob from Wrap().
	WrappedKey []byte
	// KeyVersion is the key version used during wrapping (active or retired).
	KeyVersion int
	// Algorithm is "Kyber768" (default) or "X-Wing" (hybrid).
	Algorithm string
}

// KeyUnwrapResult contains the result of a KEM key unwrap operation.
type KeyUnwrapResult struct {
	// SymmetricKey is the recovered symmetric key bytes.
	SymmetricKey []byte
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used.
	Algorithm string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// SignHashInput contains parameters for signing a pre-computed hash.
type SignHashInput struct {
	// Hash is the pre-computed hash bytes (SHA-256: 32B, SHA-384: 48B, SHA-512: 64B).
	Hash []byte
	// HashAlgorithm is one of "SHA-256", "SHA-384", "SHA-512".
	HashAlgorithm string
	// KeyVersion is the active signing key version.
	KeyVersion int
	// Algorithm is "Dilithium3" (default) or "Composite-ML-DSA" (hybrid).
	Algorithm string
}

// SignHashResult contains the result of a sign-hash operation.
type SignHashResult struct {
	// Signature is the detached signature bytes.
	Signature []byte
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used.
	Algorithm string
	// HashAlgorithm is the hash algorithm used.
	HashAlgorithm string
	// SignatureType is "detached".
	SignatureType string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// VerifyHashInput contains parameters for verifying a pre-computed hash.
type VerifyHashInput struct {
	// Hash is the pre-computed hash bytes.
	Hash []byte
	// HashAlgorithm is one of "SHA-256", "SHA-384", "SHA-512".
	HashAlgorithm string
	// Signature is the detached signature to verify.
	Signature []byte
	// KeyVersion is the key version used during signing (active or retired).
	KeyVersion int
	// Algorithm is "Dilithium3" (default) or "Composite-ML-DSA" (hybrid).
	Algorithm string
}

// VerifyHashResult contains the result of a verify-hash operation.
type VerifyHashResult struct {
	// Valid is true if the signature is valid.
	Valid bool
	// KeyVersion is the key version used.
	KeyVersion int
	// Algorithm is the algorithm used.
	Algorithm string
	// HashAlgorithm is the hash algorithm used.
	HashAlgorithm string
	// RequestID is the request UUID for tracing.
	RequestID string
}

// KeyInfo contains information about a PQC key.
type KeyInfo struct {
	// KeyVersion is the version number of the key.
	KeyVersion int
	// Algorithm is "Kyber768", "Dilithium3", "X-Wing", or "Composite-ML-DSA".
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
	// Algorithm is "Kyber768", "Dilithium3", "X-Wing", or "Composite-ML-DSA".
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
	// Algorithm is "Kyber768", "Dilithium3", "X-Wing", or "Composite-ML-DSA".
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
	// Algorithm is "Kyber768", "Dilithium3", "X-Wing", or "Composite-ML-DSA".
	Algorithm string
}

// GetKeyInput contains parameters for getting a specific key version.
type GetKeyInput struct {
	// Algorithm is "Kyber768", "Dilithium3", "X-Wing", or "Composite-ML-DSA".
	Algorithm string
	// KeyVersion is the version number to retrieve.
	KeyVersion int
}

// ListKeysInput contains parameters for listing keys.
type ListKeysInput struct {
	// Algorithm filters by "Kyber768", "Dilithium3", "X-Wing", or "Composite-ML-DSA" (optional).
	Algorithm string
	// Status filters by "active", "retired", or "archived" (optional).
	Status string
}

// RetireInput contains parameters for key retirement.
type RetireInput struct {
	// Algorithm is "Kyber768", "Dilithium3", "X-Wing", or "Composite-ML-DSA".
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

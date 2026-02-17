# Qpher Go SDK

Official Go SDK for the [Qpher](https://qpher.ai) Post-Quantum Cryptography API.

## Installation

```bash
go get github.com/qpher/qpher-go
```

## Requirements

- Go 1.21+

## Quick Start

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "log"

    "github.com/qpher/qpher-go"
)

func main() {
    // Initialize the client
    client, err := qpher.NewClient("qph_live_your_api_key", nil)
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Encrypt data using Kyber768 KEM
    encrypted, err := client.KEM.Encrypt(ctx, &qpher.EncryptInput{
        Plaintext:  []byte("Hello, Quantum World!"),
        KeyVersion: 1,
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Ciphertext: %x\n", encrypted.Ciphertext)

    // Decrypt data
    decrypted, err := client.KEM.Decrypt(ctx, &qpher.DecryptInput{
        Ciphertext: encrypted.Ciphertext,
        KeyVersion: encrypted.KeyVersion,
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Plaintext: %s\n", decrypted.Plaintext)

    // Sign a message using Dilithium3
    signed, err := client.Signatures.Sign(ctx, &qpher.SignInput{
        Message:    []byte("Invoice #12345"),
        KeyVersion: 1,
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature: %x\n", signed.Signature)

    // Verify a signature
    verified, err := client.Signatures.Verify(ctx, &qpher.VerifyInput{
        Message:    []byte("Invoice #12345"),
        Signature:  signed.Signature,
        KeyVersion: signed.KeyVersion,
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Valid: %v\n", verified.Valid)
}
```

## API Reference

### Client Initialization

```go
import "github.com/qpher/qpher-go"

// With default options
client, err := qpher.NewClient("qph_live_your_api_key", nil)

// With custom options
client, err := qpher.NewClient("qph_live_your_api_key", &qpher.ClientOptions{
    BaseURL:    "https://api.qpher.ai", // Optional, default
    Timeout:    30,                      // Optional, seconds
    MaxRetries: 3,                       // Optional
})
```

### KEM Operations (Kyber768)

#### Encrypt

```go
result, err := client.KEM.Encrypt(ctx, &qpher.EncryptInput{
    Plaintext:  []byte("secret data"),
    KeyVersion: 1,
    Mode:       "standard",        // Optional: "standard" or "deterministic"
    Salt:       make([]byte, 32),  // Required if Mode="deterministic"
})
// result.Ciphertext: []byte
// result.KeyVersion: int
// result.Algorithm: string ("Kyber768")
// result.RequestID: string
```

#### Decrypt

```go
result, err := client.KEM.Decrypt(ctx, &qpher.DecryptInput{
    Ciphertext: encryptedData,
    KeyVersion: 1,
})
// result.Plaintext: []byte
// result.KeyVersion: int
// result.Algorithm: string
// result.RequestID: string
```

### Signature Operations (Dilithium3)

#### Sign

```go
result, err := client.Signatures.Sign(ctx, &qpher.SignInput{
    Message:    []byte("document to sign"),
    KeyVersion: 1,
})
// result.Signature: []byte (3,293 bytes)
// result.KeyVersion: int
// result.Algorithm: string ("Dilithium3")
// result.RequestID: string
```

#### Verify

```go
result, err := client.Signatures.Verify(ctx, &qpher.VerifyInput{
    Message:    []byte("document to sign"),
    Signature:  signatureBytes,
    KeyVersion: 1,
})
// result.Valid: bool
// result.KeyVersion: int
// result.Algorithm: string
// result.RequestID: string
```

### Key Management

#### Generate Key

```go
result, err := client.Keys.Generate(ctx, &qpher.GenerateInput{
    Algorithm: "Kyber768",
})
// result.KeyVersion: int
// result.Algorithm: string
// result.Status: string ("active")
// result.PublicKey: []byte
// result.CreatedAt: string
```

#### Rotate Key

```go
result, err := client.Keys.Rotate(ctx, &qpher.RotateInput{
    Algorithm: "Kyber768",
})
// result.KeyVersion: int (new)
// result.OldKeyVersion: int
// result.Algorithm: string
// result.PublicKey: []byte
```

#### Get Active Key

```go
keyInfo, err := client.Keys.GetActive(ctx, &qpher.GetActiveInput{
    Algorithm: "Kyber768",
})
// keyInfo.KeyVersion: int
// keyInfo.Algorithm: string
// keyInfo.Status: string
// keyInfo.PublicKey: []byte
// keyInfo.CreatedAt: string
```

#### List Keys

```go
result, err := client.Keys.List(ctx, &qpher.ListKeysInput{
    Algorithm: "Kyber768", // Optional filter
    Status:    "active",   // Optional filter
})
// result.Keys: []KeyInfo
// result.Total: int
```

#### Retire Key

```go
result, err := client.Keys.Retire(ctx, &qpher.RetireInput{
    Algorithm:  "Kyber768",
    KeyVersion: 1,
})
// result.KeyVersion: int
// result.Status: string ("retired")
```

## Error Handling

```go
import (
    "errors"
    "github.com/qpher/qpher-go"
)

result, err := client.KEM.Encrypt(ctx, &qpher.EncryptInput{
    Plaintext:  []byte("data"),
    KeyVersion: 99,
})
if err != nil {
    var qErr *qpher.Error
    if errors.As(err, &qErr) {
        fmt.Printf("Error: %s\n", qErr.Message)
        fmt.Printf("Code: %s\n", qErr.Code)
        fmt.Printf("Status: %d\n", qErr.StatusCode)
        fmt.Printf("Request ID: %s\n", qErr.RequestID)

        // Check error type
        if qErr.IsNotFoundError() {
            fmt.Println("Key not found")
        } else if qErr.IsRateLimitError() {
            fmt.Println("Rate limit exceeded")
        } else if qErr.IsAuthenticationError() {
            fmt.Println("Invalid API key")
        }
    }
}
```

## Error Type Methods

The `*qpher.Error` type provides helper methods to check the error type:

| Method | Description |
|--------|-------------|
| `IsAuthenticationError()` | Returns true for 401 errors |
| `IsValidationError()` | Returns true for 400 errors |
| `IsNotFoundError()` | Returns true for 404 errors |
| `IsForbiddenError()` | Returns true for 403 errors |
| `IsRateLimitError()` | Returns true for 429 errors |
| `IsServerError()` | Returns true for 5xx errors |
| `IsTimeoutError()` | Returns true for timeout errors |
| `IsConnectionError()` | Returns true for connection errors |

## Context Support

All methods accept a `context.Context` as the first parameter, allowing you to:

- Set request timeouts
- Cancel requests
- Pass request-scoped values

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

result, err := client.KEM.Encrypt(ctx, input)
```

## Supported Algorithms

| Algorithm | Type | Security Level |
|-----------|------|----------------|
| Kyber768 | KEM (Encryption) | NIST Level 3 |
| Dilithium3 | Digital Signatures | NIST Level 3 |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [Qpher Website](https://qpher.ai)
- [API Documentation](https://docs.qpher.ai)
- [GitHub Repository](https://github.com/qpher/qpher-go)

# Lucinda

[![NuGet](https://img.shields.io/nuget/v/Lucinda.svg)](https://www.nuget.org/packages/Lucinda/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive end-to-end encryption (E2EE) library for .NET, providing secure cryptographic operations including symmetric/asymmetric encryption, key exchange, digital signatures, and secure key management.

## Features

- **Symmetric Encryption**
  - AES-GCM (Galois/Counter Mode) - Authenticated encryption
  - AES-CBC (Cipher Block Chaining) with optional HMAC authentication
  - Support for 128, 192, and 256-bit keys

- **Asymmetric Encryption**
  - RSA encryption with OAEP padding
  - Support for 2048, 3072, and 4096-bit keys
  - Hybrid encryption (RSA + AES-GCM)

- **Key Exchange**
  - ECDH (Elliptic Curve Diffie-Hellman)
  - Support for P-256, P-384, and P-521 curves

- **Digital Signatures**
  - RSA signatures with PSS or PKCS#1 v1.5 padding
  - ECDSA (Elliptic Curve Digital Signature Algorithm)

- **Key Derivation**
  - PBKDF2 (Password-Based Key Derivation Function 2)
  - HKDF (HMAC-based Key Derivation Function)

- **Secure Key Storage**
  - In-memory key storage with secure clearing
  - Extensible interface for custom storage backends

- **Signal Protocol-like Secure Messaging**
  - X3DH (Extended Triple Diffie-Hellman) key agreement
  - Double Ratchet algorithm for forward-secure messaging
  - Pre-key bundles for asynchronous session establishment
  - **Header Encryption**: Protects message metadata (ratchet keys, counters)
  - **Sender Keys Protocol**: Efficient group messaging with `GroupSession`
  - Forward Secrecy: Past messages remain secure if keys are compromised
  - Post-Compromise Security: Future messages become secure after compromise
  - **Extensibility**: `ICurve25519` and `IEdDSA` interfaces for custom cryptographic providers

## Supported Platforms

| Platform | Version |
|----------|---------|
| .NET Standard | 2.0, 2.1 |
| .NET Framework | 4.8, 4.8.1 |
| .NET | 6.0, 7.0, 8.0, 9.0, 10.0, 11.0 |

> **Note:** Full functionality (RSA, ECDSA, ECDH, hybrid encryption) requires .NET Core 3.0+ or .NET 5.0+. Signal Protocol features (SecureMessaging, X3DH, Double Ratchet) require .NET 6.0+. On .NET Framework 4.8/4.8.1 and .NET Standard 2.0/2.1, only symmetric encryption (AES-GCM, AES-CBC), key derivation (PBKDF2, HKDF), and utility functions are available.

## Installation

```bash
dotnet add package Lucinda
```

Or via NuGet Package Manager:

```powershell
Install-Package Lucinda
```

## Quick Start

### High-Level API

The `EndToEndEncryption` class provides a simplified API for common E2EE scenarios:

```csharp
using Lucinda;

// Create an E2EE instance
using var e2ee = new EndToEndEncryption();

// Generate key pairs for Alice and Bob
var aliceKeyPair = e2ee.GenerateKeyPair();
var bobKeyPair = e2ee.GenerateKeyPair();

// Alice encrypts a message for Bob
var encrypted = e2ee.EncryptMessage("Hello, Bob!", bobKeyPair.Value.PublicKey);

// Bob decrypts the message
var decrypted = e2ee.DecryptMessage(encrypted.Value, bobKeyPair.Value.PrivateKey);
Console.WriteLine(decrypted.Value); // "Hello, Bob!"
```

### Signal Protocol-like Secure Messaging

The `SecureMessaging` class provides Signal Protocol-like security with X3DH and Double Ratchet:

```csharp
using Lucinda;

// Alice and Bob setup
using var alice = new SecureMessaging();
using var bob = new SecureMessaging();

alice.GenerateIdentityKeyPair();
bob.GenerateIdentityKeyPair();
bob.GeneratePreKeyBundle();

// Alice initiates session with Bob's pre-key bundle
var bobBundle = bob.GetPublicPreKeyBundle();
alice.InitializeSession("bob", bobBundle.Value);

// Bob creates session from Alice's initial contact
var initialMessage = alice.GetInitialMessageData("bob");
bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);

// Send encrypted messages with forward secrecy
var encrypted = alice.SendMessage("bob", "Hello with forward secrecy!");
var decrypted = bob.ReceiveMessage("alice", encrypted.Value);
Console.WriteLine(decrypted.Value); // "Hello with forward secrecy!"
```

### Group Messaging (Sender Keys Protocol)

```csharp
using Lucinda.Protocol.SenderKeys;

// Create group sessions for each participant
using var alice = new GroupSession("my-group-123", "alice");
using var bob = new GroupSession("my-group-123", "bob");
using var charlie = new GroupSession("my-group-123", "charlie");

// Initialize sender keys
alice.Initialize();
bob.Initialize();
charlie.Initialize();

// Exchange distribution messages (each participant shares their sender key)
var aliceDist = alice.CreateDistributionMessage();
var bobDist = bob.CreateDistributionMessage();

alice.ProcessDistributionMessage("bob", bobDist.Value);
bob.ProcessDistributionMessage("alice", aliceDist.Value);

// Alice sends encrypted message to the group (single encryption for all recipients)
var groupMessage = alice.Encrypt(Encoding.UTF8.GetBytes("Hello group!"));

// Bob decrypts the group message
var decrypted = bob.Decrypt(groupMessage.Value);
Console.WriteLine(Encoding.UTF8.GetString(decrypted.Value)); // "Hello group!"
```

### Symmetric Encryption (AES-GCM)

```csharp
using Lucinda.Symmetric;

// Generate a new key
using var aes = new AesGcmEncryption(256); // 256-bit key

// Encrypt data
var plaintext = "Sensitive data"u8.ToArray();
var encrypted = aes.Encrypt(plaintext);

// Decrypt data
var decrypted = aes.Decrypt(encrypted.Value);

// With associated data (AAD)
var metadata = "header"u8.ToArray();
var encryptedWithAad = aes.Encrypt(plaintext, metadata);
var decryptedWithAad = aes.Decrypt(encryptedWithAad.Value, metadata);
```

### Hybrid Encryption (RSA + AES)

```csharp
using Lucinda.Asymmetric;

using var hybrid = new RsaAesHybridEncryption();

// Generate a key pair
var keyPair = hybrid.GenerateKeyPair();

// Encrypt (anyone with the public key can encrypt)
var data = "Large amount of data..."u8.ToArray();
var encrypted = hybrid.Encrypt(data, keyPair.Value.PublicKey);

// Decrypt (only the private key holder can decrypt)
var decrypted = hybrid.Decrypt(encrypted.Value, keyPair.Value.PrivateKey);
```

### Digital Signatures

```csharp
using Lucinda.Signatures;

// ECDSA signatures
using var signer = new EcdsaSignature();
var keyPair = signer.GenerateKeyPair();

var data = "Data to sign"u8.ToArray();

// Sign
var signature = signer.Sign(data);

// Verify
var isValid = signer.Verify(data, signature.Value);
Console.WriteLine(isValid.Value); // true
```

### Key Derivation from Password

```csharp
using Lucinda.KeyDerivation;

using var pbkdf2 = new Pbkdf2KeyDerivation();

// Derive a key from a password
var password = "MySecretPassword";
var salt = SecureRandom.GenerateSalt(32);
var derivedKey = pbkdf2.DeriveKey(password, salt, iterations: 600000, derivedKeyLength: 32);

// Use derivedKey.Value for encryption
```

### HKDF Key Derivation

```csharp
using Lucinda.KeyDerivation;

using var hkdf = new HkdfKeyDerivation();

// Derive keys from a shared secret
var sharedSecret = new byte[32]; // From key exchange
var salt = SecureRandom.GenerateSalt(32);
var info = "encryption-key"u8.ToArray();

var encryptionKey = hkdf.DeriveKey(sharedSecret, salt, info, 32);
```

### Key Exchange (ECDH)

```csharp
using Lucinda.KeyExchange;

// Alice generates her key pair
using var aliceEcdh = new EcdhKeyExchange();
var alicePublicKey = aliceEcdh.GetPublicKey();

// Bob generates his key pair
using var bobEcdh = new EcdhKeyExchange();
var bobPublicKey = bobEcdh.GetPublicKey();

// Both derive the same shared secret
var aliceSharedSecret = aliceEcdh.DeriveSharedSecret(bobPublicKey.Value);
var bobSharedSecret = bobEcdh.DeriveSharedSecret(alicePublicKey.Value);
// aliceSharedSecret == bobSharedSecret
```

### Encrypt and Sign (Complete E2EE)

```csharp
using Lucinda;

using var e2ee = new EndToEndEncryption();

// Generate keys
var senderSigningKeyPair = e2ee.GenerateSigningKeyPair();
var recipientKeyPair = e2ee.GenerateKeyPair();

var message = "Authenticated and encrypted message"u8.ToArray();

// Encrypt and sign
var signedEncrypted = e2ee.EncryptAndSign(
    message,
    recipientKeyPair.Value.PublicKey,
    senderSigningKeyPair.Value.PrivateKey);

// Verify and decrypt
var decrypted = e2ee.VerifyAndDecrypt(
    signedEncrypted.Value,
    recipientKeyPair.Value.PrivateKey,
    senderSigningKeyPair.Value.PublicKey);

if (decrypted.IsSuccess)
{
    Console.WriteLine("Message verified and decrypted!");
}
```

## Error Handling

All cryptographic operations return a `CryptoResult<T>` that encapsulates success or failure:

```csharp
var result = aes.Encrypt(data);

if (result.IsSuccess)
{
    var encrypted = result.Value;
    // Use encrypted data
}
else
{
    Console.WriteLine($"Error: {result.Error}");
}

// Or use pattern matching
result.Match(
    onSuccess: data => ProcessData(data),
    onFailure: error => HandleError(error)
);
```

## Security Considerations

1. **Key Management**: Always securely store and protect private keys.
2. **Random Number Generation**: The library uses `System.Security.Cryptography.RandomNumberGenerator` for cryptographically secure random numbers.
3. **Memory Security**: Sensitive data (keys, plaintext) is cleared from memory when possible.
4. **Authenticated Encryption**: Use AES-GCM or enable HMAC with AES-CBC to ensure data integrity.
5. **Key Sizes**: Use at least 2048-bit RSA keys and 256-bit AES keys for production.
6. **Password Hashing**: Use PBKDF2 with at least 600,000 iterations for password-based key derivation.

## API Reference

### Main Classes

| Class | Description |
|-------|-------------|
| `EndToEndEncryption` | High-level E2EE operations |
| `AesGcmEncryption` | AES-GCM authenticated encryption |
| `AesCbcEncryption` | AES-CBC encryption |
| `RsaEncryption` | RSA asymmetric encryption |
| `RsaAesHybridEncryption` | Hybrid RSA+AES encryption |
| `EcdhKeyExchange` | ECDH key exchange |
| `RsaSignature` | RSA digital signatures |
| `EcdsaSignature` | ECDSA digital signatures |
| `Pbkdf2KeyDerivation` | Password-based key derivation |
| `HkdfKeyDerivation` | HKDF key derivation |
| `InMemoryKeyStorage` | Secure in-memory key storage |
| `SecureMessaging` | Signal Protocol-like secure messaging |
| `X3DHKeyAgreement` | X3DH key agreement protocol |
| `DoubleRatchet` | Double Ratchet algorithm |
| `HeaderEncryption` | Header encryption for metadata protection |
| `GroupSession` | Sender Keys protocol for group messaging |

### Interfaces

| Interface | Description |
|-----------|-------------|
| `ISymmetricEncryption` | Contract for symmetric encryption |
| `IAsymmetricEncryption` | Contract for asymmetric encryption |
| `IHybridEncryption` | Contract for hybrid encryption |
| `IKeyExchange` | Contract for key exchange |
| `IDigitalSignature` | Contract for digital signatures |
| `IKeyDerivation` | Contract for key derivation |
| `ISecureKeyStorage` | Contract for secure key storage |
| `IX3DHKeyAgreement` | Contract for X3DH key agreement |
| `IDoubleRatchet` | Contract for Double Ratchet |
| `IKdfChain` | Contract for KDF chain operations |
| `ISessionStorage` | Contract for session storage |
| `IHeaderEncryption` | Contract for header encryption |
| `IGroupSession` | Contract for group messaging sessions |
| `ICurve25519` | Contract for X25519 key exchange (extensibility) |
| `IEdDSA` | Contract for Ed25519 signatures (extensibility) |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Built on .NET's `System.Security.Cryptography` namespace
- Follows modern cryptographic best practices
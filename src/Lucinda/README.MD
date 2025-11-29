# Lucinda

[![NuGet](https://img.shields.io/nuget/v/Lucinda.svg)](https://www.nuget.org/packages/Lucinda)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Taiizor/Lucinda/blob/develop/LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-blue.svg)](https://github.com/Taiizor/Lucinda)

A comprehensive end-to-end encryption (E2EE) library for .NET, providing secure cryptographic operations including symmetric/asymmetric encryption, key exchange, digital signatures, and secure key management.

## Features

- **Symmetric Encryption**: AES-GCM and AES-CBC with 128, 192, and 256-bit keys
- **Asymmetric Encryption**: RSA with OAEP padding (2048, 3072, 4096-bit)
- **Hybrid Encryption**: RSA + AES-GCM for efficient large data encryption
- **Key Exchange**: ECDH with P-256, P-384, and P-521 curves
- **Digital Signatures**: RSA (PSS/PKCS#1) and ECDSA
- **Key Derivation**: PBKDF2 and HKDF
- **Secure Key Storage**: In-memory storage with secure clearing
- **Signal Protocol-like Messaging**: X3DH + Double Ratchet with forward secrecy

## Supported Platforms

| Platform | Version |
|----------|---------|
| .NET Standard | 2.0, 2.1 |
| .NET Framework | 4.8, 4.8.1 |
| .NET | 6.0, 7.0, 8.0, 9.0, 10.0 |

> **Note:** Full functionality (RSA, ECDSA, ECDH, hybrid encryption) requires .NET Core 3.0+ or .NET 5.0+. Signal Protocol features (SecureMessaging, X3DH, Double Ratchet) require .NET 6.0+. On .NET Framework and .NET Standard, only symmetric encryption, key derivation, and utility functions are available.

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

```csharp
using Lucinda;

using var alice = new SecureMessaging();
using var bob = new SecureMessaging();

alice.GenerateIdentityKeyPair();
bob.GenerateIdentityKeyPair();
bob.GeneratePreKeyBundle();

var bobBundle = bob.GetPublicPreKeyBundle();
alice.InitializeSession("bob", bobBundle.Value);

var initialMessage = alice.GetInitialMessageData("bob");
bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);

var encrypted = alice.SendMessage("bob", "Hello with forward secrecy!");
var decrypted = bob.ReceiveMessage("alice", encrypted.Value);
```

### Symmetric Encryption (AES-GCM)

```csharp
using Lucinda.Symmetric;

using var aes = new AesGcmEncryption(256);

var plaintext = "Sensitive data"u8.ToArray();
var encrypted = aes.Encrypt(plaintext);
var decrypted = aes.Decrypt(encrypted.Value);
```

### Hybrid Encryption (RSA + AES)

```csharp
using Lucinda.Asymmetric;

using var hybrid = new RsaAesHybridEncryption();
var keyPair = hybrid.GenerateKeyPair();

var data = "Large amount of data..."u8.ToArray();
var encrypted = hybrid.Encrypt(data, keyPair.Value.PublicKey);
var decrypted = hybrid.Decrypt(encrypted.Value, keyPair.Value.PrivateKey);
```

### Digital Signatures

```csharp
using Lucinda.Signatures;

using var signer = new EcdsaSignature();
var keyPair = signer.GenerateKeyPair();

var data = "Data to sign"u8.ToArray();
var signature = signer.Sign(data);
var isValid = signer.Verify(data, signature.Value);
```

### Key Derivation

```csharp
using Lucinda.KeyDerivation;

using var pbkdf2 = new Pbkdf2KeyDerivation();
var salt = SecureRandom.GenerateSalt(32);
var derivedKey = pbkdf2.DeriveKey("MyPassword", salt, iterations: 600000, derivedKeyLength: 32);
```

### Key Exchange (ECDH)

```csharp
using Lucinda.KeyExchange;

using var aliceEcdh = new EcdhKeyExchange();
using var bobEcdh = new EcdhKeyExchange();

var alicePublicKey = aliceEcdh.GetPublicKey();
var bobPublicKey = bobEcdh.GetPublicKey();

// Both derive the same shared secret
var aliceSharedSecret = aliceEcdh.DeriveSharedSecret(bobPublicKey.Value);
var bobSharedSecret = bobEcdh.DeriveSharedSecret(alicePublicKey.Value);
```

## Error Handling

All operations return a `CryptoResult<T>` that encapsulates success or failure:

```csharp
var result = aes.Encrypt(data);

if (result.IsSuccess)
{
    var encrypted = result.Value;
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

## Main Classes

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
| `SecureMessaging` | Signal Protocol-like secure messaging |
| `X3DHKeyAgreement` | X3DH key agreement |
| `DoubleRatchet` | Double Ratchet algorithm |

## Security Considerations

- Always securely store and protect private keys
- Uses `System.Security.Cryptography.RandomNumberGenerator` for secure random numbers
- Sensitive data is cleared from memory when possible
- Use AES-GCM or enable HMAC with AES-CBC for data integrity
- Use at least 2048-bit RSA keys and 256-bit AES keys
- Use PBKDF2 with at least 600,000 iterations for passwords

## Documentation

For complete documentation, samples, and benchmarks, visit the [GitHub repository](https://github.com/Taiizor/Lucinda).

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/Taiizor/Lucinda/blob/develop/LICENSE) file for details.

## Contributing

Contributions are welcome! Please visit our [GitHub repository](https://github.com/Taiizor/Lucinda) to submit issues or pull requests.
# Lucinda.Blazor

Blazor WebAssembly crypto library using the browser's native Web Crypto API. Part of the Lucinda end-to-end encryption library ecosystem.

## Features

- **AES-GCM & AES-CBC** - Symmetric encryption with authenticated encryption support
- **RSA-OAEP** - Asymmetric encryption for key wrapping and small data
- **ECDH** - Elliptic curve Diffie-Hellman key exchange (P-256, P-384, P-521)
- **ECDSA & RSA-PSS** - Digital signatures
- **HKDF & PBKDF2** - Key derivation functions
- **SHA-256/384/512** - Hashing and HMAC

## Installation

```bash
dotnet add package Lucinda.Blazor
```

## Quick Start

### 1. Register Services

```csharp
// Program.cs
using Lucinda.Blazor;

builder.Services.AddLucindaBlazor();
```

### 2. Configure Options (Optional)

```csharp
builder.Services.AddLucindaBlazor(options =>
{
    options.AesKeySize = 256;
    options.UseAesGcm = true;
    options.EcdhCurve = "P-256";
    options.Pbkdf2Iterations = 600000;
});
```

### 3. Use in Components

```csharp
@inject IBlazorSymmetricEncryption SymmetricEncryption
@inject IBlazorKeyExchange KeyExchange
@inject IBlazorSecureRandom SecureRandom

@code {
    private async Task EncryptData()
    {
        // Generate a key
        var keyResult = await SymmetricEncryption.GenerateKeyAsync();
        if (!keyResult.IsSuccess) return;

        var key = keyResult.Value;

        // Encrypt data
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var encryptResult = await SymmetricEncryption.EncryptAsync(plaintext, key);
        
        if (encryptResult.IsSuccess)
        {
            var ciphertext = encryptResult.Value;
            // Use encrypted data...
        }
    }
}
```

## Selective Service Registration

You can register only the services you need:

```csharp
// Only AES-GCM
builder.Services.AddLucindaAesGcm(keySize: 256);

// Only ECDH
builder.Services.AddLucindaEcdh(curve: "P-256");

// Only ECDSA
builder.Services.AddLucindaEcdsa(curve: "P-256", hashAlgorithm: "SHA-256");

// Only PBKDF2
builder.Services.AddLucindaPbkdf2(iterations: 600000);
```

## Available Interfaces

| Interface | Description |
|-----------|-------------|
| `IBlazorSymmetricEncryption` | AES-GCM or AES-CBC encryption |
| `IBlazorAsymmetricEncryption` | RSA-OAEP encryption |
| `IBlazorKeyExchange` | ECDH key exchange |
| `IBlazorSignature` | ECDSA or RSA-PSS signatures |
| `IBlazorKeyDerivation` | HKDF key derivation |
| `IBlazorPasswordKeyDerivation` | PBKDF2 password-based KDF |
| `IBlazorSecureRandom` | Cryptographic random generation |
| `IBlazorHash` | SHA hashing and HMAC |

## Check Web Crypto Availability

```csharp
@inject WebCryptoAvailability CryptoAvailability

@code {
    private async Task CheckSupport()
    {
        var isAvailable = await CryptoAvailability.IsAvailableAsync();
        
        if (isAvailable)
        {
            var diagnostics = await CryptoAvailability.RunDiagnosticsAsync();
            Console.WriteLine($"AES-GCM: {diagnostics.SupportedEncryption.Contains("AES-GCM")}");
            Console.WriteLine($"ECDH: {diagnostics.SupportedKeyExchange.Contains("ECDH")}");
        }
    }
}
```

## Key Format Compatibility

Lucinda.Blazor uses standard key formats compatible with the main Lucinda library:
- **Public Keys**: SPKI format
- **Private Keys**: PKCS8 format

This enables interoperability between Blazor WebAssembly clients and server-side .NET applications.

## Browser Support

Lucinda.Blazor requires a browser with Web Crypto API support:
- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 12+

## Security Considerations

1. **Key Storage**: Keys in browser memory can be vulnerable. Consider using `IndexedDB` with encryption for persistent storage.
2. **HTTPS Required**: Web Crypto API is only available in secure contexts (HTTPS).
3. **PBKDF2 Iterations**: Use at least 600,000 iterations for SHA-256 (OWASP recommendation).
4. **Random Number Generation**: All randomness comes from `crypto.getRandomValues()`, which is cryptographically secure.

## License

MIT License - See [LICENSE](../LICENSE) for details.

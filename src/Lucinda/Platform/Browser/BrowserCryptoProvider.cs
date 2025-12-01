// <copyright file="BrowserCryptoProvider.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET7_0_OR_GREATER

using Lucinda.Abstractions;
using Lucinda.Platform.Browser.Implementations;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Lucinda.Platform.Browser
{
    /// <summary>
    /// Browser-based cryptography provider that uses the Web Crypto API via JavaScript interop.
    /// This provider is designed for Blazor WebAssembly applications.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This provider implements cryptographic operations using the browser's native Web Crypto API,
    /// which provides hardware-accelerated, secure cryptographic primitives.
    /// </para>
    /// <para>
    /// Supported algorithms:
    /// <list type="bullet">
    /// <item><description>AES-GCM (128/192/256-bit keys)</description></item>
    /// <item><description>RSA-OAEP (2048/3072/4096-bit keys)</description></item>
    /// <item><description>ECDH (P-256, P-384, P-521)</description></item>
    /// <item><description>ECDSA (P-256, P-384, P-521)</description></item>
    /// <item><description>HKDF (SHA-256, SHA-384, SHA-512)</description></item>
    /// <item><description>PBKDF2 (SHA-256, SHA-384, SHA-512)</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    [SupportedOSPlatform("browser")]
    public sealed class BrowserCryptoProvider : ICryptoProvider
    {
        private bool _disposed;

        /// <inheritdoc/>
        public CryptoPlatformType PlatformType => CryptoPlatformType.Browser;

        /// <inheritdoc/>
        public bool IsAvailable => CryptoPlatform.IsBrowser;

        /// <inheritdoc/>
        public CryptoResult<ISymmetricEncryption> CreateAesGcm(byte[] key)
        {
            try
            {
                ThrowIfDisposed();
                ValidateKey(key, "AES key");

                BrowserAesGcm encryption = new(key);
                return CryptoResult<ISymmetricEncryption>.Success(encryption);
            }
            catch (Exception ex)
            {
                return CryptoResult<ISymmetricEncryption>.Failure($"Failed to create AES-GCM: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<ISymmetricEncryption> CreateAesCbc(byte[] key)
        {
            try
            {
                ThrowIfDisposed();
                ValidateKey(key, "AES key");

                BrowserAesCbc encryption = new(key);
                return CryptoResult<ISymmetricEncryption>.Success(encryption);
            }
            catch (Exception ex)
            {
                return CryptoResult<ISymmetricEncryption>.Failure($"Failed to create AES-CBC: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IAsymmetricEncryption> CreateRsa(int keySizeInBits = 2048)
        {
            try
            {
                ThrowIfDisposed();
                ValidateRsaKeySize(keySizeInBits);

                BrowserRsa encryption = new(keySizeInBits);
                return CryptoResult<IAsymmetricEncryption>.Success(encryption);
            }
            catch (Exception ex)
            {
                return CryptoResult<IAsymmetricEncryption>.Failure($"Failed to create RSA: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IAsymmetricEncryption> CreateRsa(byte[] keyData, KeyFormat format, bool isPrivateKey)
        {
            try
            {
                ThrowIfDisposed();
                if (keyData == null || keyData.Length == 0)
                {
                    return CryptoResult<IAsymmetricEncryption>.Failure("Key data cannot be null or empty.");
                }

                BrowserRsa encryption = new(keyData, format, isPrivateKey);
                return CryptoResult<IAsymmetricEncryption>.Success(encryption);
            }
            catch (Exception ex)
            {
                return CryptoResult<IAsymmetricEncryption>.Failure($"Failed to create RSA from key data: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IKeyExchange> CreateEcdh(string curveName = "P-256")
        {
            try
            {
                ThrowIfDisposed();
                ValidateCurve(curveName);

                BrowserEcdh keyExchange = new(curveName);
                return CryptoResult<IKeyExchange>.Success(keyExchange);
            }
            catch (Exception ex)
            {
                return CryptoResult<IKeyExchange>.Failure($"Failed to create ECDH: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IKeyExchange> CreateEcdh(byte[] keyData, KeyFormat format, string curveName = "P-256")
        {
            try
            {
                ThrowIfDisposed();
                if (keyData == null || keyData.Length == 0)
                {
                    return CryptoResult<IKeyExchange>.Failure("Key data cannot be null or empty.");
                }
                ValidateCurve(curveName);

                BrowserEcdh keyExchange = new(curveName, keyData, format);
                return CryptoResult<IKeyExchange>.Success(keyExchange);
            }
            catch (Exception ex)
            {
                return CryptoResult<IKeyExchange>.Failure($"Failed to create ECDH from key data: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IDigitalSignature> CreateEcdsa(string curveName = "P-256")
        {
            try
            {
                ThrowIfDisposed();
                ValidateCurve(curveName);

                BrowserEcdsa signature = new(curveName);
                return CryptoResult<IDigitalSignature>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<IDigitalSignature>.Failure($"Failed to create ECDSA: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IDigitalSignature> CreateEcdsa(byte[] keyData, KeyFormat format, bool isPrivateKey, string curveName = "P-256")
        {
            try
            {
                ThrowIfDisposed();
                if (keyData == null || keyData.Length == 0)
                {
                    return CryptoResult<IDigitalSignature>.Failure("Key data cannot be null or empty.");
                }
                ValidateCurve(curveName);

                BrowserEcdsa signature = new(curveName, keyData, format, isPrivateKey);
                return CryptoResult<IDigitalSignature>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<IDigitalSignature>.Failure($"Failed to create ECDSA from key data: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IDigitalSignature> CreateRsaSignature(int keySizeInBits = 2048)
        {
            try
            {
                ThrowIfDisposed();
                ValidateRsaKeySize(keySizeInBits);

                BrowserRsaSignature signature = new(keySizeInBits);
                return CryptoResult<IDigitalSignature>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<IDigitalSignature>.Failure($"Failed to create RSA signature: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IKeyDerivation> CreateHkdf(string hashAlgorithm = "SHA256")
        {
            try
            {
                ThrowIfDisposed();
                ValidateHashAlgorithm(hashAlgorithm);

                BrowserHkdf kdf = new(hashAlgorithm);
                return CryptoResult<IKeyDerivation>.Success(kdf);
            }
            catch (Exception ex)
            {
                return CryptoResult<IKeyDerivation>.Failure($"Failed to create HKDF: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IKeyDerivation> CreatePbkdf2(string hashAlgorithm = "SHA256")
        {
            try
            {
                ThrowIfDisposed();
                ValidateHashAlgorithm(hashAlgorithm);

                BrowserPbkdf2 kdf = new(hashAlgorithm);
                return CryptoResult<IKeyDerivation>.Success(kdf);
            }
            catch (Exception ex)
            {
                return CryptoResult<IKeyDerivation>.Failure($"Failed to create PBKDF2: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> GenerateRandomBytes(int length)
        {
            try
            {
                ThrowIfDisposed();
                if (length <= 0)
                {
                    return CryptoResult<byte[]>.Failure("Length must be greater than zero.");
                }

                // RandomNumberGenerator is supported in Blazor WASM
                byte[] bytes = new byte[length];
                RandomNumberGenerator.Fill(bytes);
                return CryptoResult<byte[]>.Success(bytes);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to generate random bytes: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ComputeSha256(byte[] data)
        {
            try
            {
                ThrowIfDisposed();
                if (data == null)
                {
                    return CryptoResult<byte[]>.Failure("Data cannot be null.");
                }

                // SHA256 is supported in Blazor WASM
                byte[] hash = SHA256.HashData(data);
                return CryptoResult<byte[]>.Success(hash);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to compute SHA-256: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ComputeSha384(byte[] data)
        {
            try
            {
                ThrowIfDisposed();
                if (data == null)
                {
                    return CryptoResult<byte[]>.Failure("Data cannot be null.");
                }

                // SHA384 is supported in Blazor WASM
                byte[] hash = SHA384.HashData(data);
                return CryptoResult<byte[]>.Success(hash);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to compute SHA-384: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ComputeSha512(byte[] data)
        {
            try
            {
                ThrowIfDisposed();
                if (data == null)
                {
                    return CryptoResult<byte[]>.Failure("Data cannot be null.");
                }

                // SHA512 is supported in Blazor WASM
                byte[] hash = SHA512.HashData(data);
                return CryptoResult<byte[]>.Success(hash);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to compute SHA-512: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ComputeHmac(byte[] key, byte[] data, string hashAlgorithm = "SHA256")
        {
            try
            {
                ThrowIfDisposed();
                if (key == null || key.Length == 0)
                {
                    return CryptoResult<byte[]>.Failure("Key cannot be null or empty.");
                }
                if (data == null)
                {
                    return CryptoResult<byte[]>.Failure("Data cannot be null.");
                }

                // HMAC requires Web Crypto API interop in browser
                return BrowserCryptoInterop.ComputeHmac(key, data, hashAlgorithm);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to compute HMAC: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BrowserCryptoProvider));
            }
#endif
        }

        private static void ValidateKey(byte[] key, string keyName)
        {
            if (key == null || key.Length == 0)
            {
                throw new ArgumentException($"{keyName} cannot be null or empty.", keyName);
            }

            if (key.Length is not 16 and not 24 and not 32)
            {
                throw new ArgumentException($"{keyName} must be 16, 24, or 32 bytes.", keyName);
            }
        }

        private static void ValidateRsaKeySize(int keySizeInBits)
        {
            if (keySizeInBits is not 2048 and not 3072 and not 4096)
            {
                throw new ArgumentException("RSA key size must be 2048, 3072, or 4096 bits.", nameof(keySizeInBits));
            }
        }

        private static void ValidateCurve(string curveName)
        {
            string normalized = curveName.ToUpperInvariant();
            if (normalized is not "P-256" and not "P256" and
                not "P-384" and not "P384" and
                not "P-521" and not "P521")
            {
                throw new ArgumentException($"Unsupported curve: {curveName}. Supported curves: P-256, P-384, P-521", nameof(curveName));
            }
        }

        private static void ValidateHashAlgorithm(string hashAlgorithm)
        {
            string normalized = hashAlgorithm.ToUpperInvariant().Replace("-", "");
            if (normalized is not "SHA256" and not "SHA384" and not "SHA512")
            {
                throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}. Supported: SHA256, SHA384, SHA512", nameof(hashAlgorithm));
            }
        }
    }
}

#endif
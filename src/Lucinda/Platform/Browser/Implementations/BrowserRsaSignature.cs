// <copyright file="BrowserRsaSignature.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET7_0_OR_GREATER

using Lucinda.Abstractions;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Lucinda.Platform.Browser.Implementations
{
    /// <summary>
    /// Browser-based RSA digital signature implementation using the Web Crypto API.
    /// </summary>
    [SupportedOSPlatform("browser")]
    internal sealed class BrowserRsaSignature : IDigitalSignature
    {
        private readonly string _hashAlgorithm;
        private byte[]? _publicKey;
        private byte[]? _privateKey;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BrowserRsaSignature"/> class.
        /// </summary>
        /// <param name="keySizeInBits">The key size in bits.</param>
        /// <param name="hashAlgorithm">The hash algorithm (default: SHA-256).</param>
        public BrowserRsaSignature(int keySizeInBits, string hashAlgorithm = "SHA-256")
        {
            if (keySizeInBits is not 2048 and not 3072 and not 4096)
            {
                throw new ArgumentException("Key size must be 2048, 3072, or 4096 bits.", nameof(keySizeInBits));
            }

            KeySizeInBits = keySizeInBits;
            _hashAlgorithm = BrowserCryptoInterop.NormalizeHashAlgorithm(hashAlgorithm);
        }

        /// <inheritdoc/>
        public string AlgorithmName => "RSA-PSS";

        /// <inheritdoc/>
        public int KeySizeInBits { get; }

        /// <inheritdoc/>
        public bool HasPrivateKey => _privateKey != null;

        /// <inheritdoc/>
        public CryptoResult<byte[]> Sign(byte[] data)
        {
            try
            {
                ThrowIfDisposed();

                if (data == null)
                {
                    return CryptoResult<byte[]>.Failure("Data cannot be null.");
                }

                if (_privateKey == null)
                {
                    return CryptoResult<byte[]>.Failure("No private key available. Generate a key pair first.");
                }

                BrowserCryptoInterop.EnsureInitialized();
                byte[] signature = BrowserCryptoInterop.RsaSign(_privateKey, data, _hashAlgorithm);

                return CryptoResult<byte[]>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Signing failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> SignHash(byte[] hash)
        {
            // Web Crypto API doesn't support signing pre-computed hashes directly
            return CryptoResult<byte[]>.Failure("SignHash is not directly supported in browser. Use Sign instead.");
        }

        /// <inheritdoc/>
        public CryptoResult<bool> Verify(byte[] data, byte[] signature)
        {
            try
            {
                ThrowIfDisposed();

                if (data == null)
                {
                    return CryptoResult<bool>.Failure("Data cannot be null.");
                }

                if (signature == null)
                {
                    return CryptoResult<bool>.Failure("Signature cannot be null.");
                }

                if (_publicKey == null)
                {
                    return CryptoResult<bool>.Failure("No public key available.");
                }

                BrowserCryptoInterop.EnsureInitialized();
                bool isValid = BrowserCryptoInterop.RsaVerify(_publicKey, data, signature, _hashAlgorithm);

                return CryptoResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Verification failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> VerifyHash(byte[] hash, byte[] signature)
        {
            // Web Crypto API doesn't support verifying pre-computed hashes directly
            return CryptoResult<bool>.Failure("VerifyHash is not directly supported in browser. Use Verify instead.");
        }

        /// <inheritdoc/>
        public CryptoResult<AsymmetricKeyPair> GenerateKeyPair()
        {
            try
            {
                ThrowIfDisposed();

                BrowserCryptoInterop.EnsureInitialized();
                (byte[]? publicKey, byte[]? privateKey) = BrowserCryptoInterop.RsaGenerateKeyPair(KeySizeInBits);

                _publicKey = publicKey;
                _privateKey = privateKey;

                AsymmetricKeyPair keyPair = new(_publicKey, _privateKey);
                return CryptoResult<AsymmetricKeyPair>.Success(keyPair);
            }
            catch (Exception ex)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure($"Key generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ExportPublicKey(KeyFormat format)
        {
            try
            {
                ThrowIfDisposed();

                if (_publicKey == null)
                {
                    return CryptoResult<byte[]>.Failure("No public key available.");
                }

                if (format is not KeyFormat.SubjectPublicKeyInfo and not KeyFormat.Raw)
                {
                    return CryptoResult<byte[]>.Failure($"Unsupported key format: {format}. Browser supports SubjectPublicKeyInfo format.");
                }

                byte[] result = new byte[_publicKey.Length];
                Array.Copy(_publicKey, result, _publicKey.Length);

                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Export failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ExportPrivateKey(KeyFormat format)
        {
            try
            {
                ThrowIfDisposed();

                if (_privateKey == null)
                {
                    return CryptoResult<byte[]>.Failure("No private key available.");
                }

                if (format != KeyFormat.Pkcs8)
                {
                    return CryptoResult<byte[]>.Failure($"Unsupported key format: {format}. Browser supports PKCS8 format.");
                }

                byte[] result = new byte[_privateKey.Length];
                Array.Copy(_privateKey, result, _privateKey.Length);

                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Export failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> ImportPublicKey(byte[] keyData, KeyFormat format)
        {
            try
            {
                ThrowIfDisposed();

                if (keyData == null || keyData.Length == 0)
                {
                    return CryptoResult<bool>.Failure("Key data cannot be null or empty.");
                }

                if (format is not KeyFormat.SubjectPublicKeyInfo and not KeyFormat.Raw)
                {
                    return CryptoResult<bool>.Failure($"Unsupported key format: {format}. Browser supports SubjectPublicKeyInfo format.");
                }

                _publicKey = new byte[keyData.Length];
                Array.Copy(keyData, _publicKey, keyData.Length);

                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Import failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> ImportPrivateKey(byte[] keyData, KeyFormat format)
        {
            try
            {
                ThrowIfDisposed();

                if (keyData == null || keyData.Length == 0)
                {
                    return CryptoResult<bool>.Failure("Key data cannot be null or empty.");
                }

                if (format != KeyFormat.Pkcs8)
                {
                    return CryptoResult<bool>.Failure($"Unsupported key format: {format}. Browser supports PKCS8 format.");
                }

                _privateKey = new byte[keyData.Length];
                Array.Copy(keyData, _privateKey, keyData.Length);

                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Import failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            if (_privateKey != null)
            {
                CryptographicOperations.ZeroMemory(_privateKey);
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
                throw new ObjectDisposedException(nameof(BrowserRsaSignature));
            }
#endif
        }
    }
}

#endif
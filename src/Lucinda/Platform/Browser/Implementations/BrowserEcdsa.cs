// <copyright file="BrowserEcdsa.cs" company="Lucinda">
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
    /// Browser-based ECDSA digital signature implementation using the Web Crypto API.
    /// </summary>
    [SupportedOSPlatform("browser")]
    internal sealed class BrowserEcdsa : IDigitalSignature
    {
        private readonly string _curveName;
        private readonly string _hashAlgorithm;
        private byte[]? _publicKey;
        private byte[]? _privateKey;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BrowserEcdsa"/> class.
        /// </summary>
        /// <param name="curveName">The elliptic curve name (P-256, P-384, P-521).</param>
        /// <param name="hashAlgorithm">The hash algorithm (default: based on curve).</param>
        public BrowserEcdsa(string curveName, string? hashAlgorithm = null)
        {
            _curveName = BrowserCryptoInterop.NormalizeCurveName(curveName);
            _hashAlgorithm = hashAlgorithm ?? GetDefaultHashAlgorithm(_curveName);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BrowserEcdsa"/> class from existing key data.
        /// </summary>
        /// <param name="curveName">The elliptic curve name.</param>
        /// <param name="keyData">The key data.</param>
        /// <param name="format">The key format.</param>
        /// <param name="isPrivateKey">Whether the key is a private key.</param>
        public BrowserEcdsa(string curveName, byte[] keyData, KeyFormat format, bool isPrivateKey)
        {
            _curveName = BrowserCryptoInterop.NormalizeCurveName(curveName);
            _hashAlgorithm = GetDefaultHashAlgorithm(_curveName);

            // Note: format parameter is accepted for API compatibility but not used
            // as BrowserEcdsa always expects Raw for public keys and PKCS8 for private keys
            _ = format;

            if (keyData == null || keyData.Length == 0)
            {
                throw new ArgumentNullException(nameof(keyData));
            }

            if (isPrivateKey)
            {
                _privateKey = new byte[keyData.Length];
                Array.Copy(keyData, _privateKey, keyData.Length);
            }
            else
            {
                _publicKey = new byte[keyData.Length];
                Array.Copy(keyData, _publicKey, keyData.Length);
            }
        }

        /// <inheritdoc/>
        public string AlgorithmName => $"ECDSA-{_curveName}";

        /// <inheritdoc/>
        public int KeySizeInBits => _curveName switch
        {
            "P-256" => 256,
            "P-384" => 384,
            "P-521" => 521,
            _ => 256
        };

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
                byte[] signature = BrowserCryptoInterop.EcdsaSign(_privateKey, data, _curveName, _hashAlgorithm);

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
            // Web Crypto API doesn't have a separate SignHash method
            // The hash is computed internally, so we need to use Sign
            // This is a limitation of the Web Crypto API
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
                bool isValid = BrowserCryptoInterop.EcdsaVerify(_publicKey, data, signature, _curveName, _hashAlgorithm);

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
            // Web Crypto API doesn't have a separate VerifyHash method
            return CryptoResult<bool>.Failure("VerifyHash is not directly supported in browser. Use Verify instead.");
        }

        /// <inheritdoc/>
        public CryptoResult<AsymmetricKeyPair> GenerateKeyPair()
        {
            try
            {
                ThrowIfDisposed();

                BrowserCryptoInterop.EnsureInitialized();
                (byte[]? publicKey, byte[]? privateKey) = BrowserCryptoInterop.EcdsaGenerateKeyPair(_curveName);

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

                if (format is not KeyFormat.Raw and not KeyFormat.SubjectPublicKeyInfo)
                {
                    return CryptoResult<byte[]>.Failure($"Unsupported key format: {format}. Browser supports Raw format.");
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

                if (format is not KeyFormat.Raw and not KeyFormat.SubjectPublicKeyInfo)
                {
                    return CryptoResult<bool>.Failure($"Unsupported key format: {format}. Browser supports Raw format.");
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
                throw new ObjectDisposedException(nameof(BrowserEcdsa));
            }
#endif
        }

        private static string GetDefaultHashAlgorithm(string curveName)
        {
            return curveName switch
            {
                "P-256" => "SHA-256",
                "P-384" => "SHA-384",
                "P-521" => "SHA-512",
                _ => "SHA-256"
            };
        }
    }
}

#endif
// <copyright file="BrowserRsa.cs" company="Lucinda">
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
    /// Browser-based RSA implementation using the Web Crypto API.
    /// </summary>
    [SupportedOSPlatform("browser")]
    internal sealed class BrowserRsa : IAsymmetricEncryption
    {
        private byte[]? _publicKey;
        private byte[]? _privateKey;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BrowserRsa"/> class with key generation.
        /// </summary>
        /// <param name="keySizeInBits">The key size in bits.</param>
        public BrowserRsa(int keySizeInBits)
        {
            if (keySizeInBits is not 2048 and not 3072 and not 4096)
            {
                throw new ArgumentException("Key size must be 2048, 3072, or 4096 bits.", nameof(keySizeInBits));
            }

            KeySizeInBits = keySizeInBits;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BrowserRsa"/> class from existing key data.
        /// </summary>
        /// <param name="keyData">The key data.</param>
        /// <param name="format">The key format.</param>
        /// <param name="isPrivateKey">Whether the key is a private key.</param>
        public BrowserRsa(byte[] keyData, KeyFormat format, bool isPrivateKey)
        {
            // Note: format parameter is accepted for API compatibility but not used
            // as BrowserRsa always expects SPKI for public keys and PKCS8 for private keys
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

            // Estimate key size from key data length (approximate)
            KeySizeInBits = isPrivateKey ? EstimateKeySizeFromPrivateKey(keyData.Length) : EstimateKeySizeFromPublicKey(keyData.Length);
        }

        /// <inheritdoc/>
        public string AlgorithmName => "RSA-OAEP";

        /// <inheritdoc/>
        public int KeySizeInBits { get; }

        /// <inheritdoc/>
        public bool HasPrivateKey => _privateKey != null;

        /// <inheritdoc/>
        public CryptoResult<byte[]> Encrypt(byte[] plaintext)
        {
            try
            {
                ThrowIfDisposed();

                if (plaintext == null)
                {
                    return CryptoResult<byte[]>.Failure("Plaintext cannot be null.");
                }

                if (_publicKey == null)
                {
                    return CryptoResult<byte[]>.Failure("No public key available. Generate a key pair first.");
                }

                BrowserCryptoInterop.EnsureInitialized();
                byte[] ciphertext = BrowserCryptoInterop.RsaEncrypt(_publicKey, plaintext);

                return CryptoResult<byte[]>.Success(ciphertext);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Decrypt(byte[] ciphertext)
        {
            try
            {
                ThrowIfDisposed();

                if (ciphertext == null)
                {
                    return CryptoResult<byte[]>.Failure("Ciphertext cannot be null.");
                }

                if (_privateKey == null)
                {
                    return CryptoResult<byte[]>.Failure("No private key available.");
                }

                BrowserCryptoInterop.EnsureInitialized();
                byte[] plaintext = BrowserCryptoInterop.RsaDecrypt(_privateKey, ciphertext);

                return CryptoResult<byte[]>.Success(plaintext);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Decryption failed: {ex.Message}");
            }
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

                // Web Crypto API exports in SubjectPublicKeyInfo format
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

                // Web Crypto API exports in PKCS8 format
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
                throw new ObjectDisposedException(nameof(BrowserRsa));
            }
#endif
        }

        private static int EstimateKeySizeFromPublicKey(int length)
        {
            // Rough estimation based on SPKI encoded key length
            if (length < 300)
            {
                return 2048;
            }

            if (length < 450)
            {
                return 3072;
            }

            return 4096;
        }

        private static int EstimateKeySizeFromPrivateKey(int length)
        {
            // Rough estimation based on PKCS8 encoded key length
            if (length < 1300)
            {
                return 2048;
            }

            if (length < 1800)
            {
                return 3072;
            }

            return 4096;
        }
    }
}

#endif
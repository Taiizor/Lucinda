// <copyright file="BrowserAesCbc.cs" company="Lucinda">
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
    /// Browser-based AES-CBC implementation using the Web Crypto API.
    /// Note: AES-CBC does not provide authentication. Consider using AES-GCM instead.
    /// </summary>
    [SupportedOSPlatform("browser")]
    internal sealed class BrowserAesCbc : ISymmetricEncryption
    {
        private const int IvSize = 16;
        private const int BlockSize = 16;

        private readonly byte[] _key;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BrowserAesCbc"/> class.
        /// </summary>
        /// <param name="key">The encryption key (16, 24, or 32 bytes).</param>
        public BrowserAesCbc(byte[] key)
        {
            if (key == null || key.Length == 0)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.Length is not 16 and not 24 and not 32)
            {
                throw new ArgumentException("Key must be 16, 24, or 32 bytes.", nameof(key));
            }

            _key = new byte[key.Length];
            Array.Copy(key, _key, key.Length);
        }

        /// <inheritdoc/>
        public string AlgorithmName => "AES-CBC";

        /// <inheritdoc/>
        public int KeySizeInBits => _key.Length * 8;

        /// <inheritdoc/>
        public int BlockSizeInBits => 128;

        /// <inheritdoc/>
        public CryptoResult<byte[]> Encrypt(byte[] plaintext)
        {
            return Encrypt(plaintext, null);
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Encrypt(byte[] plaintext, byte[]? associatedData)
        {
            try
            {
                ThrowIfDisposed();

                if (plaintext == null)
                {
                    return CryptoResult<byte[]>.Failure("Plaintext cannot be null.");
                }

                // AES-CBC does not support associated data natively
                // If AAD is provided, we could compute HMAC separately, but for simplicity
                // we ignore it here and recommend AES-GCM for authenticated encryption
                if (associatedData != null && associatedData.Length > 0)
                {
                    return CryptoResult<byte[]>.Failure("AES-CBC does not support associated data. Use AES-GCM for authenticated encryption.");
                }

                // Generate random IV
                byte[] iv = new byte[IvSize];
                RandomNumberGenerator.Fill(iv);

                // Call Web Crypto API via JS interop
                BrowserCryptoInterop.EnsureInitialized();
                byte[] ciphertext = BrowserCryptoInterop.AesCbcEncrypt(_key, iv, plaintext);

                // Format: iv || ciphertext
                byte[] result = new byte[IvSize + ciphertext.Length];
                Array.Copy(iv, 0, result, 0, IvSize);
                Array.Copy(ciphertext, 0, result, IvSize, ciphertext.Length);

                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Decrypt(byte[] ciphertext)
        {
            return Decrypt(ciphertext, null);
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Decrypt(byte[] ciphertext, byte[]? associatedData)
        {
            try
            {
                ThrowIfDisposed();

                if (ciphertext == null)
                {
                    return CryptoResult<byte[]>.Failure("Ciphertext cannot be null.");
                }

                if (ciphertext.Length < IvSize + BlockSize)
                {
                    return CryptoResult<byte[]>.Failure("Ciphertext is too short.");
                }

                if (associatedData != null && associatedData.Length > 0)
                {
                    return CryptoResult<byte[]>.Failure("AES-CBC does not support associated data. Use AES-GCM for authenticated encryption.");
                }

                // Extract IV
                byte[] iv = new byte[IvSize];
                Array.Copy(ciphertext, 0, iv, 0, IvSize);

                // Extract ciphertext
                byte[] encryptedData = new byte[ciphertext.Length - IvSize];
                Array.Copy(ciphertext, IvSize, encryptedData, 0, encryptedData.Length);

                // Call Web Crypto API via JS interop
                BrowserCryptoInterop.EnsureInitialized();
                byte[] plaintext = BrowserCryptoInterop.AesCbcDecrypt(_key, iv, encryptedData);

                return CryptoResult<byte[]>.Success(plaintext);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Decryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> GenerateKey()
        {
            try
            {
                byte[] key = new byte[_key.Length];
                RandomNumberGenerator.Fill(key);
                return CryptoResult<byte[]>.Success(key);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Key generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> GenerateIV()
        {
            try
            {
                byte[] iv = new byte[IvSize];
                RandomNumberGenerator.Fill(iv);
                return CryptoResult<byte[]>.Success(iv);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"IV generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            // Securely clear the key
            CryptographicOperations.ZeroMemory(_key);
            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BrowserAesCbc));
            }
#endif
        }
    }
}

#endif
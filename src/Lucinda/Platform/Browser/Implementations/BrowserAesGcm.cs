// <copyright file="BrowserAesGcm.cs" company="Lucinda">
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
    /// Browser-based AES-GCM implementation using the Web Crypto API.
    /// </summary>
    [SupportedOSPlatform("browser")]
    internal sealed class BrowserAesGcm : ISymmetricEncryption
    {
        private const int NonceSize = 12;
        private const int TagSize = 16;

        private readonly byte[] _key;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BrowserAesGcm"/> class.
        /// </summary>
        /// <param name="key">The encryption key (16, 24, or 32 bytes).</param>
        public BrowserAesGcm(byte[] key)
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
        public string AlgorithmName => "AES-GCM";

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

                // Generate random nonce
                byte[] nonce = new byte[NonceSize];
                RandomNumberGenerator.Fill(nonce);

                // Call Web Crypto API via JS interop
                BrowserCryptoInterop.EnsureInitialized();
                byte[] ciphertext = BrowserCryptoInterop.AesGcmEncrypt(_key, nonce, plaintext, associatedData);

                // Format: nonce || ciphertext (with tag)
                byte[] result = new byte[NonceSize + ciphertext.Length];
                Array.Copy(nonce, 0, result, 0, NonceSize);
                Array.Copy(ciphertext, 0, result, NonceSize, ciphertext.Length);

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

                if (ciphertext.Length < NonceSize + TagSize)
                {
                    return CryptoResult<byte[]>.Failure("Ciphertext is too short.");
                }

                // Extract nonce
                byte[] nonce = new byte[NonceSize];
                Array.Copy(ciphertext, 0, nonce, 0, NonceSize);

                // Extract ciphertext with tag
                byte[] encryptedData = new byte[ciphertext.Length - NonceSize];
                Array.Copy(ciphertext, NonceSize, encryptedData, 0, encryptedData.Length);

                // Call Web Crypto API via JS interop
                BrowserCryptoInterop.EnsureInitialized();
                byte[] plaintext = BrowserCryptoInterop.AesGcmDecrypt(_key, nonce, encryptedData, associatedData);

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
                byte[] iv = new byte[NonceSize];
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
                throw new ObjectDisposedException(nameof(BrowserAesGcm));
            }
#endif
        }
    }
}

#endif
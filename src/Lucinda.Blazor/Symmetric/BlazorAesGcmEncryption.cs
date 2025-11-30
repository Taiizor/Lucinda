// -----------------------------------------------------------------------
// <copyright file="BlazorAesGcmEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;
using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.Symmetric
{
    /// <summary>
    /// AES-GCM encryption implementation for Blazor WebAssembly using Web Crypto API.
    /// </summary>
    public class BlazorAesGcmEncryption : IBlazorSymmetricEncryption
    {
        private readonly WebCryptoInterop _webCrypto;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorAesGcmEncryption"/> class.
        /// </summary>
        /// <param name="webCrypto">The Web Crypto interop service.</param>
        /// <param name="keySize">The key size in bits (128, 192, or 256). Default is 256.</param>
        public BlazorAesGcmEncryption(WebCryptoInterop webCrypto, int keySize = 256)
        {
            _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));

            if (keySize is not 128 and not 192 and not 256)
            {
                throw new ArgumentException("Key size must be 128, 192, or 256 bits.", nameof(keySize));
            }

            KeySize = keySize;
        }

        /// <inheritdoc/>
        public string AlgorithmName => "AES-GCM";

        /// <inheritdoc/>
        public int KeySize { get; }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> EncryptAsync(byte[] plaintext, byte[] key)
        {
            ThrowIfDisposed();

            if (plaintext == null)
            {
                return CryptoResult<byte[]>.Failure("Plaintext cannot be null.");
            }

            if (key == null)
            {
                return CryptoResult<byte[]>.Failure("Key cannot be null.");
            }

            if (key.Length != KeySize / 8)
            {
                return CryptoResult<byte[]>.Failure($"Key must be {KeySize / 8} bytes for AES-{KeySize}.");
            }

            try
            {
                byte[] result = await _webCrypto.AesGcmEncryptAsync(key, plaintext);
                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"AES-GCM encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> EncryptAsync(byte[] plaintext, byte[] key, byte[]? associatedData)
        {
            ThrowIfDisposed();

            if (plaintext == null)
            {
                return CryptoResult<byte[]>.Failure("Plaintext cannot be null.");
            }

            if (key == null)
            {
                return CryptoResult<byte[]>.Failure("Key cannot be null.");
            }

            if (key.Length != KeySize / 8)
            {
                return CryptoResult<byte[]>.Failure($"Key must be {KeySize / 8} bytes for AES-{KeySize}.");
            }

            try
            {
                byte[] result = await _webCrypto.AesGcmEncryptAsync(key, plaintext, associatedData);
                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"AES-GCM encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> DecryptAsync(byte[] ciphertext, byte[] key)
        {
            ThrowIfDisposed();

            if (ciphertext == null)
            {
                return CryptoResult<byte[]>.Failure("Ciphertext cannot be null.");
            }

            if (key == null)
            {
                return CryptoResult<byte[]>.Failure("Key cannot be null.");
            }

            if (key.Length != KeySize / 8)
            {
                return CryptoResult<byte[]>.Failure($"Key must be {KeySize / 8} bytes for AES-{KeySize}.");
            }

            // Minimum ciphertext length: 12 (IV) + 16 (tag) = 28 bytes
            if (ciphertext.Length < 28)
            {
                return CryptoResult<byte[]>.Failure("Ciphertext is too short.");
            }

            try
            {
                byte[] result = await _webCrypto.AesGcmDecryptAsync(key, ciphertext);
                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"AES-GCM decryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> DecryptAsync(byte[] ciphertext, byte[] key, byte[]? associatedData)
        {
            ThrowIfDisposed();

            if (ciphertext == null)
            {
                return CryptoResult<byte[]>.Failure("Ciphertext cannot be null.");
            }

            if (key == null)
            {
                return CryptoResult<byte[]>.Failure("Key cannot be null.");
            }

            if (key.Length != KeySize / 8)
            {
                return CryptoResult<byte[]>.Failure($"Key must be {KeySize / 8} bytes for AES-{KeySize}.");
            }

            if (ciphertext.Length < 28)
            {
                return CryptoResult<byte[]>.Failure("Ciphertext is too short.");
            }

            try
            {
                byte[] result = await _webCrypto.AesGcmDecryptAsync(key, ciphertext, associatedData);
                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"AES-GCM decryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> GenerateKeyAsync()
        {
            ThrowIfDisposed();

            try
            {
                byte[] key = await _webCrypto.GenerateAesKeyAsync(KeySize);
                return CryptoResult<byte[]>.Success(key);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Key generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> GenerateIvAsync()
        {
            ThrowIfDisposed();

            try
            {
                // AES-GCM uses 12-byte (96-bit) IV
                byte[] iv = await _webCrypto.GetRandomBytesAsync(12);
                return CryptoResult<byte[]>.Success(iv);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"IV generation failed: {ex.Message}");
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BlazorAesGcmEncryption));
            }
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            _disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}
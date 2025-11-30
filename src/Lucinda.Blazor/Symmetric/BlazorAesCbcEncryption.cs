// -----------------------------------------------------------------------
// <copyright file="BlazorAesCbcEncryption.cs" company="Lucinda">
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
    /// AES-CBC encryption implementation for Blazor WebAssembly using Web Crypto API.
    /// Note: AES-CBC does not support authenticated encryption (AAD).
    /// </summary>
    public class BlazorAesCbcEncryption : IBlazorSymmetricEncryption
    {
        private readonly WebCryptoInterop _webCrypto;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorAesCbcEncryption"/> class.
        /// </summary>
        /// <param name="webCrypto">The Web Crypto interop service.</param>
        /// <param name="keySize">The key size in bits (128, 192, or 256). Default is 256.</param>
        public BlazorAesCbcEncryption(WebCryptoInterop webCrypto, int keySize = 256)
        {
            _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));

            if (keySize is not 128 and not 192 and not 256)
            {
                throw new ArgumentException("Key size must be 128, 192, or 256 bits.", nameof(keySize));
            }

            KeySize = keySize;
        }

        /// <inheritdoc/>
        public string AlgorithmName => "AES-CBC";

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
                byte[] result = await _webCrypto.AesCbcEncryptAsync(key, plaintext);
                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"AES-CBC encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public Task<CryptoResult<byte[]>> EncryptAsync(byte[] plaintext, byte[] key, byte[]? associatedData)
        {
            // AES-CBC does not support AAD, ignore it but log a warning
            return EncryptAsync(plaintext, key);
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

            // Minimum ciphertext length: 16 (IV) + 16 (at least one block) = 32 bytes
            if (ciphertext.Length < 32)
            {
                return CryptoResult<byte[]>.Failure("Ciphertext is too short.");
            }

            try
            {
                byte[] result = await _webCrypto.AesCbcDecryptAsync(key, ciphertext);
                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"AES-CBC decryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public Task<CryptoResult<byte[]>> DecryptAsync(byte[] ciphertext, byte[] key, byte[]? associatedData)
        {
            // AES-CBC does not support AAD, ignore it
            return DecryptAsync(ciphertext, key);
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
                // AES-CBC uses 16-byte (128-bit) IV
                byte[] iv = await _webCrypto.GetRandomBytesAsync(16);
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
                throw new ObjectDisposedException(nameof(BlazorAesCbcEncryption));
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
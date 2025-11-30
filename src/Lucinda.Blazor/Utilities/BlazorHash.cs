// -----------------------------------------------------------------------
// <copyright file="BlazorHash.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;
using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.Utilities
{
    /// <summary>
    /// Hash and HMAC implementation for Blazor WebAssembly using Web Crypto API.
    /// </summary>
    public class BlazorHash : IBlazorHash
    {
        private readonly WebCryptoInterop _webCrypto;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorHash"/> class.
        /// </summary>
        /// <param name="webCrypto">The Web Crypto interop service.</param>
        /// <param name="hashAlgorithm">The hash algorithm (SHA-1, SHA-256, SHA-384, or SHA-512). Default is SHA-256.</param>
        public BlazorHash(WebCryptoInterop webCrypto, string hashAlgorithm = "SHA-256")
        {
            _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));

            if (hashAlgorithm is not "SHA-1" and not "SHA-256" and
                not "SHA-384" and not "SHA-512")
            {
                throw new ArgumentException("Hash algorithm must be SHA-1, SHA-256, SHA-384, or SHA-512.", nameof(hashAlgorithm));
            }

            AlgorithmName = hashAlgorithm;
        }

        /// <inheritdoc/>
        public string AlgorithmName { get; }

        /// <inheritdoc/>
        public int HashSize => AlgorithmName switch
        {
            "SHA-1" => 20,
            "SHA-256" => 32,
            "SHA-384" => 48,
            "SHA-512" => 64,
            _ => 32
        };

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> ComputeHashAsync(byte[] data)
        {
            ThrowIfDisposed();

            if (data == null)
            {
                return CryptoResult<byte[]>.Failure("Data cannot be null.");
            }

            try
            {
                byte[] hash = await _webCrypto.ComputeHashAsync(data, AlgorithmName);
                return CryptoResult<byte[]>.Success(hash);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Hash computation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> ComputeHmacAsync(byte[] data, byte[] key)
        {
            ThrowIfDisposed();

            if (data == null)
            {
                return CryptoResult<byte[]>.Failure("Data cannot be null.");
            }

            if (key == null || key.Length == 0)
            {
                return CryptoResult<byte[]>.Failure("Key cannot be null or empty.");
            }

            try
            {
                byte[] hmac = await _webCrypto.ComputeHmacAsync(data, key, AlgorithmName);
                return CryptoResult<byte[]>.Success(hmac);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"HMAC computation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<bool>> VerifyHmacAsync(byte[] data, byte[] expectedHmac, byte[] key)
        {
            ThrowIfDisposed();

            if (data == null)
            {
                return CryptoResult<bool>.Failure("Data cannot be null.");
            }

            if (expectedHmac == null)
            {
                return CryptoResult<bool>.Failure("Expected HMAC cannot be null.");
            }

            if (key == null || key.Length == 0)
            {
                return CryptoResult<bool>.Failure("Key cannot be null or empty.");
            }

            try
            {
                byte[] computedHmac = await _webCrypto.ComputeHmacAsync(data, key, AlgorithmName);

                // Constant-time comparison to prevent timing attacks
                bool isValid = ConstantTimeEquals(computedHmac, expectedHmac);
                return CryptoResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"HMAC verification failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Performs a constant-time comparison of two byte arrays to prevent timing attacks.
        /// </summary>
        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            uint result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= (uint)(a[i] ^ b[i]);
            }

            return result == 0;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BlazorHash));
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
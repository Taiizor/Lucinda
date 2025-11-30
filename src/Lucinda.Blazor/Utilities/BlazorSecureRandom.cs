// -----------------------------------------------------------------------
// <copyright file="BlazorSecureRandom.cs" company="Lucinda">
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
    /// Secure random number generation for Blazor WebAssembly using Web Crypto API.
    /// </summary>
    public class BlazorSecureRandom : IBlazorSecureRandom
    {
        private readonly WebCryptoInterop _webCrypto;
        private bool _disposed;

        /// <summary>
        /// Maximum number of bytes that can be generated in a single call.
        /// Web Crypto API has a limit of 65536 bytes per getRandomValues call.
        /// </summary>
        public const int MaxBytesPerCall = 65536;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorSecureRandom"/> class.
        /// </summary>
        /// <param name="webCrypto">The Web Crypto interop service.</param>
        public BlazorSecureRandom(WebCryptoInterop webCrypto)
        {
            _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> GenerateBytesAsync(int length)
        {
            ThrowIfDisposed();

            if (length <= 0)
            {
                return CryptoResult<byte[]>.Failure("Length must be greater than 0.");
            }

            if (length > MaxBytesPerCall)
            {
                return CryptoResult<byte[]>.Failure($"Length cannot exceed {MaxBytesPerCall} bytes per call.");
            }

            try
            {
                byte[] bytes = await _webCrypto.GetRandomBytesAsync(length);
                return CryptoResult<byte[]>.Success(bytes);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Random bytes generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> FillAsync(byte[] buffer)
        {
            ThrowIfDisposed();

            if (buffer == null)
            {
                return CryptoResult<byte[]>.Failure("Buffer cannot be null.");
            }

            if (buffer.Length == 0)
            {
                return CryptoResult<byte[]>.Success(buffer);
            }

            if (buffer.Length > MaxBytesPerCall)
            {
                return CryptoResult<byte[]>.Failure($"Buffer length cannot exceed {MaxBytesPerCall} bytes.");
            }

            try
            {
                byte[] bytes = await _webCrypto.GetRandomBytesAsync(buffer.Length);
                Array.Copy(bytes, buffer, buffer.Length);
                return CryptoResult<byte[]>.Success(buffer);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Buffer fill failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<int>> NextIntAsync(int minValue, int maxValue)
        {
            ThrowIfDisposed();

            if (minValue >= maxValue)
            {
                return CryptoResult<int>.Failure("minValue must be less than maxValue.");
            }

            try
            {
                long range = (long)maxValue - minValue;

                // Determine how many bytes we need
                int bytesNeeded = range <= 256 ? 1 :
                                  range <= 65536 ? 2 :
                                  range <= 16777216 ? 3 : 4;

                // Generate random bytes
                byte[] bytes = await _webCrypto.GetRandomBytesAsync(bytesNeeded);

                // Convert to integer
                uint randomValue = 0;
                for (int i = 0; i < bytesNeeded; i++)
                {
                    randomValue |= (uint)bytes[i] << (i * 8);
                }

                // Scale to range using rejection sampling to avoid bias
                uint maxUsableValue = (uint)(range * (uint.MaxValue / range));

                // If value is in the biased range, regenerate
                while (randomValue >= maxUsableValue)
                {
                    bytes = await _webCrypto.GetRandomBytesAsync(bytesNeeded);
                    randomValue = 0;
                    for (int i = 0; i < bytesNeeded; i++)
                    {
                        randomValue |= (uint)bytes[i] << (i * 8);
                    }
                }

                int result = (int)(minValue + (randomValue % range));
                return CryptoResult<int>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<int>.Failure($"Random integer generation failed: {ex.Message}");
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BlazorSecureRandom));
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
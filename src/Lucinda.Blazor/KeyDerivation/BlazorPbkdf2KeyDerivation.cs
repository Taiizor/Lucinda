// -----------------------------------------------------------------------
// <copyright file="BlazorPbkdf2KeyDerivation.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;
using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;
using System.Text;

namespace Lucinda.Blazor.KeyDerivation
{
    /// <summary>
    /// PBKDF2 key derivation implementation for Blazor WebAssembly using Web Crypto API.
    /// </summary>
    public class BlazorPbkdf2KeyDerivation : IBlazorPasswordKeyDerivation
    {
        private readonly WebCryptoInterop _webCrypto;
        private bool _disposed;

        /// <summary>
        /// Recommended minimum iterations for PBKDF2 with SHA-256.
        /// OWASP recommends at least 600,000 for SHA-256.
        /// </summary>
        public const int RecommendedIterations = 600000;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorPbkdf2KeyDerivation"/> class.
        /// </summary>
        /// <param name="webCrypto">The Web Crypto interop service.</param>
        /// <param name="hashAlgorithm">The hash algorithm (SHA-256, SHA-384, or SHA-512). Default is SHA-256.</param>
        /// <param name="defaultIterations">The default number of iterations. Default is 600000 (OWASP recommendation).</param>
        public BlazorPbkdf2KeyDerivation(WebCryptoInterop webCrypto, string hashAlgorithm = "SHA-256", int defaultIterations = RecommendedIterations)
        {
            _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));

            if (defaultIterations < 1000)
            {
                throw new ArgumentException("Iterations must be at least 1000.", nameof(defaultIterations));
            }

            HashAlgorithm = hashAlgorithm;
            DefaultIterations = defaultIterations;
        }

        /// <inheritdoc/>
        public string AlgorithmName => "PBKDF2";

        /// <summary>
        /// Gets the hash algorithm used for PBKDF2.
        /// </summary>
        public string HashAlgorithm { get; }

        /// <summary>
        /// Gets the default number of iterations.
        /// </summary>
        public int DefaultIterations { get; }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> DeriveKeyAsync(string password, byte[] salt, int outputLength)
        {
            return await DeriveKeyAsync(password, salt, DefaultIterations, outputLength);
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> DeriveKeyAsync(string password, byte[] salt, int iterations, int outputLength)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(password))
            {
                return CryptoResult<byte[]>.Failure("Password cannot be null or empty.");
            }

            if (salt == null || salt.Length < 8)
            {
                return CryptoResult<byte[]>.Failure("Salt must be at least 8 bytes.");
            }

            if (iterations < 1000)
            {
                return CryptoResult<byte[]>.Failure("Iterations must be at least 1000.");
            }

            if (outputLength <= 0)
            {
                return CryptoResult<byte[]>.Failure("Output length must be greater than 0.");
            }

            try
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] result = await _webCrypto.Pbkdf2DeriveKeyAsync(
                    passwordBytes,
                    salt,
                    iterations,
                    outputLength,
                    HashAlgorithm);

                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"PBKDF2 key derivation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> GenerateSaltAsync(int length = 16)
        {
            ThrowIfDisposed();

            if (length < 8)
            {
                return CryptoResult<byte[]>.Failure("Salt length must be at least 8 bytes.");
            }

            try
            {
                byte[] salt = await _webCrypto.GetRandomBytesAsync(length);
                return CryptoResult<byte[]>.Success(salt);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Salt generation failed: {ex.Message}");
            }
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BlazorPbkdf2KeyDerivation));
            }
#endif
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            _disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}
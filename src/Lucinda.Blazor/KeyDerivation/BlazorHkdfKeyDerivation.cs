// -----------------------------------------------------------------------
// <copyright file="BlazorHkdfKeyDerivation.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;
using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.KeyDerivation
{
    /// <summary>
    /// HKDF key derivation implementation for Blazor WebAssembly using Web Crypto API.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="BlazorHkdfKeyDerivation"/> class.
    /// </remarks>
    /// <param name="webCrypto">The Web Crypto interop service.</param>
    /// <param name="hashAlgorithm">The hash algorithm (SHA-256, SHA-384, or SHA-512). Default is SHA-256.</param>
    public class BlazorHkdfKeyDerivation(WebCryptoInterop webCrypto, string hashAlgorithm = "SHA-256") : IBlazorKeyDerivation
    {
        private readonly WebCryptoInterop _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));
        private bool _disposed;

        /// <inheritdoc/>
        public string AlgorithmName => "HKDF";

        /// <summary>
        /// Gets the hash algorithm used for HKDF.
        /// </summary>
        public string HashAlgorithm { get; } = hashAlgorithm;

        /// <summary>
        /// Gets the maximum output length in bytes based on the hash algorithm.
        /// HKDF can produce up to 255 * HashLen bytes.
        /// </summary>
        public int MaxOutputLength => HashAlgorithm switch
        {
            "SHA-256" => 255 * 32,
            "SHA-384" => 255 * 48,
            "SHA-512" => 255 * 64,
            _ => 255 * 32
        };

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> DeriveKeyAsync(byte[] inputKeyMaterial, int outputLength)
        {
            return await DeriveKeyAsync(inputKeyMaterial, [], [], outputLength);
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> DeriveKeyAsync(byte[] inputKeyMaterial, byte[] salt, int outputLength)
        {
            return await DeriveKeyAsync(inputKeyMaterial, salt, [], outputLength);
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> DeriveKeyAsync(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength)
        {
            ThrowIfDisposed();

            if (inputKeyMaterial == null || inputKeyMaterial.Length == 0)
            {
                return CryptoResult<byte[]>.Failure("Input key material cannot be null or empty.");
            }

            if (outputLength <= 0)
            {
                return CryptoResult<byte[]>.Failure("Output length must be greater than 0.");
            }

            if (outputLength > MaxOutputLength)
            {
                return CryptoResult<byte[]>.Failure($"Output length cannot exceed {MaxOutputLength} bytes for {HashAlgorithm}.");
            }

            try
            {
                byte[] result = await _webCrypto.HkdfDeriveKeyAsync(
                    inputKeyMaterial,
                    salt ?? [],
                    info ?? [],
                    outputLength,
                    HashAlgorithm);

                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"HKDF key derivation failed: {ex.Message}");
            }
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BlazorHkdfKeyDerivation));
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
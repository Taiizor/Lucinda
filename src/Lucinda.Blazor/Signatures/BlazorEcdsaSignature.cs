// -----------------------------------------------------------------------
// <copyright file="BlazorEcdsaSignature.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;
using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.Signatures
{
    /// <summary>
    /// ECDSA signature implementation for Blazor WebAssembly using Web Crypto API.
    /// </summary>
    public class BlazorEcdsaSignature : IBlazorSignature
    {
        private readonly WebCryptoInterop _webCrypto;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorEcdsaSignature"/> class.
        /// </summary>
        /// <param name="webCrypto">The Web Crypto interop service.</param>
        /// <param name="curveName">The elliptic curve name (P-256, P-384, or P-521). Default is P-256.</param>
        /// <param name="hashAlgorithm">The hash algorithm (SHA-256, SHA-384, or SHA-512). Default is SHA-256.</param>
        public BlazorEcdsaSignature(WebCryptoInterop webCrypto, string curveName = "P-256", string hashAlgorithm = "SHA-256")
        {
            _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));

            if (curveName is not "P-256" and not "P-384" and not "P-521")
            {
                throw new ArgumentException("Curve must be P-256, P-384, or P-521.", nameof(curveName));
            }

            CurveName = curveName;
            HashAlgorithm = hashAlgorithm;
        }

        /// <inheritdoc/>
        public string AlgorithmName => $"ECDSA-{CurveName}";

        /// <summary>
        /// Gets the curve name.
        /// </summary>
        public string CurveName { get; }

        /// <summary>
        /// Gets the hash algorithm.
        /// </summary>
        public string HashAlgorithm { get; }

        /// <summary>
        /// Gets the signature size in bytes based on the curve.
        /// </summary>
        public int SignatureSize => CurveName switch
        {
            "P-256" => 64,
            "P-384" => 96,
            "P-521" => 132,
            _ => 64
        };

        /// <inheritdoc/>
        public async Task<CryptoResult<AsymmetricKeyPair>> GenerateKeyPairAsync()
        {
            ThrowIfDisposed();

            try
            {
                (byte[] PublicKey, byte[] PrivateKey) result = await _webCrypto.GenerateEcdsaKeyPairAsync(CurveName);
                AsymmetricKeyPair keyPair = new(result.PublicKey, result.PrivateKey);
                return CryptoResult<AsymmetricKeyPair>.Success(keyPair);
            }
            catch (Exception ex)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure($"ECDSA key pair generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> SignAsync(byte[] data, byte[] privateKey)
        {
            ThrowIfDisposed();

            if (data == null)
            {
                return CryptoResult<byte[]>.Failure("Data cannot be null.");
            }

            if (privateKey == null)
            {
                return CryptoResult<byte[]>.Failure("Private key cannot be null.");
            }

            try
            {
                byte[] signature = await _webCrypto.EcdsaSignAsync(privateKey, data, CurveName, HashAlgorithm);
                return CryptoResult<byte[]>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"ECDSA signing failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<bool>> VerifyAsync(byte[] data, byte[] signature, byte[] publicKey)
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

            if (publicKey == null)
            {
                return CryptoResult<bool>.Failure("Public key cannot be null.");
            }

            try
            {
                bool isValid = await _webCrypto.EcdsaVerifyAsync(publicKey, data, signature, CurveName, HashAlgorithm);
                return CryptoResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"ECDSA verification failed: {ex.Message}");
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BlazorEcdsaSignature));
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
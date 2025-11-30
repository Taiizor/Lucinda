// -----------------------------------------------------------------------
// <copyright file="BlazorEcdhKeyExchange.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;
using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.KeyExchange
{
    /// <summary>
    /// ECDH key exchange implementation for Blazor WebAssembly using Web Crypto API.
    /// </summary>
    public class BlazorEcdhKeyExchange : IBlazorKeyExchange
    {
        private readonly WebCryptoInterop _webCrypto;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorEcdhKeyExchange"/> class.
        /// </summary>
        /// <param name="webCrypto">The Web Crypto interop service.</param>
        /// <param name="curveName">The elliptic curve name (P-256, P-384, or P-521). Default is P-256.</param>
        public BlazorEcdhKeyExchange(WebCryptoInterop webCrypto, string curveName = "P-256")
        {
            _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));

            if (curveName is not "P-256" and not "P-384" and not "P-521")
            {
                throw new ArgumentException("Curve must be P-256, P-384, or P-521.", nameof(curveName));
            }

            CurveName = curveName;
        }

        /// <inheritdoc/>
        public string AlgorithmName => "ECDH";

        /// <inheritdoc/>
        public string CurveName { get; }

        /// <summary>
        /// Gets the derived secret size in bytes based on the curve.
        /// </summary>
        public int DerivedSecretSize => CurveName switch
        {
            "P-256" => 32,
            "P-384" => 48,
            "P-521" => 66,
            _ => 32
        };

        /// <inheritdoc/>
        public async Task<CryptoResult<AsymmetricKeyPair>> GenerateKeyPairAsync()
        {
            ThrowIfDisposed();

            try
            {
                (byte[] PublicKey, byte[] PrivateKey) = await _webCrypto.GenerateEcdhKeyPairAsync(CurveName);
                AsymmetricKeyPair keyPair = new(PublicKey, PrivateKey);
                return CryptoResult<AsymmetricKeyPair>.Success(keyPair);
            }
            catch (Exception ex)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure($"ECDH key pair generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> DeriveSharedSecretAsync(byte[] privateKey, byte[] publicKey)
        {
            return await DeriveSharedSecretAsync(privateKey, publicKey, DerivedSecretSize);
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> DeriveSharedSecretAsync(byte[] privateKey, byte[] publicKey, int outputLengthBytes)
        {
            ThrowIfDisposed();

            if (privateKey == null)
            {
                return CryptoResult<byte[]>.Failure("Private key cannot be null.");
            }

            if (publicKey == null)
            {
                return CryptoResult<byte[]>.Failure("Public key cannot be null.");
            }

            if (outputLengthBytes <= 0 || outputLengthBytes > DerivedSecretSize)
            {
                return CryptoResult<byte[]>.Failure($"Output length must be between 1 and {DerivedSecretSize} bytes for {CurveName}.");
            }

            try
            {
                byte[] result = await _webCrypto.EcdhDeriveBitsAsync(privateKey, publicKey, CurveName, outputLengthBytes * 8);
                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"ECDH key derivation failed: {ex.Message}");
            }
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BlazorEcdhKeyExchange));
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
// -----------------------------------------------------------------------
// <copyright file="BlazorRsaPssSignature.cs" company="Lucinda">
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
    /// RSA-PSS signature implementation for Blazor WebAssembly using Web Crypto API.
    /// </summary>
    public class BlazorRsaPssSignature : IBlazorSignature
    {
        private readonly WebCryptoInterop _webCrypto;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorRsaPssSignature"/> class.
        /// </summary>
        /// <param name="webCrypto">The Web Crypto interop service.</param>
        /// <param name="keySize">The key size in bits. Default is 2048.</param>
        /// <param name="hashAlgorithm">The hash algorithm (SHA-256, SHA-384, or SHA-512). Default is SHA-256.</param>
        /// <param name="saltLength">The salt length in bytes. Default is 32 (same as hash output for SHA-256).</param>
        public BlazorRsaPssSignature(WebCryptoInterop webCrypto, int keySize = 2048, string hashAlgorithm = "SHA-256", int saltLength = 32)
        {
            _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));

            if (keySize is < 1024 or > 4096)
            {
                throw new ArgumentException("Key size must be between 1024 and 4096 bits.", nameof(keySize));
            }

            KeySize = keySize;
            HashAlgorithm = hashAlgorithm;
            SaltLength = saltLength;
        }

        /// <inheritdoc/>
        public string AlgorithmName => "RSA-PSS";

        /// <summary>
        /// Gets the key size in bits.
        /// </summary>
        public int KeySize { get; }

        /// <summary>
        /// Gets the hash algorithm.
        /// </summary>
        public string HashAlgorithm { get; }

        /// <summary>
        /// Gets the salt length in bytes.
        /// </summary>
        public int SaltLength { get; }

        /// <inheritdoc/>
        public async Task<CryptoResult<AsymmetricKeyPair>> GenerateKeyPairAsync()
        {
            ThrowIfDisposed();

            try
            {
                (byte[] PublicKey, byte[] PrivateKey) result = await _webCrypto.GenerateRsaSignatureKeyPairAsync(KeySize, HashAlgorithm);
                AsymmetricKeyPair keyPair = new(result.PublicKey, result.PrivateKey);
                return CryptoResult<AsymmetricKeyPair>.Success(keyPair);
            }
            catch (Exception ex)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure($"RSA-PSS key pair generation failed: {ex.Message}");
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
                byte[] signature = await _webCrypto.RsaPssSignAsync(data, privateKey, HashAlgorithm, SaltLength);
                return CryptoResult<byte[]>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"RSA-PSS signing failed: {ex.Message}");
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
                bool isValid = await _webCrypto.RsaPssVerifyAsync(data, signature, publicKey, HashAlgorithm, SaltLength);
                return CryptoResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"RSA-PSS verification failed: {ex.Message}");
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BlazorRsaPssSignature));
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
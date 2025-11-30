// -----------------------------------------------------------------------
// <copyright file="BlazorRsaEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;
using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.Asymmetric
{
    /// <summary>
    /// RSA-OAEP encryption implementation for Blazor WebAssembly using Web Crypto API.
    /// </summary>
    public class BlazorRsaEncryption : IBlazorAsymmetricEncryption
    {
        private readonly WebCryptoInterop _webCrypto;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorRsaEncryption"/> class.
        /// </summary>
        /// <param name="webCrypto">The Web Crypto interop service.</param>
        /// <param name="keySize">The key size in bits. Default is 2048.</param>
        /// <param name="hashAlgorithm">The hash algorithm for OAEP (SHA-256, SHA-384, or SHA-512). Default is SHA-256.</param>
        public BlazorRsaEncryption(WebCryptoInterop webCrypto, int keySize = 2048, string hashAlgorithm = "SHA-256")
        {
            _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));

            if (keySize is < 1024 or > 4096)
            {
                throw new ArgumentException("Key size must be between 1024 and 4096 bits.", nameof(keySize));
            }

            KeySize = keySize;
            HashAlgorithm = hashAlgorithm;
        }

        /// <inheritdoc/>
        public string AlgorithmName => "RSA-OAEP";

        /// <summary>
        /// Gets the key size in bits.
        /// </summary>
        public int KeySize { get; }

        /// <summary>
        /// Gets the hash algorithm used for OAEP.
        /// </summary>
        public string HashAlgorithm { get; }

        /// <inheritdoc/>
        public async Task<CryptoResult<AsymmetricKeyPair>> GenerateKeyPairAsync()
        {
            ThrowIfDisposed();

            try
            {
                (byte[] PublicKey, byte[] PrivateKey) = await _webCrypto.GenerateRsaKeyPairAsync(KeySize, HashAlgorithm);
                AsymmetricKeyPair keyPair = new(PublicKey, PrivateKey);
                return CryptoResult<AsymmetricKeyPair>.Success(keyPair);
            }
            catch (Exception ex)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure($"RSA key pair generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> EncryptAsync(byte[] plaintext, byte[] publicKey)
        {
            ThrowIfDisposed();

            if (plaintext == null)
            {
                return CryptoResult<byte[]>.Failure("Plaintext cannot be null.");
            }

            if (publicKey == null)
            {
                return CryptoResult<byte[]>.Failure("Public key cannot be null.");
            }

            // RSA-OAEP max plaintext size = keySize/8 - 2*hashSize - 2
            // For SHA-256 (32 bytes) and 2048-bit key: 256 - 66 = 190 bytes
            int hashSize = GetHashSize(HashAlgorithm);
            int maxPlaintextSize = (KeySize / 8) - (2 * hashSize) - 2;

            if (plaintext.Length > maxPlaintextSize)
            {
                return CryptoResult<byte[]>.Failure($"Plaintext is too large for RSA-OAEP encryption. Maximum size is {maxPlaintextSize} bytes.");
            }

            try
            {
                byte[] result = await _webCrypto.RsaEncryptAsync(publicKey, plaintext, HashAlgorithm);
                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"RSA-OAEP encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<CryptoResult<byte[]>> DecryptAsync(byte[] ciphertext, byte[] privateKey)
        {
            ThrowIfDisposed();

            if (ciphertext == null)
            {
                return CryptoResult<byte[]>.Failure("Ciphertext cannot be null.");
            }

            if (privateKey == null)
            {
                return CryptoResult<byte[]>.Failure("Private key cannot be null.");
            }

            try
            {
                byte[] result = await _webCrypto.RsaDecryptAsync(privateKey, ciphertext, HashAlgorithm);
                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"RSA-OAEP decryption failed: {ex.Message}");
            }
        }

        private static int GetHashSize(string hashAlgorithm)
        {
            return hashAlgorithm switch
            {
                "SHA-1" => 20,
                "SHA-256" => 32,
                "SHA-384" => 48,
                "SHA-512" => 64,
                _ => 32 // default to SHA-256 size
            };
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BlazorRsaEncryption));
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
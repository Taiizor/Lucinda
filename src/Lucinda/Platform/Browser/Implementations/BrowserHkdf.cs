// <copyright file="BrowserHkdf.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET7_0_OR_GREATER

using Lucinda.Abstractions;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Lucinda.Platform.Browser.Implementations
{
    /// <summary>
    /// Browser-based HKDF key derivation implementation using the Web Crypto API.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="BrowserHkdf"/> class.
    /// </remarks>
    /// <param name="hashAlgorithm">The hash algorithm (SHA-256, SHA-384, SHA-512).</param>
    [SupportedOSPlatform("browser")]
    internal sealed class BrowserHkdf(string hashAlgorithm = "SHA256") : IKeyDerivation
    {
        private readonly string _hashAlgorithm = BrowserCryptoInterop.NormalizeHashAlgorithm(hashAlgorithm);
        private bool _disposed;

        /// <inheritdoc/>
        public string AlgorithmName => $"HKDF-{_hashAlgorithm}";

        /// <inheritdoc/>
        public CryptoResult<byte[]> DeriveKey(string password, byte[] salt, int iterations, int derivedKeyLength)
        {
            // HKDF is not designed for password-based key derivation
            // Use PBKDF2 for passwords instead
            return CryptoResult<byte[]>.Failure("HKDF is not suitable for password-based key derivation. Use PBKDF2 instead.");
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> DeriveKey(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int derivedKeyLength)
        {
            try
            {
                ThrowIfDisposed();

                if (inputKeyMaterial == null || inputKeyMaterial.Length == 0)
                {
                    return CryptoResult<byte[]>.Failure("Input key material cannot be null or empty.");
                }

                if (derivedKeyLength <= 0)
                {
                    return CryptoResult<byte[]>.Failure("Derived key length must be greater than zero.");
                }

                // Maximum output length for HKDF is 255 * HashLen
                int maxLength = 255 * GetHashLength();
                if (derivedKeyLength > maxLength)
                {
                    return CryptoResult<byte[]>.Failure($"Derived key length cannot exceed {maxLength} bytes for {_hashAlgorithm}.");
                }

                BrowserCryptoInterop.EnsureInitialized();
                byte[] derivedKey = BrowserCryptoInterop.HkdfDerive(inputKeyMaterial, salt, info, derivedKeyLength, _hashAlgorithm);

                return CryptoResult<byte[]>.Success(derivedKey);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Key derivation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> GenerateSalt(int saltLength)
        {
            try
            {
                ThrowIfDisposed();

                if (saltLength <= 0)
                {
                    return CryptoResult<byte[]>.Failure("Salt length must be greater than zero.");
                }

                byte[] salt = new byte[saltLength];
                RandomNumberGenerator.Fill(salt);

                return CryptoResult<byte[]>.Success(salt);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Salt generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BrowserHkdf));
            }
#endif
        }

        private int GetHashLength()
        {
            return _hashAlgorithm switch
            {
                "SHA-256" => 32,
                "SHA-384" => 48,
                "SHA-512" => 64,
                _ => 32
            };
        }
    }
}

#endif
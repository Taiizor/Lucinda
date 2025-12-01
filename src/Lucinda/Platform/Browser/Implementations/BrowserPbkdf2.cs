// <copyright file="BrowserPbkdf2.cs" company="Lucinda">
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
    /// Browser-based PBKDF2 key derivation implementation using the Web Crypto API.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="BrowserPbkdf2"/> class.
    /// </remarks>
    /// <param name="hashAlgorithm">The hash algorithm (SHA-256, SHA-384, SHA-512).</param>
    [SupportedOSPlatform("browser")]
    internal sealed class BrowserPbkdf2(string hashAlgorithm = "SHA256") : IKeyDerivation
    {
        private readonly string _hashAlgorithm = BrowserCryptoInterop.NormalizeHashAlgorithm(hashAlgorithm);
        private bool _disposed;

        /// <inheritdoc/>
        public string AlgorithmName => $"PBKDF2-{_hashAlgorithm}";

        /// <inheritdoc/>
        public CryptoResult<byte[]> DeriveKey(string password, byte[] salt, int iterations, int derivedKeyLength)
        {
            try
            {
                ThrowIfDisposed();

                if (string.IsNullOrEmpty(password))
                {
                    return CryptoResult<byte[]>.Failure("Password cannot be null or empty.");
                }

                if (salt == null || salt.Length == 0)
                {
                    return CryptoResult<byte[]>.Failure("Salt cannot be null or empty.");
                }

                if (iterations < 1)
                {
                    return CryptoResult<byte[]>.Failure("Iterations must be at least 1.");
                }

                if (derivedKeyLength <= 0)
                {
                    return CryptoResult<byte[]>.Failure("Derived key length must be greater than zero.");
                }

                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

                BrowserCryptoInterop.EnsureInitialized();
                byte[] derivedKey = BrowserCryptoInterop.Pbkdf2Derive(passwordBytes, salt, iterations, derivedKeyLength, _hashAlgorithm);

                // Clear password bytes
                CryptographicOperations.ZeroMemory(passwordBytes);

                return CryptoResult<byte[]>.Success(derivedKey);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Key derivation failed: {ex.Message}");
            }
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

                // PBKDF2 doesn't use 'info' parameter, only salt
                // Use a default iteration count for IKM-based derivation
                const int defaultIterations = 100000;

                byte[] effectiveSalt = salt ?? new byte[16];
                if (salt == null)
                {
                    RandomNumberGenerator.Fill(effectiveSalt);
                }

                BrowserCryptoInterop.EnsureInitialized();
                byte[] derivedKey = BrowserCryptoInterop.Pbkdf2Derive(inputKeyMaterial, effectiveSalt, defaultIterations, derivedKeyLength, _hashAlgorithm);

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

                // Minimum recommended salt length is 16 bytes
                if (saltLength < 16)
                {
                    return CryptoResult<byte[]>.Failure("Salt length should be at least 16 bytes for security.");
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
                throw new ObjectDisposedException(nameof(BrowserPbkdf2));
            }
#endif
        }
    }
}

#endif
// <copyright file="Pbkdf2KeyDerivation.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
using System.Security.Cryptography;
using System.Text;
#else
using System.Security.Cryptography;
using System.Text;
#endif

using Lucinda.Abstractions;
using Lucinda.Platform;
using Lucinda.Utilities;

namespace Lucinda.KeyDerivation
{
    /// <summary>
    /// Provides PBKDF2 (Password-Based Key Derivation Function 2) key derivation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// PBKDF2 is designed for deriving cryptographic keys from passwords.
    /// It applies a pseudorandom function (typically HMAC) many times to increase
    /// the computational cost of brute-force attacks.
    /// </para>
    /// <para>
    /// Recommended parameters:
    /// <list type="bullet">
    /// <item><description>Salt: At least 16 bytes (128 bits)</description></item>
    /// <item><description>Iterations: At least 100,000 for interactive use, 600,000+ for non-interactive</description></item>
    /// <item><description>Hash: SHA-256 or SHA-512</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// For Blazor WebAssembly, use <see cref="ICryptoProvider"/> to get a browser-compatible implementation.
    /// </para>
    /// </remarks>
    public sealed class Pbkdf2KeyDerivation : IKeyDerivation
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Pbkdf2KeyDerivation"/> class.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm to use. Default is SHA-256.</param>
        /// <exception cref="PlatformNotSupportedException">Thrown when running in Blazor WebAssembly. Use <see cref="ICryptoProvider"/> instead.</exception>
        public Pbkdf2KeyDerivation(HashAlgorithmName? hashAlgorithm = null)
        {
            CryptoPlatform.ThrowIfBrowser("Pbkdf2KeyDerivation");
            _hashAlgorithm = hashAlgorithm ?? HashAlgorithmName.SHA256;
        }

        /// <summary>
        /// The minimum recommended number of iterations.
        /// </summary>
        public const int MinimumRecommendedIterations = 100000;

        /// <summary>
        /// The default number of iterations.
        /// </summary>
        public const int DefaultIterations = 600000;

        /// <summary>
        /// The default salt length in bytes.
        /// </summary>
        public const int DefaultSaltLength = 32;

        private readonly HashAlgorithmName _hashAlgorithm;
        private bool _disposed;

        /// <inheritdoc/>
        public string AlgorithmName => $"PBKDF2-{_hashAlgorithm.Name}";

        /// <inheritdoc/>
        public CryptoResult<byte[]> DeriveKey(string password, byte[] salt, int iterations, int derivedKeyLength)
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

            if (derivedKeyLength < 1)
            {
                return CryptoResult<byte[]>.Failure("Derived key length must be at least 1 byte.");
            }

            try
            {
#if NET6_0_OR_GREATER
                byte[] derivedKey = Rfc2898DeriveBytes.Pbkdf2(
                    password,
                    salt,
                    iterations,
                    _hashAlgorithm,
                    derivedKeyLength);
#elif NETCOREAPP || NETSTANDARD2_1
                byte[] derivedKey;
                using (Rfc2898DeriveBytes pbkdf2 = new(
                    Encoding.UTF8.GetBytes(password),
                    salt,
                    iterations,
                    _hashAlgorithm))
                {
                    derivedKey = pbkdf2.GetBytes(derivedKeyLength);
                }
#else
                byte[] derivedKey;
                // .NET Standard 2.0 doesn't support HashAlgorithmName in Rfc2898DeriveBytes
                // Use SHA1 by default (the only option available)
                using (Rfc2898DeriveBytes pbkdf2 = new(password, salt, iterations))
                {
                    derivedKey = pbkdf2.GetBytes(derivedKeyLength);
                }
#endif
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
            ThrowIfDisposed();

            // For PBKDF2, we use the input key material as the "password"
            // The info parameter is not directly supported by PBKDF2,
            // so we concatenate it with the salt for domain separation
            if (inputKeyMaterial == null || inputKeyMaterial.Length == 0)
            {
                return CryptoResult<byte[]>.Failure("Input key material cannot be null or empty.");
            }

            if (derivedKeyLength < 1)
            {
                return CryptoResult<byte[]>.Failure("Derived key length must be at least 1 byte.");
            }

            try
            {
                // Use salt or generate one, and incorporate info if provided
                byte[] effectiveSalt = salt ?? SecureRandom.GenerateSalt(DefaultSaltLength);
                if (info != null && info.Length > 0)
                {
                    effectiveSalt = CryptoHelpers.Concatenate(effectiveSalt, info);
                }

#if NET6_0_OR_GREATER
                byte[] derivedKey = Rfc2898DeriveBytes.Pbkdf2(
                    inputKeyMaterial,
                    effectiveSalt,
                    DefaultIterations,
                    _hashAlgorithm,
                    derivedKeyLength);
#elif NETCOREAPP || NETSTANDARD2_1
                byte[] derivedKey;
                using (Rfc2898DeriveBytes pbkdf2 = new(
                    inputKeyMaterial,
                    effectiveSalt,
                    DefaultIterations,
                    _hashAlgorithm))
                {
                    derivedKey = pbkdf2.GetBytes(derivedKeyLength);
                }
#else
                byte[] derivedKey;
                // .NET Standard 2.0 doesn't support HashAlgorithmName in Rfc2898DeriveBytes
                using (Rfc2898DeriveBytes pbkdf2 = new(inputKeyMaterial, effectiveSalt, DefaultIterations))
                {
                    derivedKey = pbkdf2.GetBytes(derivedKeyLength);
                }
#endif
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
            ThrowIfDisposed();

            if (saltLength < 1)
            {
                return CryptoResult<byte[]>.Failure("Salt length must be at least 1 byte.");
            }

            try
            {
                byte[] salt = SecureRandom.GenerateSalt(saltLength);
                return CryptoResult<byte[]>.Success(salt);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Salt generation failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Derives a key from a password with the recommended default parameters.
        /// </summary>
        /// <param name="password">The password to derive the key from.</param>
        /// <param name="salt">The salt to use. If null, a new salt will be generated.</param>
        /// <param name="derivedKeyLength">The desired length of the derived key in bytes.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing a tuple of (derived key, salt) on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<(byte[] Key, byte[] Salt)> DeriveKeyWithDefaults(
            string password,
            byte[]? salt = null,
            int derivedKeyLength = 32)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(password))
            {
                return CryptoResult<(byte[], byte[])>.Failure("Password cannot be null or empty.");
            }

            try
            {
                byte[] effectiveSalt = salt ?? SecureRandom.GenerateSalt(DefaultSaltLength);
                CryptoResult<byte[]> result = DeriveKey(password, effectiveSalt, DefaultIterations, derivedKeyLength);

                if (result.IsFailure)
                {
                    return CryptoResult<(byte[], byte[])>.Failure(result.Error);
                }

                return CryptoResult<(byte[], byte[])>.Success((result.Value, effectiveSalt));
            }
            catch (Exception ex)
            {
                return CryptoResult<(byte[], byte[])>.Failure($"Key derivation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(Pbkdf2KeyDerivation));
            }
#endif
        }
    }
}
// <copyright file="HkdfKeyDerivation.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
using System.Security.Cryptography;
#else
using System.Security.Cryptography;
#endif

using Lucinda.Abstractions;
using Lucinda.Utilities;

namespace Lucinda.KeyDerivation
{
    /// <summary>
    /// Provides HKDF (HMAC-based Key Derivation Function) key derivation as specified in RFC 5869.
    /// </summary>
    /// <remarks>
    /// <para>
    /// HKDF is designed for deriving cryptographic keys from high-entropy input key material.
    /// It is NOT suitable for password-based key derivation - use <see cref="Pbkdf2KeyDerivation"/> instead.
    /// </para>
    /// <para>
    /// HKDF consists of two stages:
    /// <list type="bullet">
    /// <item><description>Extract: Takes input key material and optional salt, produces a pseudorandom key (PRK)</description></item>
    /// <item><description>Expand: Takes PRK and optional info, produces output key material</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public sealed class HkdfKeyDerivation : IKeyDerivation
    {
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly int _hashLength;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="HkdfKeyDerivation"/> class.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm to use. Default is SHA-256.</param>
        public HkdfKeyDerivation(HashAlgorithmName? hashAlgorithm = null)
        {
            _hashAlgorithm = hashAlgorithm ?? HashAlgorithmName.SHA256;
            _hashLength = GetHashLength(_hashAlgorithm);
        }

        /// <inheritdoc/>
        public string AlgorithmName => $"HKDF-{_hashAlgorithm.Name}";

        /// <inheritdoc/>
        public CryptoResult<byte[]> DeriveKey(string password, byte[] salt, int iterations, int derivedKeyLength)
        {
            ThrowIfDisposed();

            // HKDF is not designed for password-based key derivation
            // Convert the password to bytes and use it as input key material
            if (string.IsNullOrEmpty(password))
            {
                return CryptoResult<byte[]>.Failure("Password cannot be null or empty.");
            }

            byte[] inputKeyMaterial = CryptoHelpers.GetUtf8Bytes(password);
            return DeriveKey(inputKeyMaterial, salt, null, derivedKeyLength);
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> DeriveKey(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int derivedKeyLength)
        {
            ThrowIfDisposed();

            if (inputKeyMaterial == null || inputKeyMaterial.Length == 0)
            {
                return CryptoResult<byte[]>.Failure("Input key material cannot be null or empty.");
            }

            if (derivedKeyLength < 1)
            {
                return CryptoResult<byte[]>.Failure("Derived key length must be at least 1 byte.");
            }

            // Maximum output length is 255 * hash length (RFC 5869)
            int maxLength = 255 * _hashLength;
            if (derivedKeyLength > maxLength)
            {
                return CryptoResult<byte[]>.Failure(
                    $"Derived key length cannot exceed {maxLength} bytes for {_hashAlgorithm.Name}.");
            }

            try
            {
#if NET5_0_OR_GREATER
                byte[] derivedKey = HKDF.DeriveKey(
                    _hashAlgorithm,
                    inputKeyMaterial,
                    derivedKeyLength,
                    salt ?? Array.Empty<byte>(),
                    info ?? Array.Empty<byte>());
                return CryptoResult<byte[]>.Success(derivedKey);
#else
                // Manual HKDF implementation for older frameworks
                var derivedKey = HkdfImplementation(inputKeyMaterial, salt, info, derivedKeyLength);
                return CryptoResult<byte[]>.Success(derivedKey);
#endif
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
        /// Performs the HKDF-Extract operation.
        /// </summary>
        /// <param name="salt">The salt value (can be null).</param>
        /// <param name="inputKeyMaterial">The input key material.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the pseudorandom key (PRK) on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<byte[]> Extract(byte[]? salt, byte[] inputKeyMaterial)
        {
            ThrowIfDisposed();

            if (inputKeyMaterial == null || inputKeyMaterial.Length == 0)
            {
                return CryptoResult<byte[]>.Failure("Input key material cannot be null or empty.");
            }

            try
            {
#if NET5_0_OR_GREATER
                byte[] prk = HKDF.Extract(_hashAlgorithm, inputKeyMaterial, salt);
                return CryptoResult<byte[]>.Success(prk);
#else
                var prk = HkdfExtract(salt, inputKeyMaterial);
                return CryptoResult<byte[]>.Success(prk);
#endif
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"HKDF-Extract failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Performs the HKDF-Expand operation.
        /// </summary>
        /// <param name="prk">The pseudorandom key from the Extract phase.</param>
        /// <param name="info">Optional context information.</param>
        /// <param name="outputLength">The desired length of the output key material.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the output key material on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<byte[]> Expand(byte[] prk, byte[]? info, int outputLength)
        {
            ThrowIfDisposed();

            if (prk == null || prk.Length < _hashLength)
            {
                return CryptoResult<byte[]>.Failure(
                    $"PRK must be at least {_hashLength} bytes for {_hashAlgorithm.Name}.");
            }

            if (outputLength < 1)
            {
                return CryptoResult<byte[]>.Failure("Output length must be at least 1 byte.");
            }

            int maxLength = 255 * _hashLength;
            if (outputLength > maxLength)
            {
                return CryptoResult<byte[]>.Failure(
                    $"Output length cannot exceed {maxLength} bytes for {_hashAlgorithm.Name}.");
            }

            try
            {
#if NET5_0_OR_GREATER
                byte[] okm = HKDF.Expand(_hashAlgorithm, prk, outputLength, info ?? Array.Empty<byte>());
                return CryptoResult<byte[]>.Success(okm);
#else
                var okm = HkdfExpand(prk, info, outputLength);
                return CryptoResult<byte[]>.Success(okm);
#endif
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"HKDF-Expand failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _disposed = true;
        }

#if !NET5_0_OR_GREATER
        private byte[] HkdfImplementation(byte[] ikm, byte[]? salt, byte[]? info, int outputLength)
        {
            var prk = HkdfExtract(salt, ikm);
            return HkdfExpand(prk, info, outputLength);
        }

        private byte[] HkdfExtract(byte[]? salt, byte[] ikm)
        {
            // If salt is not provided, use a string of HashLen zeros
            var effectiveSalt = salt ?? new byte[_hashLength];
            return ComputeHmac(effectiveSalt, ikm);
        }

        private byte[] HkdfExpand(byte[] prk, byte[]? info, int outputLength)
        {
            var effectiveInfo = info ?? Array.Empty<byte>();
            var n = (int)Math.Ceiling((double)outputLength / _hashLength);
            var okm = new byte[outputLength];
            var t = Array.Empty<byte>();
            var offset = 0;

            for (var i = 1; i <= n; i++)
            {
                // T(i) = HMAC(PRK, T(i-1) | info | i)
                var counterByte = new byte[] { (byte)i };
                var inputData = CryptoHelpers.Concatenate(t, effectiveInfo, counterByte);
                t = ComputeHmac(prk, inputData);

                var bytesToCopy = Math.Min(_hashLength, outputLength - offset);
                Array.Copy(t, 0, okm, offset, bytesToCopy);
                offset += bytesToCopy;
            }

            return okm;
        }

        private byte[] ComputeHmac(byte[] key, byte[] data)
        {
            if (_hashAlgorithm == HashAlgorithmName.SHA256)
            {
                return CryptoHelpers.ComputeHmacSha256(key, data);
            }
            else if (_hashAlgorithm == HashAlgorithmName.SHA512)
            {
                return CryptoHelpers.ComputeHmacSha512(key, data);
            }
            else if (_hashAlgorithm == HashAlgorithmName.SHA384)
            {
                using (var hmac = new HMACSHA384(key))
                {
                    return hmac.ComputeHash(data);
                }
            }
            else
            {
                throw new NotSupportedException($"Hash algorithm {_hashAlgorithm.Name} is not supported.");
            }
        }
#endif

        private static int GetHashLength(HashAlgorithmName hashAlgorithm)
        {
            if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                return 32;
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                return 48;
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                return 64;
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA1)
            {
                return 20;
            }
            else
            {
                throw new NotSupportedException($"Hash algorithm {hashAlgorithm.Name} is not supported.");
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(HkdfKeyDerivation));
            }
        }
    }
}
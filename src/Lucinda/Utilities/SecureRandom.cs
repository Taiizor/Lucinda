// <copyright file="SecureRandom.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
using System.Security.Cryptography;
#else
using System.Security.Cryptography;
#endif

namespace Lucinda.Utilities
{
    /// <summary>
    /// Provides cryptographically secure random number generation.
    /// </summary>
    /// <remarks>
    /// This class wraps the platform's cryptographic random number generator
    /// and provides convenient methods for generating random bytes and numbers.
    /// </remarks>
    public static class SecureRandom
    {
#if NETFRAMEWORK || NETSTANDARD2_0
        private static readonly RNGCryptoServiceProvider _rng = new();
#endif

        /// <summary>
        /// Generates cryptographically secure random bytes.
        /// </summary>
        /// <param name="length">The number of random bytes to generate.</param>
        /// <returns>An array of cryptographically secure random bytes.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="length"/> is less than or equal to zero.</exception>
        public static byte[] GenerateBytes(int length)
        {
            if (length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be greater than zero.");
            }

            byte[] bytes = new byte[length];
#if NETFRAMEWORK || NETSTANDARD2_0
            _rng.GetBytes(bytes);
#else
            RandomNumberGenerator.Fill(bytes);
#endif
            return bytes;
        }

        /// <summary>
        /// Fills the specified buffer with cryptographically secure random bytes.
        /// </summary>
        /// <param name="buffer">The buffer to fill with random bytes.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="buffer"/> is null.</exception>
        public static void Fill(byte[] buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

#if NETFRAMEWORK || NETSTANDARD2_0
            _rng.GetBytes(buffer);
#else
            RandomNumberGenerator.Fill(buffer);
#endif
        }

#if !NETFRAMEWORK && !NETSTANDARD2_0
        /// <summary>
        /// Fills the specified span with cryptographically secure random bytes.
        /// </summary>
        /// <param name="buffer">The span to fill with random bytes.</param>
        public static void Fill(Span<byte> buffer)
        {
            RandomNumberGenerator.Fill(buffer);
        }
#endif

        /// <summary>
        /// Generates a cryptographically secure random non-negative integer.
        /// </summary>
        /// <returns>A random non-negative integer.</returns>
        public static int GetInt32()
        {
            byte[] bytes = new byte[4];
#if NETFRAMEWORK || NETSTANDARD2_0
            _rng.GetBytes(bytes);
#else
            RandomNumberGenerator.Fill(bytes);
#endif
            return Math.Abs(BitConverter.ToInt32(bytes, 0));
        }

        /// <summary>
        /// Generates a cryptographically secure random integer within the specified range.
        /// </summary>
        /// <param name="minValue">The inclusive lower bound of the random number returned.</param>
        /// <param name="maxValue">The exclusive upper bound of the random number returned.</param>
        /// <returns>A random integer greater than or equal to <paramref name="minValue"/> and less than <paramref name="maxValue"/>.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="minValue"/> is greater than or equal to <paramref name="maxValue"/>.</exception>
        public static int GetInt32(int minValue, int maxValue)
        {
            if (minValue >= maxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(minValue), "minValue must be less than maxValue.");
            }

#if NET6_0_OR_GREATER
            return RandomNumberGenerator.GetInt32(minValue, maxValue);
#else
            long range = (long)maxValue - minValue;
            byte[] bytes = new byte[4];
#if NETSTANDARD2_0
            _rng.GetBytes(bytes);
#else
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
#endif
            uint randomValue = (uint)BitConverter.ToInt32(bytes, 0);
            return (int)(minValue + (randomValue % range));
#endif
        }

        /// <summary>
        /// Generates a cryptographically secure random nonce of the specified length.
        /// </summary>
        /// <param name="length">The length of the nonce in bytes.</param>
        /// <returns>A cryptographically secure random nonce.</returns>
        /// <remarks>
        /// Nonces are typically used in cryptographic protocols to ensure that
        /// the same plaintext encrypts to different ciphertexts each time.
        /// Common nonce lengths are 12 bytes for GCM mode and 16 bytes for CBC mode.
        /// </remarks>
        public static byte[] GenerateNonce(int length)
        {
            return GenerateBytes(length);
        }

        /// <summary>
        /// Generates a cryptographically secure random salt for key derivation.
        /// </summary>
        /// <param name="length">The length of the salt in bytes.</param>
        /// <returns>A cryptographically secure random salt.</returns>
        /// <remarks>
        /// Salts should be at least 16 bytes (128 bits) for security.
        /// The recommended length for password hashing is 32 bytes (256 bits).
        /// </remarks>
        public static byte[] GenerateSalt(int length = 32)
        {
            return GenerateBytes(length);
        }

        /// <summary>
        /// Generates a cryptographically secure random key of the specified length.
        /// </summary>
        /// <param name="keySizeInBits">The size of the key in bits.</param>
        /// <returns>A cryptographically secure random key.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="keySizeInBits"/> is not a multiple of 8 or is less than or equal to zero.</exception>
        public static byte[] GenerateKey(int keySizeInBits)
        {
            if (keySizeInBits <= 0 || keySizeInBits % 8 != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(keySizeInBits), "Key size must be a positive multiple of 8.");
            }

            return GenerateBytes(keySizeInBits / 8);
        }
    }
}
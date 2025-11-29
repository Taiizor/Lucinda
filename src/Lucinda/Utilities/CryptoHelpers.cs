// <copyright file="CryptoHelpers.cs" company="Lucinda">
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

namespace Lucinda.Utilities
{
    /// <summary>
    /// Provides common cryptographic utility methods.
    /// </summary>
    public static class CryptoHelpers
    {
        /// <summary>
        /// Compares two byte arrays in constant time to prevent timing attacks.
        /// </summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns><c>true</c> if the arrays are equal; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// This method is designed to take the same amount of time regardless of
        /// where the arrays differ, preventing timing-based side-channel attacks.
        /// </remarks>
        public static bool ConstantTimeEquals(byte[]? a, byte[]? b)
        {
            if (a == null && b == null)
            {
                return true;
            }

            if (a == null || b == null)
            {
                return false;
            }

            if (a.Length != b.Length)
            {
                return false;
            }

#if NET6_0_OR_GREATER
            return CryptographicOperations.FixedTimeEquals(a, b);
#else
            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
#endif
        }

        /// <summary>
        /// Securely clears the contents of a byte array.
        /// </summary>
        /// <param name="data">The byte array to clear.</param>
        /// <remarks>
        /// This method overwrites the array contents with zeros to ensure
        /// sensitive data is removed from memory.
        /// </remarks>
        public static void SecureClear(byte[]? data)
        {
            if (data == null)
            {
                return;
            }

#if NET6_0_OR_GREATER
            CryptographicOperations.ZeroMemory(data);
#else
            Array.Clear(data, 0, data.Length);
#endif
        }

#if !NETFRAMEWORK && !NETSTANDARD2_0
        /// <summary>
        /// Securely clears the contents of a span.
        /// </summary>
        /// <param name="data">The span to clear.</param>
        public static void SecureClear(Span<byte> data)
        {
#if NET6_0_OR_GREATER
            CryptographicOperations.ZeroMemory(data);
#else
            data.Clear();
#endif
        }
#endif

        /// <summary>
        /// Converts a byte array to a hexadecimal string.
        /// </summary>
        /// <param name="bytes">The bytes to convert.</param>
        /// <returns>A hexadecimal string representation of the bytes.</returns>
        public static string ToHexString(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return string.Empty;
            }

#if NET5_0_OR_GREATER
            return Convert.ToHexString(bytes);
#else
            StringBuilder sb = new(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
#endif
        }

        /// <summary>
        /// Converts a hexadecimal string to a byte array.
        /// </summary>
        /// <param name="hex">The hexadecimal string to convert.</param>
        /// <returns>A byte array representation of the hexadecimal string.</returns>
        /// <exception cref="ArgumentException">Thrown when the string is not valid hexadecimal.</exception>
        public static byte[] FromHexString(string hex)
        {
            if (string.IsNullOrEmpty(hex))
            {
                return [];
            }

            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("Hexadecimal string must have an even number of characters.", nameof(hex));
            }

#if NET5_0_OR_GREATER
            return Convert.FromHexString(hex);
#else
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
#endif
        }

        /// <summary>
        /// Converts a byte array to a Base64 string.
        /// </summary>
        /// <param name="bytes">The bytes to convert.</param>
        /// <returns>A Base64 string representation of the bytes.</returns>
        public static string ToBase64(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return string.Empty;
            }

            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Converts a Base64 string to a byte array.
        /// </summary>
        /// <param name="base64">The Base64 string to convert.</param>
        /// <returns>A byte array representation of the Base64 string.</returns>
        public static byte[] FromBase64(string base64)
        {
            if (string.IsNullOrEmpty(base64))
            {
                return [];
            }

            return Convert.FromBase64String(base64);
        }

        /// <summary>
        /// Converts a string to UTF-8 bytes.
        /// </summary>
        /// <param name="text">The string to convert.</param>
        /// <returns>UTF-8 encoded bytes.</returns>
        public static byte[] GetUtf8Bytes(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return [];
            }

            return Encoding.UTF8.GetBytes(text);
        }

        /// <summary>
        /// Converts UTF-8 bytes to a string.
        /// </summary>
        /// <param name="bytes">The UTF-8 bytes to convert.</param>
        /// <returns>The decoded string.</returns>
        public static string GetUtf8String(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return string.Empty;
            }

            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Concatenates multiple byte arrays into a single array.
        /// </summary>
        /// <param name="arrays">The arrays to concatenate.</param>
        /// <returns>A single byte array containing all input arrays.</returns>
        public static byte[] Concatenate(params byte[][] arrays)
        {
            if (arrays == null || arrays.Length == 0)
            {
                return [];
            }

            int totalLength = 0;
            foreach (byte[] arr in arrays)
            {
                if (arr != null)
                {
                    totalLength += arr.Length;
                }
            }

            byte[] result = new byte[totalLength];
            int offset = 0;
            foreach (byte[] arr in arrays)
            {
                if (arr != null && arr.Length > 0)
                {
                    Array.Copy(arr, 0, result, offset, arr.Length);
                    offset += arr.Length;
                }
            }

            return result;
        }

        /// <summary>
        /// Computes a SHA-256 hash of the specified data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>The SHA-256 hash of the data.</returns>
        public static byte[] ComputeSha256(byte[] data)
        {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(data);
#else
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
#endif

#if NET5_0_OR_GREATER
            return SHA256.HashData(data);
#else
            using SHA256 sha256 = SHA256.Create();
            return sha256.ComputeHash(data);
#endif
        }

        /// <summary>
        /// Computes a SHA-384 hash of the specified data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>The SHA-384 hash of the data.</returns>
        public static byte[] ComputeSha384(byte[] data)
        {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(data);
#else
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
#endif

#if NET5_0_OR_GREATER
            return SHA384.HashData(data);
#else
            using SHA384 sha384 = SHA384.Create();
            return sha384.ComputeHash(data);
#endif
        }

        /// <summary>
        /// Computes a SHA-512 hash of the specified data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>The SHA-512 hash of the data.</returns>
        public static byte[] ComputeSha512(byte[] data)
        {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(data);
#else
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
#endif

#if NET5_0_OR_GREATER
            return SHA512.HashData(data);
#else
            using SHA512 sha512 = SHA512.Create();
            return sha512.ComputeHash(data);
#endif
        }

        /// <summary>
        /// Computes an HMAC-SHA256 of the specified data.
        /// </summary>
        /// <param name="key">The HMAC key.</param>
        /// <param name="data">The data to authenticate.</param>
        /// <returns>The HMAC-SHA256 authentication code.</returns>
        public static byte[] ComputeHmacSha256(byte[] key, byte[] data)
        {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(key);
#else
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
#endif

#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(data);
#else
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
#endif

#if NET6_0_OR_GREATER
            return HMACSHA256.HashData(key, data);
#else
            using HMACSHA256 hmac = new(key);
            return hmac.ComputeHash(data);
#endif
        }

        /// <summary>
        /// Computes an HMAC-SHA512 of the specified data.
        /// </summary>
        /// <param name="key">The HMAC key.</param>
        /// <param name="data">The data to authenticate.</param>
        /// <returns>The HMAC-SHA512 authentication code.</returns>
        public static byte[] ComputeHmacSha512(byte[] key, byte[] data)
        {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(key);
#else
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
#endif

#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(data);
#else
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
#endif

#if NET6_0_OR_GREATER
            return HMACSHA512.HashData(key, data);
#else
            using HMACSHA512 hmac = new(key);
            return hmac.ComputeHash(data);
#endif
        }
    }
}
// <copyright file="BlazorCryptoHelpers.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using System.Text;

namespace Lucinda.Blazor.Utilities
{
    /// <summary>
    /// Provides common cryptographic utility methods for Blazor WebAssembly applications.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class provides helper methods for common cryptographic operations including:
    /// <list type="bullet">
    /// <item><description>Constant-time comparison to prevent timing attacks</description></item>
    /// <item><description>Secure memory clearing</description></item>
    /// <item><description>Encoding/decoding (Base64, Base64Url, Hex)</description></item>
    /// <item><description>Byte array manipulation</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public static class BlazorCryptoHelpers
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

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
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

            Array.Clear(data, 0, data.Length);
        }

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

            return Convert.ToHexString(bytes);
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

            return Convert.FromHexString(hex);
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
        /// Converts a byte array to a Base64Url string.
        /// </summary>
        /// <param name="bytes">The bytes to convert.</param>
        /// <returns>A Base64Url string representation of the bytes.</returns>
        /// <remarks>
        /// Base64Url is URL-safe variant of Base64, replacing '+' with '-' and '/' with '_',
        /// and omitting padding characters. This format is commonly used in JWTs and URLs.
        /// </remarks>
        public static string ToBase64Url(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return string.Empty;
            }

            return Convert.ToBase64String(bytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }

        /// <summary>
        /// Converts a Base64Url string to a byte array.
        /// </summary>
        /// <param name="base64Url">The Base64Url string to convert.</param>
        /// <returns>A byte array representation of the Base64Url string.</returns>
        /// <remarks>
        /// Base64Url is URL-safe variant of Base64, replacing '+' with '-' and '/' with '_',
        /// and omitting padding characters. This format is commonly used in JWTs and URLs.
        /// </remarks>
        public static byte[] FromBase64Url(string base64Url)
        {
            if (string.IsNullOrEmpty(base64Url))
            {
                return [];
            }

            // Convert Base64Url to standard Base64
            string base64 = base64Url
                .Replace('-', '+')
                .Replace('_', '/');

            // Add padding if necessary
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
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
        /// Splits a byte array at the specified position.
        /// </summary>
        /// <param name="data">The data to split.</param>
        /// <param name="position">The position to split at.</param>
        /// <returns>A tuple containing the two parts (Left, Right).</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when position is out of range.</exception>
        public static (byte[] Left, byte[] Right) Split(byte[] data, int position)
        {
            if (data == null)
            {
                return ([], []);
            }

            if (position < 0 || position > data.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(position), "Position must be within the data bounds.");
            }

            byte[] left = new byte[position];
            byte[] right = new byte[data.Length - position];

            if (position > 0)
            {
                Array.Copy(data, 0, left, 0, position);
            }

            if (right.Length > 0)
            {
                Array.Copy(data, position, right, 0, right.Length);
            }

            return (left, right);
        }

        /// <summary>
        /// Creates a copy of a byte array.
        /// </summary>
        /// <param name="source">The source array.</param>
        /// <returns>A new array with the same contents.</returns>
        public static byte[] Clone(byte[] source)
        {
            if (source == null)
            {
                return [];
            }

            byte[] copy = new byte[source.Length];
            Array.Copy(source, copy, source.Length);
            return copy;
        }

        /// <summary>
        /// Extracts a portion of a byte array.
        /// </summary>
        /// <param name="source">The source array.</param>
        /// <param name="offset">The starting offset.</param>
        /// <param name="length">The number of bytes to extract.</param>
        /// <returns>A new array containing the specified portion.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when offset or length is out of range.</exception>
        public static byte[] Slice(byte[] source, int offset, int length)
        {
            if (source == null)
            {
                return [];
            }

            if (offset < 0 || offset >= source.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            if (length < 0 || offset + length > source.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            byte[] result = new byte[length];
            Array.Copy(source, offset, result, 0, length);
            return result;
        }

        /// <summary>
        /// XORs two byte arrays together.
        /// </summary>
        /// <param name="a">The first array.</param>
        /// <param name="b">The second array.</param>
        /// <returns>A new array containing the XOR result.</returns>
        /// <exception cref="ArgumentException">Thrown when arrays have different lengths.</exception>
        public static byte[] Xor(byte[] a, byte[] b)
        {
            if (a == null || b == null)
            {
                throw new ArgumentNullException(a == null ? nameof(a) : nameof(b));
            }

            if (a.Length != b.Length)
            {
                throw new ArgumentException("Arrays must have the same length.");
            }

            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }

            return result;
        }

        /// <summary>
        /// Generates a random identifier string.
        /// </summary>
        /// <param name="length">The length of the identifier in bytes (default: 16).</param>
        /// <returns>A random identifier as a Base64Url string.</returns>
        public static string GenerateRandomId(int length = 16)
        {
            byte[] bytes = new byte[length];
            Random.Shared.NextBytes(bytes);
            return ToBase64Url(bytes);
        }
    }
}

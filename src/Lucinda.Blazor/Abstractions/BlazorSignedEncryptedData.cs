// <copyright file="BlazorSignedEncryptedData.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Represents encrypted data with an accompanying digital signature.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="BlazorSignedEncryptedData"/> class.
    /// </remarks>
    /// <param name="encryptedData">The encrypted data bytes.</param>
    /// <param name="signature">The digital signature bytes.</param>
    public sealed class BlazorSignedEncryptedData(byte[] encryptedData, byte[] signature)
    {
        /// <summary>
        /// Gets the encrypted data.
        /// </summary>
        public byte[] EncryptedData { get; } = encryptedData ?? throw new ArgumentNullException(nameof(encryptedData));

        /// <summary>
        /// Gets the digital signature.
        /// </summary>
        public byte[] Signature { get; } = signature ?? throw new ArgumentNullException(nameof(signature));

        /// <summary>
        /// Serializes this signed encrypted data to a byte array.
        /// </summary>
        /// <returns>The serialized bytes.</returns>
        public byte[] ToBytes()
        {
            // Format: [4 bytes: encrypted data length][encrypted data][signature]
            byte[] result = new byte[4 + EncryptedData.Length + Signature.Length];

            // Write encrypted data length
            BitConverter.GetBytes(EncryptedData.Length).CopyTo(result, 0);

            // Write encrypted data
            EncryptedData.CopyTo(result, 4);

            // Write signature
            Signature.CopyTo(result, 4 + EncryptedData.Length);

            return result;
        }

        /// <summary>
        /// Deserializes signed encrypted data from a byte array.
        /// </summary>
        /// <param name="data">The serialized data.</param>
        /// <returns>The deserialized signed encrypted data.</returns>
        /// <exception cref="ArgumentException">Thrown when data is invalid.</exception>
        public static BlazorSignedEncryptedData FromBytes(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            if (data.Length < 4)
            {
                throw new ArgumentException("Data is too short to contain signed encrypted data.", nameof(data));
            }

            // Read encrypted data length
            int encryptedDataLength = BitConverter.ToInt32(data, 0);

            if (encryptedDataLength < 0 || encryptedDataLength > data.Length - 4)
            {
                throw new ArgumentException("Invalid encrypted data length.", nameof(data));
            }

            // Read encrypted data
            byte[] encryptedData = new byte[encryptedDataLength];
            Array.Copy(data, 4, encryptedData, 0, encryptedDataLength);

            // Read signature
            int signatureLength = data.Length - 4 - encryptedDataLength;
            byte[] signature = new byte[signatureLength];
            Array.Copy(data, 4 + encryptedDataLength, signature, 0, signatureLength);

            return new BlazorSignedEncryptedData(encryptedData, signature);
        }

        /// <summary>
        /// Converts this signed encrypted data to a Base64 string.
        /// </summary>
        /// <returns>The Base64 encoded string.</returns>
        public string ToBase64()
        {
            return Convert.ToBase64String(ToBytes());
        }

        /// <summary>
        /// Creates signed encrypted data from a Base64 string.
        /// </summary>
        /// <param name="base64">The Base64 encoded string.</param>
        /// <returns>The deserialized signed encrypted data.</returns>
        public static BlazorSignedEncryptedData FromBase64(string base64)
        {
            ArgumentNullException.ThrowIfNull(base64);
            return FromBytes(Convert.FromBase64String(base64));
        }
    }
}
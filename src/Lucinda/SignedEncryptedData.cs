// <copyright file="SignedEncryptedData.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

using Lucinda.Abstractions;

namespace Lucinda
{
    /// <summary>
    /// Represents data that has been encrypted and digitally signed.
    /// </summary>
    public sealed class SignedEncryptedData
    {
        /// <summary>
        /// Gets or sets the encrypted data.
        /// </summary>
        /// <value>The encrypted data bytes.</value>
        public byte[] EncryptedData { get; set; } = [];

        /// <summary>
        /// Gets or sets the digital signature of the encrypted data.
        /// </summary>
        /// <value>The signature bytes.</value>
        public byte[] Signature { get; set; } = [];

        /// <summary>
        /// Gets or sets the version of the signed encrypted data format.
        /// </summary>
        /// <value>The format version. Default is 1.</value>
        public int Version { get; set; } = 1;

        /// <summary>
        /// Serializes the signed encrypted data to a byte array.
        /// </summary>
        /// <returns>A byte array containing the serialized data.</returns>
        public byte[] ToBytes()
        {
            int totalLength = 4 + 4 + EncryptedData.Length + 4 + Signature.Length;
            byte[] result = new byte[totalLength];
            int offset = 0;

            // Version
            WriteInt32(result, offset, Version);
            offset += 4;

            // Encrypted data
            WriteInt32(result, offset, EncryptedData.Length);
            offset += 4;
            Array.Copy(EncryptedData, 0, result, offset, EncryptedData.Length);
            offset += EncryptedData.Length;

            // Signature
            WriteInt32(result, offset, Signature.Length);
            offset += 4;
            Array.Copy(Signature, 0, result, offset, Signature.Length);

            return result;
        }

        /// <summary>
        /// Deserializes signed encrypted data from a byte array.
        /// </summary>
        /// <param name="data">The serialized data.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the deserialized data on success,
        /// or an error message on failure.
        /// </returns>
        public static CryptoResult<SignedEncryptedData> FromBytes(byte[] data)
        {
            if (data == null || data.Length < 12)
            {
                return CryptoResult<SignedEncryptedData>.Failure("Invalid data format: data is too short.");
            }

            try
            {
                int offset = 0;

                // Version
                int version = ReadInt32(data, offset);
                offset += 4;

                // Encrypted data
                int encryptedDataLength = ReadInt32(data, offset);
                offset += 4;
                if (encryptedDataLength < 0 || offset + encryptedDataLength > data.Length)
                {
                    return CryptoResult<SignedEncryptedData>.Failure("Invalid data format: invalid encrypted data length.");
                }
                byte[] encryptedData = new byte[encryptedDataLength];
                Array.Copy(data, offset, encryptedData, 0, encryptedDataLength);
                offset += encryptedDataLength;

                // Signature
                if (offset + 4 > data.Length)
                {
                    return CryptoResult<SignedEncryptedData>.Failure("Invalid data format: missing signature length.");
                }
                int signatureLength = ReadInt32(data, offset);
                offset += 4;
                if (signatureLength < 0 || offset + signatureLength > data.Length)
                {
                    return CryptoResult<SignedEncryptedData>.Failure("Invalid data format: invalid signature length.");
                }
                byte[] signature = new byte[signatureLength];
                Array.Copy(data, offset, signature, 0, signatureLength);

                return CryptoResult<SignedEncryptedData>.Success(new SignedEncryptedData
                {
                    Version = version,
                    EncryptedData = encryptedData,
                    Signature = signature
                });
            }
            catch (Exception ex)
            {
                return CryptoResult<SignedEncryptedData>.Failure($"Failed to deserialize data: {ex.Message}");
            }
        }

        private static void WriteInt32(byte[] buffer, int offset, int value)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }

        private static int ReadInt32(byte[] buffer, int offset)
        {
            return (buffer[offset] << 24) |
                   (buffer[offset + 1] << 16) |
                   (buffer[offset + 2] << 8) |
                   buffer[offset + 3];
        }
    }
}
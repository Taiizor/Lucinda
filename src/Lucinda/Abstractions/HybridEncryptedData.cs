// <copyright file="HybridEncryptedData.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Represents the result of hybrid encryption, containing the encapsulated key and encrypted data.
    /// </summary>
    /// <remarks>
    /// This class encapsulates all the components needed to decrypt hybrid-encrypted data:
    /// <list type="bullet">
    /// <item><description>The encrypted symmetric key (encrypted with the recipient's public key)</description></item>
    /// <item><description>The encrypted data (encrypted with the symmetric key)</description></item>
    /// <item><description>Any additional metadata required for decryption</description></item>
    /// </list>
    /// </remarks>
    /// <remarks>
    /// Initializes a new instance of the <see cref="HybridEncryptedData"/> class.
    /// </remarks>
    /// <param name="encapsulatedKey">The asymmetrically encrypted symmetric key.</param>
    /// <param name="ciphertext">The symmetrically encrypted data (including IV/nonce and tag).</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="encapsulatedKey"/> or <paramref name="ciphertext"/> is null.
    /// </exception>
    public sealed class HybridEncryptedData(byte[] encapsulatedKey, byte[] ciphertext)
    {
        /// <summary>
        /// Gets the encapsulated (asymmetrically encrypted) symmetric key.
        /// </summary>
        /// <value>The encrypted symmetric key bytes.</value>
        public byte[] EncapsulatedKey { get; } = encapsulatedKey ?? throw new ArgumentNullException(nameof(encapsulatedKey));

        /// <summary>
        /// Gets the symmetrically encrypted ciphertext.
        /// </summary>
        /// <value>The encrypted data bytes (including IV/nonce and authentication tag).</value>
        public byte[] Ciphertext { get; } = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));

        /// <summary>
        /// Gets or sets the version identifier for the encryption format.
        /// </summary>
        /// <value>The format version (default is 1).</value>
        public int Version { get; set; } = 1;

        /// <summary>
        /// Gets or sets optional metadata associated with the encrypted data.
        /// </summary>
        /// <value>Additional metadata bytes, or null if not present.</value>
        public byte[]? Metadata { get; set; }

        /// <summary>
        /// Serializes the encrypted data to a single byte array for storage or transmission.
        /// </summary>
        /// <returns>A byte array containing all encrypted data components.</returns>
        /// <remarks>
        /// The serialization format:
        /// [4 bytes: version][4 bytes: key length][key data][4 bytes: ciphertext length][ciphertext][metadata if present]
        /// </remarks>
        public byte[] ToBytes()
        {
            int metadataLength = Metadata?.Length ?? 0;
            int totalLength = 4 + 4 + EncapsulatedKey.Length + 4 + Ciphertext.Length + 4 + metadataLength;
            byte[] result = new byte[totalLength];
            int offset = 0;

            // Version
            WriteInt32(result, offset, Version);
            offset += 4;

            // Encapsulated key
            WriteInt32(result, offset, EncapsulatedKey.Length);
            offset += 4;
            Array.Copy(EncapsulatedKey, 0, result, offset, EncapsulatedKey.Length);
            offset += EncapsulatedKey.Length;

            // Ciphertext
            WriteInt32(result, offset, Ciphertext.Length);
            offset += 4;
            Array.Copy(Ciphertext, 0, result, offset, Ciphertext.Length);
            offset += Ciphertext.Length;

            // Metadata
            WriteInt32(result, offset, metadataLength);
            offset += 4;
            if (Metadata != null && metadataLength > 0)
            {
                Array.Copy(Metadata, 0, result, offset, metadataLength);
            }

            return result;
        }

        /// <summary>
        /// Deserializes encrypted data from a byte array.
        /// </summary>
        /// <param name="data">The serialized encrypted data.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the deserialized <see cref="HybridEncryptedData"/> on success,
        /// or an error message on failure.
        /// </returns>
        public static CryptoResult<HybridEncryptedData> FromBytes(byte[] data)
        {
            if (data == null || data.Length < 16)
            {
                return CryptoResult<HybridEncryptedData>.Failure("Invalid encrypted data format: data is too short.");
            }

            try
            {
                int offset = 0;

                // Version
                int version = ReadInt32(data, offset);
                offset += 4;

                // Encapsulated key
                int keyLength = ReadInt32(data, offset);
                offset += 4;
                if (keyLength < 0 || offset + keyLength > data.Length)
                {
                    return CryptoResult<HybridEncryptedData>.Failure("Invalid encrypted data format: invalid key length.");
                }
                byte[] encapsulatedKey = new byte[keyLength];
                Array.Copy(data, offset, encapsulatedKey, 0, keyLength);
                offset += keyLength;

                // Ciphertext
                if (offset + 4 > data.Length)
                {
                    return CryptoResult<HybridEncryptedData>.Failure("Invalid encrypted data format: missing ciphertext length.");
                }
                int ciphertextLength = ReadInt32(data, offset);
                offset += 4;
                if (ciphertextLength < 0 || offset + ciphertextLength > data.Length)
                {
                    return CryptoResult<HybridEncryptedData>.Failure("Invalid encrypted data format: invalid ciphertext length.");
                }
                byte[] ciphertext = new byte[ciphertextLength];
                Array.Copy(data, offset, ciphertext, 0, ciphertextLength);
                offset += ciphertextLength;

                // Metadata (optional)
                byte[]? metadata = null;
                if (offset + 4 <= data.Length)
                {
                    int metadataLength = ReadInt32(data, offset);
                    offset += 4;
                    if (metadataLength > 0 && offset + metadataLength <= data.Length)
                    {
                        metadata = new byte[metadataLength];
                        Array.Copy(data, offset, metadata, 0, metadataLength);
                    }
                }

                HybridEncryptedData result = new(encapsulatedKey, ciphertext)
                {
                    Version = version,
                    Metadata = metadata
                };

                return CryptoResult<HybridEncryptedData>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<HybridEncryptedData>.Failure($"Failed to deserialize encrypted data: {ex.Message}");
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
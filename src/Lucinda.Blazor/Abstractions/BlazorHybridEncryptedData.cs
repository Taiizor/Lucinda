// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

using System.Buffers.Binary;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Represents hybrid encrypted data containing an encapsulated symmetric key and ciphertext.
    /// </summary>
    public sealed class BlazorHybridEncryptedData
    {
        /// <summary>
        /// Current version of the hybrid encrypted data format.
        /// </summary>
        public const int CurrentVersion = 1;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorHybridEncryptedData"/> class.
        /// </summary>
        /// <param name="encapsulatedKey">The symmetric key encrypted with the recipient's public key.</param>
        /// <param name="ciphertext">The data encrypted with the symmetric key (includes IV/nonce).</param>
        public BlazorHybridEncryptedData(byte[] encapsulatedKey, byte[] ciphertext)
        {
            ArgumentNullException.ThrowIfNull(encapsulatedKey);
            ArgumentNullException.ThrowIfNull(ciphertext);

            if (encapsulatedKey.Length == 0)
            {
                throw new ArgumentException("Encapsulated key cannot be empty.", nameof(encapsulatedKey));
            }

            if (ciphertext.Length == 0)
            {
                throw new ArgumentException("Ciphertext cannot be empty.", nameof(ciphertext));
            }

            EncapsulatedKey = encapsulatedKey;
            Ciphertext = ciphertext;
        }

        /// <summary>
        /// Gets the encapsulated (RSA-encrypted) symmetric key.
        /// </summary>
        public byte[] EncapsulatedKey { get; }

        /// <summary>
        /// Gets the ciphertext (AES-GCM encrypted data with IV prepended).
        /// </summary>
        public byte[] Ciphertext { get; }

        /// <summary>
        /// Gets or sets the version of the encrypted data format.
        /// </summary>
        public int Version { get; set; } = CurrentVersion;

        /// <summary>
        /// Gets or sets optional metadata associated with the encrypted data.
        /// </summary>
        public byte[]? Metadata { get; set; }

        /// <summary>
        /// Serializes the hybrid encrypted data to a byte array.
        /// Format: [Version (4 bytes)][EncapsulatedKeyLength (4 bytes)][EncapsulatedKey][CiphertextLength (4 bytes)][Ciphertext][MetadataLength (4 bytes)][Metadata?]
        /// </summary>
        /// <returns>The serialized byte array.</returns>
        public byte[] ToBytes()
        {
            int metadataLength = Metadata?.Length ?? 0;
            int totalLength = 4 + 4 + EncapsulatedKey.Length + 4 + Ciphertext.Length + 4 + metadataLength;
            byte[] result = new byte[totalLength];
            int offset = 0;

            // Write version
            BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset, 4), Version);
            offset += 4;

            // Write encapsulated key length and data
            BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset, 4), EncapsulatedKey.Length);
            offset += 4;
            EncapsulatedKey.CopyTo(result, offset);
            offset += EncapsulatedKey.Length;

            // Write ciphertext length and data
            BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset, 4), Ciphertext.Length);
            offset += 4;
            Ciphertext.CopyTo(result, offset);
            offset += Ciphertext.Length;

            // Write metadata length and data
            BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset, 4), metadataLength);
            offset += 4;
            Metadata?.CopyTo(result, offset);

            return result;
        }

        /// <summary>
        /// Deserializes hybrid encrypted data from a byte array.
        /// </summary>
        /// <param name="data">The serialized data.</param>
        /// <returns>The deserialized <see cref="BlazorHybridEncryptedData"/> instance.</returns>
        /// <exception cref="ArgumentException">Thrown when the data format is invalid.</exception>
        public static BlazorHybridEncryptedData FromBytes(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            if (data.Length < 20) // Minimum: version(4) + keyLen(4) + key(1) + ctLen(4) + ct(1) + metaLen(4)
            {
                throw new ArgumentException("Data is too short to be valid hybrid encrypted data.", nameof(data));
            }

            int offset = 0;

            // Read version
            int version = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
            offset += 4;

            if (version != CurrentVersion)
            {
                throw new ArgumentException($"Unsupported hybrid encrypted data version: {version}", nameof(data));
            }

            // Read encapsulated key
            int encapsulatedKeyLength = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
            offset += 4;

            if (encapsulatedKeyLength <= 0 || offset + encapsulatedKeyLength > data.Length)
            {
                throw new ArgumentException("Invalid encapsulated key length.", nameof(data));
            }

            byte[] encapsulatedKey = data.AsSpan(offset, encapsulatedKeyLength).ToArray();
            offset += encapsulatedKeyLength;

            // Read ciphertext
            if (offset + 4 > data.Length)
            {
                throw new ArgumentException("Data is truncated at ciphertext length.", nameof(data));
            }

            int ciphertextLength = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
            offset += 4;

            if (ciphertextLength <= 0 || offset + ciphertextLength > data.Length)
            {
                throw new ArgumentException("Invalid ciphertext length.", nameof(data));
            }

            byte[] ciphertext = data.AsSpan(offset, ciphertextLength).ToArray();
            offset += ciphertextLength;

            // Read metadata (optional)
            byte[]? metadata = null;
            if (offset + 4 <= data.Length)
            {
                int metadataLength = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
                offset += 4;

                if (metadataLength > 0)
                {
                    if (offset + metadataLength > data.Length)
                    {
                        throw new ArgumentException("Invalid metadata length.", nameof(data));
                    }

                    metadata = data.AsSpan(offset, metadataLength).ToArray();
                }
            }

            return new BlazorHybridEncryptedData(encapsulatedKey, ciphertext)
            {
                Version = version,
                Metadata = metadata
            };
        }

        /// <summary>
        /// Creates a deep copy of this instance.
        /// </summary>
        /// <returns>A new <see cref="BlazorHybridEncryptedData"/> instance with copied data.</returns>
        public BlazorHybridEncryptedData Clone()
        {
            return new BlazorHybridEncryptedData(
                (byte[])EncapsulatedKey.Clone(),
                (byte[])Ciphertext.Clone())
            {
                Version = Version,
                Metadata = Metadata != null ? (byte[])Metadata.Clone() : null
            };
        }
    }
}
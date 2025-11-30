// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

namespace Lucinda.Blazor.Protocol.DoubleRatchet
{
    /// <summary>
    /// Represents the header of a Double Ratchet message.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="BlazorRatchetHeader"/> class.
    /// </remarks>
    /// <param name="dhPublicKey">The sender's current DH public key.</param>
    /// <param name="previousChainLength">The number of messages in the previous sending chain.</param>
    /// <param name="messageNumber">The message number in the current sending chain.</param>
    public sealed class BlazorRatchetHeader(byte[] dhPublicKey, int previousChainLength, int messageNumber)
    {
        /// <summary>
        /// Gets the sender's current DH public key.
        /// </summary>
        public byte[] DHPublicKey { get; } = dhPublicKey ?? throw new ArgumentNullException(nameof(dhPublicKey));

        /// <summary>
        /// Gets the number of messages sent in the previous sending chain.
        /// </summary>
        public int PreviousChainLength { get; } = previousChainLength;

        /// <summary>
        /// Gets the message number within the current sending chain.
        /// </summary>
        public int MessageNumber { get; } = messageNumber;

        /// <summary>
        /// Serializes the header to a byte array.
        /// </summary>
        /// <returns>The serialized header bytes.</returns>
        public byte[] ToBytes()
        {
            using MemoryStream ms = new();
            using BinaryWriter writer = new(ms);

            // Version
            writer.Write((byte)1);

            // DH public key
            writer.Write(DHPublicKey.Length);
            writer.Write(DHPublicKey);

            // Counters
            writer.Write(PreviousChainLength);
            writer.Write(MessageNumber);

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializes a header from a byte array.
        /// </summary>
        /// <param name="data">The serialized header bytes.</param>
        /// <returns>The deserialized header.</returns>
        public static BlazorRatchetHeader FromBytes(byte[] data)
        {
            if (data == null || data.Length < 10)
            {
                throw new InvalidDataException("Invalid header data.");
            }

            using MemoryStream ms = new(data);
            using BinaryReader reader = new(ms);

            byte version = reader.ReadByte();
            if (version != 1)
            {
                throw new InvalidDataException($"Unsupported header version: {version}");
            }

            int dhKeyLength = reader.ReadInt32();
            byte[] dhPublicKey = reader.ReadBytes(dhKeyLength);
            int previousChainLength = reader.ReadInt32();
            int messageNumber = reader.ReadInt32();

            return new BlazorRatchetHeader(dhPublicKey, previousChainLength, messageNumber);
        }
    }

    /// <summary>
    /// Represents an encrypted message from the Double Ratchet protocol.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="BlazorRatchetMessage"/> class.
    /// </remarks>
    /// <param name="header">The message header.</param>
    /// <param name="ciphertext">The encrypted message content.</param>
    public sealed class BlazorRatchetMessage(BlazorRatchetHeader header, byte[] ciphertext)
    {
        /// <summary>
        /// Gets the message header.
        /// </summary>
        public BlazorRatchetHeader Header { get; } = header ?? throw new ArgumentNullException(nameof(header));

        /// <summary>
        /// Gets the encrypted message content.
        /// </summary>
        public byte[] Ciphertext { get; } = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));

        /// <summary>
        /// Serializes the message to a byte array.
        /// </summary>
        /// <returns>The serialized message bytes.</returns>
        public byte[] ToBytes()
        {
            byte[] headerBytes = Header.ToBytes();

            using MemoryStream ms = new();
            using BinaryWriter writer = new(ms);

            writer.Write(headerBytes.Length);
            writer.Write(headerBytes);
            writer.Write(Ciphertext.Length);
            writer.Write(Ciphertext);

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializes a message from a byte array.
        /// </summary>
        /// <param name="data">The serialized message bytes.</param>
        /// <returns>The deserialized message.</returns>
        public static BlazorRatchetMessage FromBytes(byte[] data)
        {
            using MemoryStream ms = new(data);
            using BinaryReader reader = new(ms);

            int headerLength = reader.ReadInt32();
            byte[] headerBytes = reader.ReadBytes(headerLength);
            BlazorRatchetHeader header = BlazorRatchetHeader.FromBytes(headerBytes);

            int ciphertextLength = reader.ReadInt32();
            byte[] ciphertext = reader.ReadBytes(ciphertextLength);

            return new BlazorRatchetMessage(header, ciphertext);
        }
    }
}
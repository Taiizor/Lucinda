// <copyright file="RatchetHeader.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
namespace Lucinda.Protocol.DoubleRatchet
{
    /// <summary>
    /// Represents the header of a Double Ratchet message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The header contains:
    /// <list type="bullet">
    /// <item><description>DH Public Key: The sender's current ratchet public key</description></item>
    /// <item><description>Previous Chain Length: Number of messages sent in the previous chain</description></item>
    /// <item><description>Message Number: The index of this message in the current chain</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// The header is sent unencrypted (but authenticated) with each message.
    /// </para>
    /// </remarks>
    /// <remarks>
    /// Initializes a new instance of the <see cref="RatchetHeader"/> class.
    /// </remarks>
    /// <param name="dhPublicKey">The sender's current DH public key.</param>
    /// <param name="previousChainLength">The number of messages in the previous sending chain.</param>
    /// <param name="messageNumber">The message number in the current sending chain.</param>
    public sealed class RatchetHeader(byte[] dhPublicKey, int previousChainLength, int messageNumber)
    {
        /// <summary>
        /// Gets the sender's current DH public key.
        /// </summary>
        /// <value>The DH public key bytes.</value>
        public byte[] DHPublicKey { get; } = dhPublicKey ?? throw new ArgumentNullException(nameof(dhPublicKey));

        /// <summary>
        /// Gets the number of messages sent in the previous sending chain.
        /// </summary>
        /// <value>The previous chain length.</value>
        /// <remarks>
        /// This allows the recipient to skip the appropriate number of message keys
        /// in their previous receiving chain.
        /// </remarks>
        public int PreviousChainLength { get; } = previousChainLength;

        /// <summary>
        /// Gets the message number within the current sending chain.
        /// </summary>
        /// <value>The message number (0-indexed).</value>
        public int MessageNumber { get; } = messageNumber;

        /// <summary>
        /// Serializes the header to a byte array.
        /// </summary>
        /// <returns>The serialized header bytes.</returns>
        public byte[] ToBytes()
        {
            using MemoryStream ms = new();
            using BinaryWriter writer = new(ms);

            // Write version
            writer.Write((byte)1);

            // Write DH public key
            writer.Write(DHPublicKey.Length);
            writer.Write(DHPublicKey);

            // Write counters
            writer.Write(PreviousChainLength);
            writer.Write(MessageNumber);

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializes a header from a byte array.
        /// </summary>
        /// <param name="data">The serialized header bytes.</param>
        /// <returns>The deserialized header.</returns>
        /// <exception cref="InvalidDataException">Thrown if the data format is invalid.</exception>
        public static RatchetHeader FromBytes(byte[] data)
        {
            if (data == null || data.Length < 10)
            {
                throw new InvalidDataException("Invalid header data.");
            }

            using MemoryStream ms = new(data);
            using BinaryReader reader = new(ms);

            // Read version
            byte version = reader.ReadByte();
            if (version != 1)
            {
                throw new InvalidDataException($"Unsupported header version: {version}");
            }

            // Read DH public key
            int keyLength = reader.ReadInt32();
            byte[] dhPublicKey = reader.ReadBytes(keyLength);

            // Read counters
            int previousChainLength = reader.ReadInt32();
            int messageNumber = reader.ReadInt32();

            return new RatchetHeader(dhPublicKey, previousChainLength, messageNumber);
        }
    }

    /// <summary>
    /// Represents a complete Double Ratchet encrypted message.
    /// </summary>
    /// <remarks>
    /// Contains both the header (for ratchet synchronization) and the encrypted ciphertext.
    /// </remarks>
    /// <remarks>
    /// Initializes a new instance of the <see cref="RatchetMessage"/> class.
    /// </remarks>
    /// <param name="header">The message header.</param>
    /// <param name="ciphertext">The encrypted message ciphertext.</param>
    public sealed class RatchetMessage(RatchetHeader header, byte[] ciphertext)
    {
        /// <summary>
        /// Gets the message header.
        /// </summary>
        /// <value>The ratchet header.</value>
        public RatchetHeader Header { get; } = header ?? throw new ArgumentNullException(nameof(header));

        /// <summary>
        /// Gets the encrypted ciphertext.
        /// </summary>
        /// <value>The ciphertext bytes.</value>
        public byte[] Ciphertext { get; } = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));

        /// <summary>
        /// Serializes the complete message to a byte array.
        /// </summary>
        /// <returns>The serialized message bytes.</returns>
        public byte[] ToBytes()
        {
            byte[] headerBytes = Header.ToBytes();

            using MemoryStream ms = new();
            using BinaryWriter writer = new(ms);

            // Write header
            writer.Write(headerBytes.Length);
            writer.Write(headerBytes);

            // Write ciphertext
            writer.Write(Ciphertext.Length);
            writer.Write(Ciphertext);

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializes a message from a byte array.
        /// </summary>
        /// <param name="data">The serialized message bytes.</param>
        /// <returns>The deserialized message.</returns>
        /// <exception cref="InvalidDataException">Thrown if the data format is invalid.</exception>
        public static RatchetMessage FromBytes(byte[] data)
        {
            if (data == null || data.Length < 8)
            {
                throw new InvalidDataException("Invalid message data.");
            }

            using MemoryStream ms = new(data);
            using BinaryReader reader = new(ms);

            // Read header
            int headerLength = reader.ReadInt32();
            byte[] headerBytes = reader.ReadBytes(headerLength);
            RatchetHeader header = RatchetHeader.FromBytes(headerBytes);

            // Read ciphertext
            int ciphertextLength = reader.ReadInt32();
            byte[] ciphertext = reader.ReadBytes(ciphertextLength);

            return new RatchetMessage(header, ciphertext);
        }
    }
}
#endif
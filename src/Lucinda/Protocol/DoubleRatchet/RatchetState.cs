// <copyright file="RatchetState.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using Lucinda.Utilities;
using System.Security.Cryptography;

namespace Lucinda.Protocol.DoubleRatchet
{
    /// <summary>
    /// Represents the state of a Double Ratchet session.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The ratchet state maintains:
    /// <list type="bullet">
    /// <item><description>DH key pairs for the DH ratchet</description></item>
    /// <item><description>Root key for deriving chain keys</description></item>
    /// <item><description>Sending and receiving chain keys</description></item>
    /// <item><description>Message counters for ordering</description></item>
    /// <item><description>Skipped message keys for out-of-order decryption</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// This state should be persisted securely between sessions and updated after each
    /// encrypt/decrypt operation.
    /// </para>
    /// </remarks>
    public sealed class RatchetState : IDisposable
    {
        private bool _disposed;

        /// <summary>
        /// Maximum number of skipped message keys to store.
        /// </summary>
        public const int MaxSkippedMessageKeys = 1000;

        /// <summary>
        /// Initializes a new instance of the <see cref="RatchetState"/> class.
        /// </summary>
        public RatchetState()
        {
            SkippedMessageKeys = [];
        }

        /// <summary>
        /// Gets or sets the local DH private key for sending.
        /// </summary>
        /// <value>The local DH private key bytes.</value>
        public byte[]? DHSendingPrivateKey { get; set; }

        /// <summary>
        /// Gets or sets the local DH public key for sending.
        /// </summary>
        /// <value>The local DH public key bytes.</value>
        public byte[]? DHSendingPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the remote DH public key for receiving.
        /// </summary>
        /// <value>The remote DH public key bytes.</value>
        public byte[]? DHReceivingPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the root key used to derive chain keys.
        /// </summary>
        /// <value>The root key bytes (32 bytes).</value>
        public byte[]? RootKey { get; set; }

        /// <summary>
        /// Gets or sets the sending chain key.
        /// </summary>
        /// <value>The sending chain key bytes (32 bytes).</value>
        public byte[]? SendingChainKey { get; set; }

        /// <summary>
        /// Gets or sets the receiving chain key.
        /// </summary>
        /// <value>The receiving chain key bytes (32 bytes).</value>
        public byte[]? ReceivingChainKey { get; set; }

        /// <summary>
        /// Gets or sets the number of messages sent in the current sending chain.
        /// </summary>
        /// <value>The sending message number.</value>
        public int SendingMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the number of messages received in the current receiving chain.
        /// </summary>
        /// <value>The receiving message number.</value>
        public int ReceivingMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the length of the previous sending chain.
        /// </summary>
        /// <value>The previous chain length.</value>
        /// <remarks>
        /// This is sent in message headers so the recipient can skip the appropriate number
        /// of keys in the previous receiving chain.
        /// </remarks>
        public int PreviousSendingChainLength { get; set; }

        /// <summary>
        /// Gets the dictionary of skipped message keys for out-of-order decryption.
        /// </summary>
        /// <value>A dictionary mapping (public key hash, message number) to message keys.</value>
        public Dictionary<SkippedKeyId, byte[]> SkippedMessageKeys { get; }

        /// <summary>
        /// Stores a skipped message key for later use.
        /// </summary>
        /// <param name="publicKey">The DH public key associated with the chain.</param>
        /// <param name="messageNumber">The message number.</param>
        /// <param name="messageKey">The message key to store.</param>
        /// <returns><c>true</c> if the key was stored; <c>false</c> if the limit was reached.</returns>
        public bool StoreSkippedMessageKey(byte[] publicKey, int messageNumber, byte[] messageKey)
        {
            if (SkippedMessageKeys.Count >= MaxSkippedMessageKeys)
            {
                return false;
            }

            SkippedKeyId keyId = new(publicKey, messageNumber);
            SkippedMessageKeys[keyId] = messageKey;
            return true;
        }

        /// <summary>
        /// Tries to retrieve and remove a skipped message key.
        /// </summary>
        /// <param name="publicKey">The DH public key associated with the chain.</param>
        /// <param name="messageNumber">The message number.</param>
        /// <param name="messageKey">The retrieved message key, if found.</param>
        /// <returns><c>true</c> if a key was found and removed; otherwise, <c>false</c>.</returns>
        public bool TryConsumeSkippedMessageKey(byte[] publicKey, int messageNumber, out byte[]? messageKey)
        {
            SkippedKeyId keyId = new(publicKey, messageNumber);

            if (SkippedMessageKeys.TryGetValue(keyId, out messageKey))
            {
                SkippedMessageKeys.Remove(keyId);
                return true;
            }

            messageKey = null;
            return false;
        }

        /// <summary>
        /// Creates a deep clone of the ratchet state.
        /// </summary>
        /// <returns>A new <see cref="RatchetState"/> with copied values.</returns>
        public RatchetState Clone()
        {
            RatchetState clone = new()
            {
                DHSendingPrivateKey = DHSendingPrivateKey?.ToArray(),
                DHSendingPublicKey = DHSendingPublicKey?.ToArray(),
                DHReceivingPublicKey = DHReceivingPublicKey?.ToArray(),
                RootKey = RootKey?.ToArray(),
                SendingChainKey = SendingChainKey?.ToArray(),
                ReceivingChainKey = ReceivingChainKey?.ToArray(),
                SendingMessageNumber = SendingMessageNumber,
                ReceivingMessageNumber = ReceivingMessageNumber,
                PreviousSendingChainLength = PreviousSendingChainLength
            };

            foreach (KeyValuePair<SkippedKeyId, byte[]> kvp in SkippedMessageKeys)
            {
                clone.SkippedMessageKeys[kvp.Key] = [.. kvp.Value];
            }

            return clone;
        }

        /// <summary>
        /// Serializes the ratchet state to a byte array.
        /// </summary>
        /// <returns>The serialized state bytes.</returns>
        public byte[] Serialize()
        {
            using MemoryStream ms = new();
            using BinaryWriter writer = new(ms);

            // Write version
            writer.Write((byte)1);

            // Write keys
            WriteNullableBytes(writer, DHSendingPrivateKey);
            WriteNullableBytes(writer, DHSendingPublicKey);
            WriteNullableBytes(writer, DHReceivingPublicKey);
            WriteNullableBytes(writer, RootKey);
            WriteNullableBytes(writer, SendingChainKey);
            WriteNullableBytes(writer, ReceivingChainKey);

            // Write counters
            writer.Write(SendingMessageNumber);
            writer.Write(ReceivingMessageNumber);
            writer.Write(PreviousSendingChainLength);

            // Write skipped keys
            writer.Write(SkippedMessageKeys.Count);
            foreach (KeyValuePair<SkippedKeyId, byte[]> kvp in SkippedMessageKeys)
            {
                writer.Write(kvp.Key.PublicKeyHash.Length);
                writer.Write(kvp.Key.PublicKeyHash);
                writer.Write(kvp.Key.MessageNumber);
                writer.Write(kvp.Value.Length);
                writer.Write(kvp.Value);
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializes a ratchet state from a byte array.
        /// </summary>
        /// <param name="data">The serialized state bytes.</param>
        /// <returns>The deserialized ratchet state.</returns>
        public static RatchetState Deserialize(byte[] data)
        {
            using MemoryStream ms = new(data);
            using BinaryReader reader = new(ms);

            // Read version
            byte version = reader.ReadByte();
            if (version != 1)
            {
                throw new InvalidDataException($"Unsupported ratchet state version: {version}");
            }

            RatchetState state = new()
            {
                DHSendingPrivateKey = ReadNullableBytes(reader),
                DHSendingPublicKey = ReadNullableBytes(reader),
                DHReceivingPublicKey = ReadNullableBytes(reader),
                RootKey = ReadNullableBytes(reader),
                SendingChainKey = ReadNullableBytes(reader),
                ReceivingChainKey = ReadNullableBytes(reader),
                SendingMessageNumber = reader.ReadInt32(),
                ReceivingMessageNumber = reader.ReadInt32(),
                PreviousSendingChainLength = reader.ReadInt32()
            };

            // Read skipped keys
            int skippedCount = reader.ReadInt32();
            for (int i = 0; i < skippedCount; i++)
            {
                int hashLength = reader.ReadInt32();
                byte[] hash = reader.ReadBytes(hashLength);
                int messageNumber = reader.ReadInt32();
                int keyLength = reader.ReadInt32();
                byte[] key = reader.ReadBytes(keyLength);

                SkippedKeyId keyId = new(hash, messageNumber, isHash: true);
                state.SkippedMessageKeys[keyId] = key;
            }

            return state;
        }

        private static void WriteNullableBytes(BinaryWriter writer, byte[]? data)
        {
            if (data == null)
            {
                writer.Write(-1);
            }
            else
            {
                writer.Write(data.Length);
                writer.Write(data);
            }
        }

        private static byte[]? ReadNullableBytes(BinaryReader reader)
        {
            int length = reader.ReadInt32();
            if (length < 0)
            {
                return null;
            }
            return reader.ReadBytes(length);
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (!_disposed)
            {
                // Securely clear sensitive key material
                if (DHSendingPrivateKey != null)
                {
                    CryptoHelpers.SecureClear(DHSendingPrivateKey);
                }

                if (RootKey != null)
                {
                    CryptoHelpers.SecureClear(RootKey);
                }

                if (SendingChainKey != null)
                {
                    CryptoHelpers.SecureClear(SendingChainKey);
                }

                if (ReceivingChainKey != null)
                {
                    CryptoHelpers.SecureClear(ReceivingChainKey);
                }

                foreach (byte[] key in SkippedMessageKeys.Values)
                {
                    CryptoHelpers.SecureClear(key);
                }

                SkippedMessageKeys.Clear();
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Represents a unique identifier for a skipped message key.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="SkippedKeyId"/> struct.
    /// </remarks>
    /// <param name="publicKey">The DH public key (will be hashed).</param>
    /// <param name="messageNumber">The message number.</param>
    /// <param name="isHash">If true, publicKey is already a hash.</param>
    public readonly struct SkippedKeyId(byte[] publicKey, int messageNumber, bool isHash = false) : IEquatable<SkippedKeyId>
    {
        /// <summary>
        /// Gets the hash of the DH public key.
        /// </summary>
        public byte[] PublicKeyHash { get; } = isHash ? publicKey : ComputeHash(publicKey);

        /// <summary>
        /// Gets the message number.
        /// </summary>
        public int MessageNumber { get; } = messageNumber;

        private static byte[] ComputeHash(byte[] data)
        {
            return SHA256.HashData(data);
        }

        /// <inheritdoc/>
        public bool Equals(SkippedKeyId other)
        {
            return MessageNumber == other.MessageNumber &&
                   CryptoHelpers.ConstantTimeEquals(PublicKeyHash, other.PublicKeyHash);
        }

        /// <inheritdoc/>
        public override bool Equals(object? obj)
        {
            return obj is SkippedKeyId other && Equals(other);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            unchecked
            {
                int hash = 17;
                hash = (hash * 31) + MessageNumber;
                if (PublicKeyHash != null && PublicKeyHash.Length >= 4)
                {
                    hash = (hash * 31) + BitConverter.ToInt32(PublicKeyHash, 0);
                }
                return hash;
            }
        }

        /// <summary>
        /// Equality operator.
        /// </summary>
        public static bool operator ==(SkippedKeyId left, SkippedKeyId right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// Inequality operator.
        /// </summary>
        public static bool operator !=(SkippedKeyId left, SkippedKeyId right)
        {
            return !left.Equals(right);
        }
    }
}
#endif
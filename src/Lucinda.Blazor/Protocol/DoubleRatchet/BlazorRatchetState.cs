// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

namespace Lucinda.Blazor.Protocol.DoubleRatchet
{
    /// <summary>
    /// Represents the state of a Double Ratchet session for Blazor WebAssembly.
    /// </summary>
    public sealed class BlazorRatchetState : IDisposable
    {
        private bool _disposed;

        /// <summary>
        /// Maximum number of skipped message keys to store.
        /// </summary>
        public const int MaxSkippedMessageKeys = 1000;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorRatchetState"/> class.
        /// </summary>
        public BlazorRatchetState()
        {
            SkippedMessageKeys = new Dictionary<(byte[] DhPublicKey, int MessageNumber), byte[]>(
                new SkippedKeyComparer());
        }

        /// <summary>
        /// Gets or sets the local DH private key for sending.
        /// </summary>
        public byte[]? DHSendingPrivateKey { get; set; }

        /// <summary>
        /// Gets or sets the local DH public key for sending.
        /// </summary>
        public byte[]? DHSendingPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the remote DH public key for receiving.
        /// </summary>
        public byte[]? DHReceivingPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the root key used to derive chain keys.
        /// </summary>
        public byte[]? RootKey { get; set; }

        /// <summary>
        /// Gets or sets the sending chain key.
        /// </summary>
        public byte[]? SendingChainKey { get; set; }

        /// <summary>
        /// Gets or sets the receiving chain key.
        /// </summary>
        public byte[]? ReceivingChainKey { get; set; }

        /// <summary>
        /// Gets or sets the number of messages sent in the current sending chain.
        /// </summary>
        public int SendingMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the number of messages received in the current receiving chain.
        /// </summary>
        public int ReceivingMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the length of the previous sending chain.
        /// </summary>
        public int PreviousSendingChainLength { get; set; }

        /// <summary>
        /// Gets or sets the dictionary of skipped message keys.
        /// Key is (DHPublicKey, MessageNumber), value is the message key.
        /// </summary>
        public Dictionary<(byte[] DhPublicKey, int MessageNumber), byte[]> SkippedMessageKeys { get; set; }

        /// <summary>
        /// Serializes the ratchet state to a byte array.
        /// </summary>
        /// <returns>The serialized state.</returns>
        public byte[] Serialize()
        {
            using MemoryStream ms = new();
            using BinaryWriter writer = new(ms);

            // Version
            writer.Write((byte)1);

            // DH Keys
            WriteByteArray(writer, DHSendingPrivateKey);
            WriteByteArray(writer, DHSendingPublicKey);
            WriteByteArray(writer, DHReceivingPublicKey);

            // Chain keys
            WriteByteArray(writer, RootKey);
            WriteByteArray(writer, SendingChainKey);
            WriteByteArray(writer, ReceivingChainKey);

            // Counters
            writer.Write(SendingMessageNumber);
            writer.Write(ReceivingMessageNumber);
            writer.Write(PreviousSendingChainLength);

            // Skipped message keys
            writer.Write(SkippedMessageKeys.Count);
            foreach (KeyValuePair<(byte[] DhPublicKey, int MessageNumber), byte[]> kvp in SkippedMessageKeys)
            {
                WriteByteArray(writer, kvp.Key.DhPublicKey);
                writer.Write(kvp.Key.MessageNumber);
                WriteByteArray(writer, kvp.Value);
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializes a ratchet state from a byte array.
        /// </summary>
        /// <param name="data">The serialized state data.</param>
        /// <returns>The deserialized state.</returns>
        public static BlazorRatchetState Deserialize(byte[] data)
        {
            using MemoryStream ms = new(data);
            using BinaryReader reader = new(ms);

            byte version = reader.ReadByte();
            if (version != 1)
            {
                throw new InvalidDataException($"Unsupported state version: {version}");
            }

            BlazorRatchetState state = new()
            {
                DHSendingPrivateKey = ReadByteArray(reader),
                DHSendingPublicKey = ReadByteArray(reader),
                DHReceivingPublicKey = ReadByteArray(reader),
                RootKey = ReadByteArray(reader),
                SendingChainKey = ReadByteArray(reader),
                ReceivingChainKey = ReadByteArray(reader),
                SendingMessageNumber = reader.ReadInt32(),
                ReceivingMessageNumber = reader.ReadInt32(),
                PreviousSendingChainLength = reader.ReadInt32()
            };

            int skippedCount = reader.ReadInt32();
            for (int i = 0; i < skippedCount; i++)
            {
                byte[]? dhKey = ReadByteArray(reader);
                int msgNum = reader.ReadInt32();
                byte[]? msgKey = ReadByteArray(reader);
                if (dhKey != null && msgKey != null)
                {
                    state.SkippedMessageKeys[(dhKey, msgNum)] = msgKey;
                }
            }

            return state;
        }

        private static void WriteByteArray(BinaryWriter writer, byte[]? data)
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

        private static byte[]? ReadByteArray(BinaryReader reader)
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
            if (_disposed)
            {
                return;
            }

            // Clear sensitive data
            if (DHSendingPrivateKey != null)
            {
                Array.Clear(DHSendingPrivateKey, 0, DHSendingPrivateKey.Length);
            }

            if (RootKey != null)
            {
                Array.Clear(RootKey, 0, RootKey.Length);
            }

            if (SendingChainKey != null)
            {
                Array.Clear(SendingChainKey, 0, SendingChainKey.Length);
            }

            if (ReceivingChainKey != null)
            {
                Array.Clear(ReceivingChainKey, 0, ReceivingChainKey.Length);
            }

            foreach (byte[] key in SkippedMessageKeys.Values)
            {
                Array.Clear(key, 0, key.Length);
            }
            SkippedMessageKeys.Clear();

            _disposed = true;
        }

        /// <summary>
        /// Custom comparer for skipped message keys dictionary.
        /// </summary>
        private sealed class SkippedKeyComparer : IEqualityComparer<(byte[] DhPublicKey, int MessageNumber)>
        {
            public bool Equals((byte[] DhPublicKey, int MessageNumber) x, (byte[] DhPublicKey, int MessageNumber) y)
            {
                return x.MessageNumber == y.MessageNumber &&
                       x.DhPublicKey.SequenceEqual(y.DhPublicKey);
            }

            public int GetHashCode((byte[] DhPublicKey, int MessageNumber) obj)
            {
                int hash = obj.MessageNumber;
                foreach (byte b in obj.DhPublicKey.Take(8))
                {
                    hash = HashCode.Combine(hash, b);
                }
                return hash;
            }
        }
    }
}
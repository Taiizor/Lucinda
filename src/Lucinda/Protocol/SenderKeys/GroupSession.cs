// -----------------------------------------------------------------------
// <copyright file="GroupSession.cs" company="Taiizor">
// Copyright (c) Taiizor. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.
// </copyright>
// -----------------------------------------------------------------------

#if NET6_0_OR_GREATER
using Lucinda.Abstractions;
using Lucinda.Utilities;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Lucinda.Protocol.SenderKeys
{
    /// <summary>
    /// Manages a group messaging session using the Sender Keys protocol.
    /// Each participant in a group has their own sender key for encrypting messages.
    /// </summary>
    /// <remarks>
    /// Initializes a new GroupSession.
    /// </remarks>
    /// <param name="groupId">The group identifier.</param>
    /// <param name="localParticipantId">The local participant's identifier.</param>
    public class GroupSession(string groupId, string localParticipantId) : IDisposable
    {
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32;
        private SenderKeyState? _localSenderKey;
        private readonly Dictionary<string, SenderKeyState> _remoteSenderKeys = [];
        private bool _disposed;

        /// <summary>
        /// Gets the group ID.
        /// </summary>
        public string GroupId { get; } = groupId ?? throw new ArgumentNullException(nameof(groupId));

        /// <summary>
        /// Gets the local participant ID.
        /// </summary>
        public string LocalParticipantId { get; } = localParticipantId ?? throw new ArgumentNullException(nameof(localParticipantId));

        /// <summary>
        /// Gets whether the local sender key is initialized.
        /// </summary>
        public bool IsInitialized => _localSenderKey != null;

        /// <summary>
        /// Gets the number of known remote participants.
        /// </summary>
        public int RemoteParticipantCount => _remoteSenderKeys.Count;

        /// <summary>
        /// Initializes the local sender key.
        /// Must be called before sending messages.
        /// </summary>
        /// <param name="keyId">Optional key ID (auto-generated if not specified).</param>
        /// <returns>A CryptoResult indicating success or failure.</returns>
        public CryptoResult<bool> Initialize(int? keyId = null)
        {
            if (_disposed)
            {
                return CryptoResult<bool>.Failure("GroupSession has been disposed");
            }

            try
            {
                int id = keyId ?? RandomNumberGenerator.GetInt32(int.MaxValue);
                _localSenderKey?.Dispose();
                _localSenderKey = SenderKeyState.CreateAsOwner(id);
                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to initialize sender key: {ex.Message}");
            }
        }

        /// <summary>
        /// Creates a sender key distribution message to share with other group members.
        /// </summary>
        /// <returns>A CryptoResult containing the distribution data.</returns>
        public CryptoResult<SenderKeyDistributionData> CreateDistributionMessage()
        {
            if (_disposed)
            {
                return CryptoResult<SenderKeyDistributionData>.Failure("GroupSession has been disposed");
            }

            if (_localSenderKey == null)
            {
                return CryptoResult<SenderKeyDistributionData>.Failure("Local sender key not initialized");
            }

            SenderKeyDistributionData? data = _localSenderKey.ExportForDistribution();
            if (data == null)
            {
                return CryptoResult<SenderKeyDistributionData>.Failure("Failed to export sender key");
            }

            return CryptoResult<SenderKeyDistributionData>.Success(data);
        }

        /// <summary>
        /// Processes a sender key distribution message from another participant.
        /// </summary>
        /// <param name="participantId">The participant ID who sent the distribution.</param>
        /// <param name="distributionData">The distribution data.</param>
        /// <returns>A CryptoResult indicating success or failure.</returns>
        public CryptoResult<bool> ProcessDistributionMessage(string participantId, SenderKeyDistributionData distributionData)
        {
            if (_disposed)
            {
                return CryptoResult<bool>.Failure("GroupSession has been disposed");
            }

            if (string.IsNullOrEmpty(participantId))
            {
                return CryptoResult<bool>.Failure("Participant ID cannot be null or empty");
            }

            if (distributionData == null)
            {
                return CryptoResult<bool>.Failure("Distribution data cannot be null");
            }

            try
            {
                // Dispose existing state if present
                if (_remoteSenderKeys.TryGetValue(participantId, out SenderKeyState? existing))
                {
                    existing.Dispose();
                }

                // Create new state from distribution
                SenderKeyState state = SenderKeyState.CreateFromDistribution(
                    distributionData.KeyId,
                    distributionData.ChainKey,
                    distributionData.SignaturePublicKey,
                    distributionData.ChainIndex);

                _remoteSenderKeys[participantId] = state;
                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to process distribution: {ex.Message}");
            }
        }

        /// <summary>
        /// Encrypts a message for the group.
        /// </summary>
        /// <param name="plaintext">The message to encrypt.</param>
        /// <returns>A CryptoResult containing the encrypted group message.</returns>
        public CryptoResult<GroupMessage> Encrypt(byte[] plaintext)
        {
            if (_disposed)
            {
                return CryptoResult<GroupMessage>.Failure("GroupSession has been disposed");
            }

            if (_localSenderKey == null)
            {
                return CryptoResult<GroupMessage>.Failure("Local sender key not initialized");
            }

            if (plaintext == null || plaintext.Length == 0)
            {
                return CryptoResult<GroupMessage>.Failure("Plaintext cannot be null or empty");
            }

            try
            {
                // Get message key
                byte[]? messageKey = _localSenderKey.GetMessageKeyAndAdvance();
                if (messageKey == null)
                {
                    return CryptoResult<GroupMessage>.Failure("Failed to get message key - re-keying may be required");
                }

                try
                {
                    // Encrypt message
                    byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
                    byte[] ciphertext = new byte[plaintext.Length];
                    byte[] tag = new byte[TagSize];

#if NET8_0_OR_GREATER
                    using AesGcm aesGcm = new(messageKey, TagSize);
#else
                    using AesGcm aesGcm = new(messageKey);
#endif
                    aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

                    // Create message data for signing (includes metadata)
                    int chainIndex = _localSenderKey.ChainIndex - 1; // Current index after advance
                    byte[] messageData = CreateMessageDataForSigning(_localSenderKey.KeyId, chainIndex, ciphertext);

                    // Sign the message
                    byte[]? signature = _localSenderKey.Sign(messageData);
                    if (signature == null)
                    {
                        return CryptoResult<GroupMessage>.Failure("Failed to sign message");
                    }

                    GroupMessage message = new(
                        GroupId,
                        LocalParticipantId,
                        _localSenderKey.KeyId,
                        chainIndex,
                        nonce,
                        ciphertext,
                        tag,
                        signature);

                    return CryptoResult<GroupMessage>.Success(message);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(messageKey);
                }
            }
            catch (Exception ex)
            {
                return CryptoResult<GroupMessage>.Failure($"Failed to encrypt: {ex.Message}");
            }
        }

        /// <summary>
        /// Decrypts a message from the group.
        /// </summary>
        /// <param name="message">The encrypted group message.</param>
        /// <returns>A CryptoResult containing the decrypted plaintext.</returns>
        public CryptoResult<byte[]> Decrypt(GroupMessage message)
        {
            if (_disposed)
            {
                return CryptoResult<byte[]>.Failure("GroupSession has been disposed");
            }

            if (message == null)
            {
                return CryptoResult<byte[]>.Failure("Message cannot be null");
            }

            if (message.GroupId != GroupId)
            {
                return CryptoResult<byte[]>.Failure("Message is for a different group");
            }

            // Handle own messages
            if (message.SenderId == LocalParticipantId && _localSenderKey != null)
            {
                return DecryptWithState(_localSenderKey, message);
            }

            // Get remote sender's state
            if (!_remoteSenderKeys.TryGetValue(message.SenderId, out SenderKeyState? senderState))
            {
                return CryptoResult<byte[]>.Failure($"Unknown sender: {message.SenderId}. Distribution message needed.");
            }

            // Check key ID
            if (senderState.KeyId != message.KeyId)
            {
                return CryptoResult<byte[]>.Failure("Key ID mismatch. Sender may have re-keyed.");
            }

            return DecryptWithState(senderState, message);
        }

        /// <summary>
        /// Decrypts a message using a specific sender state.
        /// </summary>
        private CryptoResult<byte[]> DecryptWithState(SenderKeyState state, GroupMessage message)
        {
            try
            {
                // Verify signature first
                byte[] messageData = CreateMessageDataForSigning(message.KeyId, message.ChainIndex, message.Ciphertext);
                if (!state.Verify(messageData, message.Signature))
                {
                    return CryptoResult<byte[]>.Failure("Signature verification failed");
                }

                // Get message key for specific chain index
                byte[]? messageKey = state.GetMessageKeyAtIndex(message.ChainIndex);
                if (messageKey == null)
                {
                    return CryptoResult<byte[]>.Failure("Unable to derive message key for chain index");
                }

                try
                {
                    byte[] plaintext = new byte[message.Ciphertext.Length];

#if NET8_0_OR_GREATER
                    using AesGcm aesGcm = new(messageKey, TagSize);
#else
                    using AesGcm aesGcm = new(messageKey);
#endif
                    aesGcm.Decrypt(message.Nonce, message.Ciphertext, message.Tag, plaintext);

                    return CryptoResult<byte[]>.Success(plaintext);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(messageKey);
                }
            }
            catch (CryptographicException)
            {
                return CryptoResult<byte[]>.Failure("Message authentication failed");
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Decryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Creates the message data for signing/verification.
        /// </summary>
        private static byte[] CreateMessageDataForSigning(int keyId, int chainIndex, byte[] ciphertext)
        {
            byte[] data = new byte[4 + 4 + ciphertext.Length];
            BitConverter.GetBytes(keyId).CopyTo(data, 0);
            BitConverter.GetBytes(chainIndex).CopyTo(data, 4);
            ciphertext.CopyTo(data, 8);
            return data;
        }

        /// <summary>
        /// Removes a participant from the group session.
        /// </summary>
        /// <param name="participantId">The participant ID to remove.</param>
        public void RemoveParticipant(string participantId)
        {
            if (_remoteSenderKeys.TryGetValue(participantId, out SenderKeyState? state))
            {
                state.Dispose();
                _remoteSenderKeys.Remove(participantId);
            }
        }

        /// <summary>
        /// Re-keys the local sender key (should be done periodically or after participant changes).
        /// </summary>
        /// <returns>A CryptoResult indicating success and providing new distribution data.</returns>
        public CryptoResult<SenderKeyDistributionData> ReKey()
        {
            if (_disposed)
            {
                return CryptoResult<SenderKeyDistributionData>.Failure("GroupSession has been disposed");
            }

            CryptoResult<bool> initResult = Initialize();
            if (!initResult.IsSuccess)
            {
                return CryptoResult<SenderKeyDistributionData>.Failure($"Failed to re-key: {initResult.Error}");
            }

            return CreateDistributionMessage();
        }

        /// <summary>
        /// Gets all known participant IDs.
        /// </summary>
        /// <returns>The list of participant IDs.</returns>
        public IEnumerable<string> GetParticipants()
        {
            return _remoteSenderKeys.Keys;
        }

        /// <summary>
        /// Checks if a participant's sender key is known.
        /// </summary>
        /// <param name="participantId">The participant ID.</param>
        /// <returns>True if the participant's sender key is known.</returns>
        public bool HasParticipant(string participantId)
        {
            return _remoteSenderKeys.ContainsKey(participantId);
        }

        /// <summary>
        /// Disposes the group session.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes managed resources.
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _localSenderKey?.Dispose();
                    _localSenderKey = null;

                    foreach (SenderKeyState state in _remoteSenderKeys.Values)
                    {
                        state.Dispose();
                    }
                    _remoteSenderKeys.Clear();
                }
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Represents an encrypted group message.
    /// </summary>
    /// <remarks>
    /// Initializes a new GroupMessage.
    /// </remarks>
    public class GroupMessage(string groupId, string senderId, int keyId, int chainIndex,
        byte[] nonce, byte[] ciphertext, byte[] tag, byte[] signature)
    {
        /// <summary>
        /// Gets the group ID.
        /// </summary>
        public string GroupId { get; } = groupId;

        /// <summary>
        /// Gets the sender's participant ID.
        /// </summary>
        public string SenderId { get; } = senderId;

        /// <summary>
        /// Gets the sender key ID.
        /// </summary>
        public int KeyId { get; } = keyId;

        /// <summary>
        /// Gets the chain index (message counter).
        /// </summary>
        public int ChainIndex { get; } = chainIndex;

        /// <summary>
        /// Gets the encryption nonce.
        /// </summary>
        public byte[] Nonce { get; } = nonce;

        /// <summary>
        /// Gets the encrypted ciphertext.
        /// </summary>
        public byte[] Ciphertext { get; } = ciphertext;

        /// <summary>
        /// Gets the authentication tag.
        /// </summary>
        public byte[] Tag { get; } = tag;

        /// <summary>
        /// Gets the signature.
        /// </summary>
        public byte[] Signature { get; } = signature;

        /// <summary>
        /// Serializes the message to a byte array.
        /// </summary>
        public byte[] Serialize()
        {
            byte[] groupIdBytes = Encoding.UTF8.GetBytes(GroupId);
            byte[] senderIdBytes = Encoding.UTF8.GetBytes(SenderId);

            int totalLength = 4 + groupIdBytes.Length +
                             4 + senderIdBytes.Length +
                             4 + 4 + // KeyId + ChainIndex
                             4 + Nonce.Length +
                             4 + Ciphertext.Length +
                             4 + Tag.Length +
                             4 + Signature.Length;

            byte[] result = new byte[totalLength];
            int offset = 0;

            // Group ID
            BitConverter.GetBytes(groupIdBytes.Length).CopyTo(result, offset);
            offset += 4;
            groupIdBytes.CopyTo(result, offset);
            offset += groupIdBytes.Length;

            // Sender ID
            BitConverter.GetBytes(senderIdBytes.Length).CopyTo(result, offset);
            offset += 4;
            senderIdBytes.CopyTo(result, offset);
            offset += senderIdBytes.Length;

            // Key ID and Chain Index
            BitConverter.GetBytes(KeyId).CopyTo(result, offset);
            offset += 4;
            BitConverter.GetBytes(ChainIndex).CopyTo(result, offset);
            offset += 4;

            // Nonce
            BitConverter.GetBytes(Nonce.Length).CopyTo(result, offset);
            offset += 4;
            Nonce.CopyTo(result, offset);
            offset += Nonce.Length;

            // Ciphertext
            BitConverter.GetBytes(Ciphertext.Length).CopyTo(result, offset);
            offset += 4;
            Ciphertext.CopyTo(result, offset);
            offset += Ciphertext.Length;

            // Tag
            BitConverter.GetBytes(Tag.Length).CopyTo(result, offset);
            offset += 4;
            Tag.CopyTo(result, offset);
            offset += Tag.Length;

            // Signature
            BitConverter.GetBytes(Signature.Length).CopyTo(result, offset);
            offset += 4;
            Signature.CopyTo(result, offset);

            return result;
        }

        /// <summary>
        /// Deserializes a message from a byte array.
        /// </summary>
        public static CryptoResult<GroupMessage> Deserialize(byte[] data)
        {
            if (data == null || data.Length < 32)
            {
                return CryptoResult<GroupMessage>.Failure("Invalid message data");
            }

            try
            {
                int offset = 0;

                // Group ID
                int groupIdLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                string groupId = Encoding.UTF8.GetString(data, offset, groupIdLength);
                offset += groupIdLength;

                // Sender ID
                int senderIdLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                string senderId = Encoding.UTF8.GetString(data, offset, senderIdLength);
                offset += senderIdLength;

                // Key ID and Chain Index
                int keyId = BitConverter.ToInt32(data, offset);
                offset += 4;
                int chainIndex = BitConverter.ToInt32(data, offset);
                offset += 4;

                // Nonce
                int nonceLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                byte[] nonce = new byte[nonceLength];
                Array.Copy(data, offset, nonce, 0, nonceLength);
                offset += nonceLength;

                // Ciphertext
                int ciphertextLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                byte[] ciphertext = new byte[ciphertextLength];
                Array.Copy(data, offset, ciphertext, 0, ciphertextLength);
                offset += ciphertextLength;

                // Tag
                int tagLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                byte[] tag = new byte[tagLength];
                Array.Copy(data, offset, tag, 0, tagLength);
                offset += tagLength;

                // Signature
                int signatureLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                byte[] signature = new byte[signatureLength];
                Array.Copy(data, offset, signature, 0, signatureLength);

                return CryptoResult<GroupMessage>.Success(new GroupMessage(
                    groupId, senderId, keyId, chainIndex, nonce, ciphertext, tag, signature));
            }
            catch (Exception ex)
            {
                return CryptoResult<GroupMessage>.Failure($"Failed to deserialize: {ex.Message}");
            }
        }
    }
}
#endif
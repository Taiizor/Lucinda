// <copyright file="SecureMessaging.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using Lucinda.Abstractions;
using Lucinda.KeyExchange;
using Lucinda.KeyManagement;
using Lucinda.Protocol.DoubleRatchet;
using Lucinda.Protocol.X3DH;
using Lucinda.Utilities;
using System.Collections.Concurrent;
using System.Text;

namespace Lucinda
{
    /// <summary>
    /// Provides high-level secure messaging operations with Signal Protocol-like security.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <see cref="SecureMessaging"/> class provides:
    /// <list type="bullet">
    /// <item><description>X3DH key agreement for session establishment</description></item>
    /// <item><description>Double Ratchet for forward-secure messaging</description></item>
    /// <item><description>Session management for multiple conversations</description></item>
    /// <item><description>Automatic key rotation and management</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Key security properties:
    /// <list type="bullet">
    /// <item><description>Forward Secrecy: Past messages remain secure if keys are compromised</description></item>
    /// <item><description>Post-Compromise Security: Future messages become secure after compromise</description></item>
    /// <item><description>Asynchronous: Sessions can be established with offline recipients</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Alice setup
    /// using var alice = new SecureMessaging();
    /// var aliceIdentity = alice.GenerateIdentityKeyPair();
    /// var aliceBundle = alice.GeneratePreKeyBundle();
    /// 
    /// // Bob setup
    /// using var bob = new SecureMessaging();
    /// var bobIdentity = bob.GenerateIdentityKeyPair();
    /// var bobBundle = bob.GeneratePreKeyBundle();
    /// 
    /// // Alice initiates session with Bob using his pre-key bundle
    /// alice.InitializeSession("bob", bobBundle.Value.Bundle);
    /// 
    /// // Alice sends a message
    /// var encrypted = alice.SendMessage("bob", "Hello Bob!");
    /// 
    /// // Bob creates session from initial message and decrypts
    /// var initialMessage = alice.GetInitialMessageData("bob");
    /// bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);
    /// var decrypted = bob.ReceiveMessage("alice", encrypted.Value);
    /// </code>
    /// </example>
    /// <remarks>
    /// Initializes a new instance of the <see cref="SecureMessaging"/> class with specified options.
    /// </remarks>
    /// <param name="options">The configuration options.</param>
    public sealed class SecureMessaging(SecureMessagingOptions options) : IDisposable
    {
        private readonly SecureMessagingOptions _options = options ?? throw new ArgumentNullException(nameof(options));
        private readonly X3DHKeyAgreement _x3dh = new(options.Curve);
        private readonly DoubleRatchet _doubleRatchet = new(options.Curve, options.MaxSkipMessageKeys);
        private readonly InMemorySessionStorage _sessionStorage = new();

        private readonly ConcurrentDictionary<string, RatchetState> _activeSessions = new();
        private readonly ConcurrentDictionary<string, string> _recipientToSessionMap = new();
        private readonly ConcurrentDictionary<string, InitialMessageData> _pendingInitialMessages = new();

        private AsymmetricKeyPair? _identityKeyPair;
        private PreKeyBundleWithPrivateKeys? _preKeyBundle;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecureMessaging"/> class with default options.
        /// </summary>
        public SecureMessaging()
            : this(new SecureMessagingOptions())
        {
        }

        /// <summary>
        /// Gets a value indicating whether an identity key pair has been generated.
        /// </summary>
        public bool HasIdentity => _identityKeyPair != null;

        /// <summary>
        /// Gets a value indicating whether a pre-key bundle has been generated.
        /// </summary>
        public bool HasPreKeyBundle => _preKeyBundle != null;

        /// <summary>
        /// Generates a new identity key pair.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the identity key pair on success.
        /// </returns>
        /// <remarks>
        /// The identity key is a long-term key that represents the user's cryptographic identity.
        /// It should be generated once and stored securely.
        /// </remarks>
        public CryptoResult<AsymmetricKeyPair> GenerateIdentityKeyPair()
        {
            ThrowIfDisposed();

            try
            {
                using EcdhKeyExchange ecdh = new(_options.Curve);
                CryptoResult<AsymmetricKeyPair> result = ecdh.GenerateKeyPair();

                if (result.IsSuccess)
                {
                    _identityKeyPair = result.Value;
                }

                return result;
            }
            catch (Exception ex)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure($"Failed to generate identity key pair: {ex.Message}");
            }
        }

        /// <summary>
        /// Sets an existing identity key pair.
        /// </summary>
        /// <param name="keyPair">The identity key pair to use.</param>
        /// <returns>A result indicating success or failure.</returns>
        public CryptoResult<bool> SetIdentityKeyPair(AsymmetricKeyPair keyPair)
        {
            ThrowIfDisposed();

            if (keyPair == null)
            {
                return CryptoResult<bool>.Failure("Key pair cannot be null.");
            }

            _identityKeyPair = keyPair;
            return CryptoResult<bool>.Success(true);
        }

        /// <summary>
        /// Gets the identity public key.
        /// </summary>
        /// <returns>The identity public key bytes.</returns>
        public CryptoResult<byte[]> GetIdentityPublicKey()
        {
            ThrowIfDisposed();

            if (_identityKeyPair == null)
            {
                return CryptoResult<byte[]>.Failure("Identity key pair not generated.");
            }

            return CryptoResult<byte[]>.Success([.. _identityKeyPair.PublicKey]);
        }

        /// <summary>
        /// Generates a new pre-key bundle for publishing.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the pre-key bundle with private keys.
        /// </returns>
        /// <remarks>
        /// The pre-key bundle should be published to a server so other users can
        /// establish sessions when you are offline.
        /// </remarks>
        public CryptoResult<PreKeyBundleWithPrivateKeys> GeneratePreKeyBundle()
        {
            ThrowIfDisposed();

            if (_identityKeyPair == null)
            {
                return CryptoResult<PreKeyBundleWithPrivateKeys>.Failure(
                    "Identity key pair must be generated first.");
            }

            try
            {
                int signedPreKeyId = 1; // In production, this should be incremented
                int[] oneTimePreKeyIds = [.. Enumerable.Range(1, _options.OneTimePreKeyCount)];

                CryptoResult<PreKeyBundleWithPrivateKeys> result = _x3dh.GeneratePreKeyBundle(
                    _identityKeyPair,
                    signedPreKeyId,
                    oneTimePreKeyIds);

                if (result.IsSuccess)
                {
                    _preKeyBundle = result.Value;
                }

                return result;
            }
            catch (Exception ex)
            {
                return CryptoResult<PreKeyBundleWithPrivateKeys>.Failure(
                    $"Failed to generate pre-key bundle: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the public pre-key bundle for publishing.
        /// </summary>
        /// <returns>The public pre-key bundle.</returns>
        public CryptoResult<PreKeyBundle> GetPublicPreKeyBundle()
        {
            ThrowIfDisposed();

            if (_preKeyBundle == null)
            {
                return CryptoResult<PreKeyBundle>.Failure("Pre-key bundle not generated.");
            }

            return CryptoResult<PreKeyBundle>.Success(_preKeyBundle.Bundle);
        }

        /// <summary>
        /// Initializes a new session with a recipient using their pre-key bundle.
        /// </summary>
        /// <param name="recipientId">The recipient's unique identifier.</param>
        /// <param name="recipientBundle">The recipient's pre-key bundle.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the session ID on success.
        /// </returns>
        public CryptoResult<string> InitializeSession(string recipientId, PreKeyBundle recipientBundle)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(recipientId))
            {
                return CryptoResult<string>.Failure("Recipient ID cannot be null or empty.");
            }

            if (recipientBundle == null)
            {
                return CryptoResult<string>.Failure("Recipient bundle cannot be null.");
            }

            if (_identityKeyPair == null)
            {
                return CryptoResult<string>.Failure("Identity key pair must be generated first.");
            }

            try
            {
                // Perform X3DH key agreement
                CryptoResult<X3DHResult> x3dhResult = _x3dh.InitiatorAgree(_identityKeyPair, recipientBundle);
                if (x3dhResult.IsFailure)
                {
                    return CryptoResult<string>.Failure($"X3DH failed: {x3dhResult.Error}");
                }

                // Initialize Double Ratchet as initiator
                CryptoResult<RatchetState> ratchetResult = _doubleRatchet.InitializeAsInitiator(
                    x3dhResult.Value.SharedSecret,
                    recipientBundle.SignedPreKey);

                // Clear shared secret
                CryptoHelpers.SecureClear(x3dhResult.Value.SharedSecret);

                if (ratchetResult.IsFailure)
                {
                    return CryptoResult<string>.Failure($"Ratchet initialization failed: {ratchetResult.Error}");
                }

                // Generate session ID
                string sessionId = GenerateSessionId();

                // Store session
                _activeSessions[sessionId] = ratchetResult.Value;
                _recipientToSessionMap[recipientId] = sessionId;

                // Store initial message data for the recipient
                _pendingInitialMessages[recipientId] = new InitialMessageData(
                    _identityKeyPair.PublicKey,
                    x3dhResult.Value.EphemeralPublicKey!,
                    x3dhResult.Value.UsedOneTimePreKeyId);

                return CryptoResult<string>.Success(sessionId);
            }
            catch (Exception ex)
            {
                return CryptoResult<string>.Failure($"Session initialization failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the initial message data to send to the recipient.
        /// </summary>
        /// <param name="recipientId">The recipient's identifier.</param>
        /// <returns>The initial message data.</returns>
        public CryptoResult<InitialMessageData> GetInitialMessageData(string recipientId)
        {
            ThrowIfDisposed();

            if (_pendingInitialMessages.TryGetValue(recipientId, out InitialMessageData? data))
            {
                return CryptoResult<InitialMessageData>.Success(data);
            }

            return CryptoResult<InitialMessageData>.Failure($"No pending initial message for: {recipientId}");
        }

        /// <summary>
        /// Creates a session from an incoming initial message.
        /// </summary>
        /// <param name="senderId">The sender's unique identifier.</param>
        /// <param name="initialMessage">The initial message data from the sender.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the session ID on success.
        /// </returns>
        public CryptoResult<string> CreateSessionFromInitialMessage(string senderId, InitialMessageData initialMessage)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(senderId))
            {
                return CryptoResult<string>.Failure("Sender ID cannot be null or empty.");
            }

            if (initialMessage == null)
            {
                return CryptoResult<string>.Failure("Initial message cannot be null.");
            }

            if (_identityKeyPair == null)
            {
                return CryptoResult<string>.Failure("Identity key pair must be generated first.");
            }

            if (_preKeyBundle == null)
            {
                return CryptoResult<string>.Failure("Pre-key bundle must be generated first.");
            }

            try
            {
                // Get the one-time pre-key if used
                AsymmetricKeyPair? oneTimePreKeyPair = null;
                if (initialMessage.UsedOneTimePreKeyId.HasValue)
                {
                    byte[]? otpkPrivate = _preKeyBundle.ConsumeOneTimePreKeyPrivate(
                        initialMessage.UsedOneTimePreKeyId.Value);

                    if (otpkPrivate != null)
                    {
                        // We need to reconstruct the key pair - for simplicity, we create a new one
                        // In production, you'd want to store and retrieve the full key pair
                        oneTimePreKeyPair = new AsymmetricKeyPair([], otpkPrivate);
                    }
                }

                // Create signed pre-key pair
                AsymmetricKeyPair signedPreKeyPair = new(
                    _preKeyBundle.Bundle.SignedPreKey,
                    _preKeyBundle.SignedPreKeyPrivate);

                // Perform X3DH key agreement as responder
                CryptoResult<X3DHResult> x3dhResult = _x3dh.ResponderAgree(
                    _identityKeyPair,
                    signedPreKeyPair,
                    oneTimePreKeyPair,
                    initialMessage.SenderIdentityPublicKey,
                    initialMessage.SenderEphemeralPublicKey);

                if (x3dhResult.IsFailure)
                {
                    return CryptoResult<string>.Failure($"X3DH failed: {x3dhResult.Error}");
                }

                // Initialize Double Ratchet as responder using the signed pre-key pair
                // This is important because Alice (initiator) used our signed pre-key's public key
                // as the initial remote public key for her ratchet
                CryptoResult<RatchetState> ratchetResult = _doubleRatchet.InitializeAsResponder(
                    x3dhResult.Value.SharedSecret,
                    signedPreKeyPair);

                // Clear shared secret
                CryptoHelpers.SecureClear(x3dhResult.Value.SharedSecret);

                if (ratchetResult.IsFailure)
                {
                    return CryptoResult<string>.Failure($"Ratchet initialization failed: {ratchetResult.Error}");
                }

                // Generate session ID
                string sessionId = GenerateSessionId();

                // Store session
                _activeSessions[sessionId] = ratchetResult.Value;
                _recipientToSessionMap[senderId] = sessionId;

                return CryptoResult<string>.Success(sessionId);
            }
            catch (Exception ex)
            {
                return CryptoResult<string>.Failure($"Session creation failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Sends an encrypted message to a recipient.
        /// </summary>
        /// <param name="recipientId">The recipient's identifier.</param>
        /// <param name="message">The plaintext message to send.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the encrypted message bytes.
        /// </returns>
        public CryptoResult<byte[]> SendMessage(string recipientId, string message)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(message))
            {
                return CryptoResult<byte[]>.Failure("Message cannot be null or empty.");
            }

            return SendMessage(recipientId, Encoding.UTF8.GetBytes(message));
        }

        /// <summary>
        /// Sends encrypted data to a recipient.
        /// </summary>
        /// <param name="recipientId">The recipient's identifier.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the encrypted message bytes.
        /// </returns>
        public CryptoResult<byte[]> SendMessage(string recipientId, byte[] data)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(recipientId))
            {
                return CryptoResult<byte[]>.Failure("Recipient ID cannot be null or empty.");
            }

            if (data == null || data.Length == 0)
            {
                return CryptoResult<byte[]>.Failure("Data cannot be null or empty.");
            }

            if (!_recipientToSessionMap.TryGetValue(recipientId, out string? sessionId) ||
                !_activeSessions.TryGetValue(sessionId!, out RatchetState? state))
            {
                return CryptoResult<byte[]>.Failure($"No active session for recipient: {recipientId}");
            }

            try
            {
                CryptoResult<RatchetMessage> encryptResult = _doubleRatchet.Encrypt(state, data);
                if (encryptResult.IsFailure)
                {
                    return CryptoResult<byte[]>.Failure($"Encryption failed: {encryptResult.Error}");
                }

                return CryptoResult<byte[]>.Success(encryptResult.Value.ToBytes());
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Send failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Receives and decrypts a message from a sender.
        /// </summary>
        /// <param name="senderId">The sender's identifier.</param>
        /// <param name="encryptedMessage">The encrypted message bytes.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted message string.
        /// </returns>
        public CryptoResult<string> ReceiveMessage(string senderId, byte[] encryptedMessage)
        {
            CryptoResult<byte[]> result = ReceiveData(senderId, encryptedMessage);
            if (result.IsFailure)
            {
                return CryptoResult<string>.Failure(result.Error);
            }

            try
            {
                return CryptoResult<string>.Success(Encoding.UTF8.GetString(result.Value));
            }
            catch (Exception ex)
            {
                return CryptoResult<string>.Failure($"Failed to decode message: {ex.Message}");
            }
        }

        /// <summary>
        /// Receives and decrypts data from a sender.
        /// </summary>
        /// <param name="senderId">The sender's identifier.</param>
        /// <param name="encryptedData">The encrypted data bytes.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted data.
        /// </returns>
        public CryptoResult<byte[]> ReceiveData(string senderId, byte[] encryptedData)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(senderId))
            {
                return CryptoResult<byte[]>.Failure("Sender ID cannot be null or empty.");
            }

            if (encryptedData == null || encryptedData.Length == 0)
            {
                return CryptoResult<byte[]>.Failure("Encrypted data cannot be null or empty.");
            }

            if (!_recipientToSessionMap.TryGetValue(senderId, out string? sessionId) ||
                !_activeSessions.TryGetValue(sessionId!, out RatchetState? state))
            {
                return CryptoResult<byte[]>.Failure($"No active session for sender: {senderId}");
            }

            try
            {
                RatchetMessage message = RatchetMessage.FromBytes(encryptedData);
                return _doubleRatchet.Decrypt(state, message);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Receive failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Checks if a session exists for the specified recipient.
        /// </summary>
        /// <param name="recipientId">The recipient's identifier.</param>
        /// <returns>True if a session exists.</returns>
        public CryptoResult<bool> HasSession(string recipientId)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(recipientId))
            {
                return CryptoResult<bool>.Failure("Recipient ID cannot be null or empty.");
            }

            return CryptoResult<bool>.Success(_recipientToSessionMap.ContainsKey(recipientId));
        }

        /// <summary>
        /// Deletes a session with the specified recipient.
        /// </summary>
        /// <param name="recipientId">The recipient's identifier.</param>
        /// <returns>A result indicating success or failure.</returns>
        public CryptoResult<bool> DeleteSession(string recipientId)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(recipientId))
            {
                return CryptoResult<bool>.Failure("Recipient ID cannot be null or empty.");
            }

            try
            {
                if (_recipientToSessionMap.TryRemove(recipientId, out string? sessionId))
                {
                    if (_activeSessions.TryRemove(sessionId!, out RatchetState? state))
                    {
                        state.Dispose();
                    }
                    _pendingInitialMessages.TryRemove(recipientId, out _);
                    return CryptoResult<bool>.Success(true);
                }

                return CryptoResult<bool>.Success(false);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to delete session: {ex.Message}");
            }
        }

        /// <summary>
        /// Lists all active session recipient IDs.
        /// </summary>
        /// <returns>An array of recipient IDs with active sessions.</returns>
        public CryptoResult<string[]> ListActiveSessions()
        {
            ThrowIfDisposed();

            return CryptoResult<string[]>.Success([.. _recipientToSessionMap.Keys]);
        }

        private static string GenerateSessionId()
        {
            return Guid.NewGuid().ToString("N");
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(SecureMessaging));
            }
#endif
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (!_disposed)
            {
                // Dispose all active sessions
                foreach (RatchetState state in _activeSessions.Values)
                {
                    state.Dispose();
                }

                _activeSessions.Clear();
                _recipientToSessionMap.Clear();
                _pendingInitialMessages.Clear();

                _x3dh.Dispose();
                _doubleRatchet.Dispose();
                _sessionStorage.Dispose();

                // Clear identity key
                if (_identityKeyPair?.PrivateKey != null)
                {
                    CryptoHelpers.SecureClear(_identityKeyPair.PrivateKey);
                }

                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Contains the data that must be sent with the first message to a recipient.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="InitialMessageData"/> class.
    /// </remarks>
    public sealed class InitialMessageData(
        byte[] senderIdentityPublicKey,
        byte[] senderEphemeralPublicKey,
        int? usedOneTimePreKeyId)
    {
        /// <summary>
        /// Gets the sender's identity public key.
        /// </summary>
        public byte[] SenderIdentityPublicKey { get; } = senderIdentityPublicKey;

        /// <summary>
        /// Gets the sender's ephemeral public key for X3DH.
        /// </summary>
        public byte[] SenderEphemeralPublicKey { get; } = senderEphemeralPublicKey;

        /// <summary>
        /// Gets the ID of the one-time pre-key that was used, if any.
        /// </summary>
        public int? UsedOneTimePreKeyId { get; } = usedOneTimePreKeyId;

        /// <summary>
        /// Serializes the initial message data.
        /// </summary>
        public byte[] ToBytes()
        {
            using MemoryStream ms = new();
            using BinaryWriter writer = new(ms);

            writer.Write((byte)1); // Version

            writer.Write(SenderIdentityPublicKey.Length);
            writer.Write(SenderIdentityPublicKey);

            writer.Write(SenderEphemeralPublicKey.Length);
            writer.Write(SenderEphemeralPublicKey);

            writer.Write(UsedOneTimePreKeyId.HasValue);
            if (UsedOneTimePreKeyId.HasValue)
            {
                writer.Write(UsedOneTimePreKeyId.Value);
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializes initial message data.
        /// </summary>
        public static InitialMessageData FromBytes(byte[] data)
        {
            using MemoryStream ms = new(data);
            using BinaryReader reader = new(ms);

            byte version = reader.ReadByte();
            if (version != 1)
            {
                throw new InvalidDataException($"Unsupported version: {version}");
            }

            int idKeyLength = reader.ReadInt32();
            byte[] idKey = reader.ReadBytes(idKeyLength);

            int ephKeyLength = reader.ReadInt32();
            byte[] ephKey = reader.ReadBytes(ephKeyLength);

            int? otpkId = null;
            if (reader.ReadBoolean())
            {
                otpkId = reader.ReadInt32();
            }

            return new InitialMessageData(idKey, ephKey, otpkId);
        }
    }
}
#endif
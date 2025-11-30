// <copyright file="BlazorSecureMessaging.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;
using Lucinda.Blazor.Protocol.DoubleRatchet;
using Lucinda.Blazor.Protocol.X3DH;
using System.Collections.Concurrent;
using System.Text;

namespace Lucinda.Blazor;

/// <summary>
/// Provides high-level secure messaging operations with Signal Protocol-like security
/// for Blazor WebAssembly applications.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="BlazorSecureMessaging"/> class provides:
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
/// @inject BlazorSecureMessaging SecureMessaging
/// 
/// // Initialize identity
/// await SecureMessaging.GenerateIdentityKeyPairAsync();
/// var aliceBundle = await SecureMessaging.GeneratePreKeyBundleAsync();
/// 
/// // Alice initiates session with Bob using his pre-key bundle
/// await SecureMessaging.InitializeSessionAsync("bob", bobBundle);
/// 
/// // Alice sends a message
/// var encrypted = await SecureMessaging.SendMessageAsync("bob", "Hello Bob!");
/// 
/// // Bob creates session from initial message and decrypts
/// var decrypted = await SecureMessaging.ReceiveMessageAsync("alice", encrypted);
/// </code>
/// </example>
public sealed class BlazorSecureMessaging : IAsyncDisposable
{
    private readonly WebCryptoInterop _interop;
    private readonly BlazorSecureMessagingOptions _options;
    private readonly BlazorX3DHKeyAgreement _x3dh;
    private readonly BlazorDoubleRatchet _doubleRatchet;
    private readonly IBlazorSessionStorage? _sessionStorage;

    private readonly ConcurrentDictionary<string, BlazorRatchetState> _activeSessions = new();
    private readonly ConcurrentDictionary<string, string> _recipientToSessionMap = new();
    private readonly ConcurrentDictionary<string, BlazorInitialMessageData> _pendingInitialMessages = new();

    private BlazorAsymmetricKeyPair? _identityKeyPair;
    private BlazorPreKeyBundleWithPrivateKeys? _preKeyBundle;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorSecureMessaging"/> class.
    /// </summary>
    /// <param name="interop">The Web Crypto interop service.</param>
    public BlazorSecureMessaging(WebCryptoInterop interop)
        : this(interop, new BlazorSecureMessagingOptions(), null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorSecureMessaging"/> class with options.
    /// </summary>
    /// <param name="interop">The Web Crypto interop service.</param>
    /// <param name="options">The configuration options.</param>
    public BlazorSecureMessaging(WebCryptoInterop interop, BlazorSecureMessagingOptions options)
        : this(interop, options, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorSecureMessaging"/> class with options and session storage.
    /// </summary>
    /// <param name="interop">The Web Crypto interop service.</param>
    /// <param name="options">The configuration options.</param>
    /// <param name="sessionStorage">Optional session storage for persistence.</param>
    public BlazorSecureMessaging(
        WebCryptoInterop interop,
        BlazorSecureMessagingOptions options,
        IBlazorSessionStorage? sessionStorage)
    {
        ArgumentNullException.ThrowIfNull(interop);
        ArgumentNullException.ThrowIfNull(options);

        _interop = interop;
        _options = options;
        _sessionStorage = sessionStorage;

        _x3dh = new BlazorX3DHKeyAgreement(interop, options.CurveName, options.HashAlgorithm);
        _doubleRatchet = new BlazorDoubleRatchet(interop, options.CurveName, options.HashAlgorithm, options.MaxSkipMessageKeys);
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
    /// Gets the identity public key.
    /// </summary>
    /// <returns>The identity public key bytes, or null if not set.</returns>
    public byte[]? GetIdentityPublicKey()
    {
        ThrowIfDisposed();
        return _identityKeyPair?.PublicKey;
    }

    /// <summary>
    /// Generates a new identity key pair.
    /// </summary>
    /// <returns>The generated identity key pair.</returns>
    /// <remarks>
    /// The identity key is a long-term key that represents the user's cryptographic identity.
    /// It should be generated once and stored securely.
    /// </remarks>
    public async Task<BlazorAsymmetricKeyPair> GenerateIdentityKeyPairAsync()
    {
        ThrowIfDisposed();

        _identityKeyPair = await _x3dh.GenerateIdentityKeyPairAsync().ConfigureAwait(false);
        return _identityKeyPair;
    }

    /// <summary>
    /// Sets an existing identity key pair.
    /// </summary>
    /// <param name="keyPair">The identity key pair to use.</param>
    public void SetIdentityKeyPair(BlazorAsymmetricKeyPair keyPair)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(keyPair);
        _identityKeyPair = keyPair;
    }

    /// <summary>
    /// Generates a new pre-key bundle for publishing.
    /// </summary>
    /// <returns>The pre-key bundle with private keys.</returns>
    /// <remarks>
    /// The pre-key bundle should be published to a server so other users can
    /// establish sessions when you are offline.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Thrown when identity key pair is not set.</exception>
    public async Task<BlazorPreKeyBundleWithPrivateKeys> GeneratePreKeyBundleAsync()
    {
        ThrowIfDisposed();

        if (_identityKeyPair == null)
        {
            throw new InvalidOperationException("Identity key pair must be generated first.");
        }

        int signedPreKeyId = 1; // In production, this should be incremented
        int[] oneTimePreKeyIds = Enumerable.Range(1, _options.OneTimePreKeyCount).ToArray();

        _preKeyBundle = await _x3dh.GeneratePreKeyBundleAsync(
            _identityKeyPair,
            signedPreKeyId,
            oneTimePreKeyIds).ConfigureAwait(false);

        return _preKeyBundle;
    }

    /// <summary>
    /// Gets the public pre-key bundle for publishing.
    /// </summary>
    /// <returns>The public pre-key bundle.</returns>
    /// <exception cref="InvalidOperationException">Thrown when pre-key bundle is not generated.</exception>
    public BlazorPreKeyBundle GetPublicPreKeyBundle()
    {
        ThrowIfDisposed();

        if (_preKeyBundle == null)
        {
            throw new InvalidOperationException("Pre-key bundle not generated.");
        }

        return _preKeyBundle.Bundle;
    }

    /// <summary>
    /// Initializes a new session with a recipient using their pre-key bundle.
    /// </summary>
    /// <param name="recipientId">The recipient's unique identifier.</param>
    /// <param name="recipientBundle">The recipient's pre-key bundle.</param>
    /// <returns>The session ID.</returns>
    public async Task<string> InitializeSessionAsync(string recipientId, BlazorPreKeyBundle recipientBundle)
    {
        ThrowIfDisposed();

        if (string.IsNullOrEmpty(recipientId))
        {
            throw new ArgumentException("Recipient ID cannot be null or empty.", nameof(recipientId));
        }

        ArgumentNullException.ThrowIfNull(recipientBundle);

        if (_identityKeyPair == null)
        {
            throw new InvalidOperationException("Identity key pair must be generated first.");
        }

        // Perform X3DH key agreement
        BlazorX3DHResult x3dhResult = await _x3dh.InitiatorAgreeAsync(_identityKeyPair, recipientBundle)
            .ConfigureAwait(false);

        // Initialize Double Ratchet as initiator
        BlazorRatchetState ratchetState = await _doubleRatchet.InitializeAsInitiatorAsync(
            x3dhResult.SharedSecret,
            recipientBundle.SignedPreKey).ConfigureAwait(false);

        // Clear shared secret
        Array.Clear(x3dhResult.SharedSecret);

        // Generate session ID
        string sessionId = GenerateSessionId();

        // Store session
        _activeSessions[sessionId] = ratchetState;
        _recipientToSessionMap[recipientId] = sessionId;

        // Store initial message data for the recipient
        if (x3dhResult.EphemeralPublicKey != null)
        {
            _pendingInitialMessages[recipientId] = new BlazorInitialMessageData(
                _identityKeyPair.PublicKey,
                x3dhResult.EphemeralPublicKey,
                x3dhResult.UsedOneTimePreKeyId);
        }

        // Persist session if storage is available
        if (_sessionStorage != null && _options.PersistSessions)
        {
            byte[] sessionData = SerializeRatchetState(ratchetState);
            await _sessionStorage.StoreSessionAsync(sessionId, sessionData).ConfigureAwait(false);
        }

        return sessionId;
    }

    /// <summary>
    /// Gets the initial message data to send to the recipient.
    /// </summary>
    /// <param name="recipientId">The recipient's identifier.</param>
    /// <returns>The initial message data.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no pending initial message exists.</exception>
    public BlazorInitialMessageData GetInitialMessageData(string recipientId)
    {
        ThrowIfDisposed();

        if (_pendingInitialMessages.TryGetValue(recipientId, out BlazorInitialMessageData? data))
        {
            return data;
        }

        throw new InvalidOperationException($"No pending initial message for: {recipientId}");
    }

    /// <summary>
    /// Creates a session from an incoming initial message.
    /// </summary>
    /// <param name="senderId">The sender's unique identifier.</param>
    /// <param name="initialMessage">The initial message data from the sender.</param>
    /// <returns>The session ID.</returns>
    public async Task<string> CreateSessionFromInitialMessageAsync(
        string senderId,
        BlazorInitialMessageData initialMessage)
    {
        ThrowIfDisposed();

        if (string.IsNullOrEmpty(senderId))
        {
            throw new ArgumentException("Sender ID cannot be null or empty.", nameof(senderId));
        }

        ArgumentNullException.ThrowIfNull(initialMessage);

        if (_identityKeyPair == null)
        {
            throw new InvalidOperationException("Identity key pair must be generated first.");
        }

        if (_preKeyBundle == null)
        {
            throw new InvalidOperationException("Pre-key bundle must be generated first.");
        }

        // Get the one-time pre-key if used
        BlazorAsymmetricKeyPair? oneTimePreKeyPair = null;
        if (initialMessage.UsedOneTimePreKeyId.HasValue)
        {
            byte[]? oneTimePrivate = _preKeyBundle.GetOneTimePreKeyPrivate(initialMessage.UsedOneTimePreKeyId.Value);

            if (oneTimePrivate != null)
            {
                // Find the corresponding public key from the bundle
                byte[]? oneTimePublic = _preKeyBundle.Bundle.OneTimePreKey;
                if (oneTimePublic != null)
                {
                    oneTimePreKeyPair = new BlazorAsymmetricKeyPair(oneTimePublic, oneTimePrivate);
                }

                // Remove used one-time pre-key if configured
                if (_options.AutoDeleteUsedOneTimePreKeys)
                {
                    _preKeyBundle.ConsumeOneTimePreKey(initialMessage.UsedOneTimePreKeyId.Value);
                }
            }
        }

        // Create signed pre-key pair from bundle
        BlazorAsymmetricKeyPair signedPreKeyPair = new(
            _preKeyBundle.Bundle.SignedPreKey,
            _preKeyBundle.SignedPreKeyPrivate);

        // Perform X3DH key agreement as responder
        BlazorX3DHResult x3dhResult = await _x3dh.ResponderAgreeAsync(
            _identityKeyPair,
            signedPreKeyPair,
            oneTimePreKeyPair,
            initialMessage.SenderIdentityKey,
            initialMessage.SenderEphemeralKey).ConfigureAwait(false);

        // Initialize Double Ratchet as responder
        BlazorRatchetState ratchetState = await _doubleRatchet.InitializeAsResponderAsync(
            x3dhResult.SharedSecret,
            signedPreKeyPair).ConfigureAwait(false);

        // Clear shared secret
        Array.Clear(x3dhResult.SharedSecret);

        // Generate session ID
        string sessionId = GenerateSessionId();

        // Store session
        _activeSessions[sessionId] = ratchetState;
        _recipientToSessionMap[senderId] = sessionId;

        // Persist session if storage is available
        if (_sessionStorage != null && _options.PersistSessions)
        {
            byte[] sessionData = SerializeRatchetState(ratchetState);
            await _sessionStorage.StoreSessionAsync(sessionId, sessionData).ConfigureAwait(false);
        }

        return sessionId;
    }

    /// <summary>
    /// Sends an encrypted message to a recipient.
    /// </summary>
    /// <param name="recipientId">The recipient's identifier.</param>
    /// <param name="message">The message to send.</param>
    /// <returns>The encrypted message.</returns>
    public async Task<BlazorRatchetMessage> SendMessageAsync(string recipientId, string message)
    {
        ThrowIfDisposed();

        if (string.IsNullOrEmpty(message))
        {
            throw new ArgumentException("Message cannot be null or empty.", nameof(message));
        }

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        return await SendDataAsync(recipientId, messageBytes).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends encrypted binary data to a recipient.
    /// </summary>
    /// <param name="recipientId">The recipient's identifier.</param>
    /// <param name="data">The data to send.</param>
    /// <returns>The encrypted message.</returns>
    public async Task<BlazorRatchetMessage> SendDataAsync(string recipientId, byte[] data)
    {
        ThrowIfDisposed();

        if (string.IsNullOrEmpty(recipientId))
        {
            throw new ArgumentException("Recipient ID cannot be null or empty.", nameof(recipientId));
        }

        ArgumentNullException.ThrowIfNull(data);

        BlazorRatchetState state = await GetOrLoadSessionAsync(recipientId).ConfigureAwait(false);

        BlazorRatchetMessage encryptedMessage = await _doubleRatchet.EncryptAsync(state, data)
            .ConfigureAwait(false);

        // Persist updated session state
        if (_sessionStorage != null && _options.PersistSessions)
        {
            string sessionId = _recipientToSessionMap[recipientId];
            byte[] sessionData = SerializeRatchetState(state);
            await _sessionStorage.StoreSessionAsync(sessionId, sessionData).ConfigureAwait(false);
        }

        return encryptedMessage;
    }

    /// <summary>
    /// Receives and decrypts a message from a sender.
    /// </summary>
    /// <param name="senderId">The sender's identifier.</param>
    /// <param name="encryptedMessage">The encrypted message.</param>
    /// <returns>The decrypted message string.</returns>
    public async Task<string> ReceiveMessageAsync(string senderId, BlazorRatchetMessage encryptedMessage)
    {
        ThrowIfDisposed();

        byte[] decryptedData = await ReceiveDataAsync(senderId, encryptedMessage).ConfigureAwait(false);
        return Encoding.UTF8.GetString(decryptedData);
    }

    /// <summary>
    /// Receives and decrypts binary data from a sender.
    /// </summary>
    /// <param name="senderId">The sender's identifier.</param>
    /// <param name="encryptedMessage">The encrypted message.</param>
    /// <returns>The decrypted data.</returns>
    public async Task<byte[]> ReceiveDataAsync(string senderId, BlazorRatchetMessage encryptedMessage)
    {
        ThrowIfDisposed();

        if (string.IsNullOrEmpty(senderId))
        {
            throw new ArgumentException("Sender ID cannot be null or empty.", nameof(senderId));
        }

        ArgumentNullException.ThrowIfNull(encryptedMessage);

        BlazorRatchetState state = await GetOrLoadSessionAsync(senderId).ConfigureAwait(false);

        byte[] decryptedData = await _doubleRatchet.DecryptAsync(state, encryptedMessage)
            .ConfigureAwait(false);

        // Persist updated session state
        if (_sessionStorage != null && _options.PersistSessions)
        {
            string sessionId = _recipientToSessionMap[senderId];
            byte[] sessionData = SerializeRatchetState(state);
            await _sessionStorage.StoreSessionAsync(sessionId, sessionData).ConfigureAwait(false);
        }

        return decryptedData;
    }

    /// <summary>
    /// Checks if a session exists for a given recipient.
    /// </summary>
    /// <param name="recipientId">The recipient's identifier.</param>
    /// <returns>True if a session exists, false otherwise.</returns>
    public bool HasSession(string recipientId)
    {
        ThrowIfDisposed();
        return _recipientToSessionMap.ContainsKey(recipientId);
    }

    /// <summary>
    /// Gets all active session IDs.
    /// </summary>
    /// <returns>A collection of session IDs.</returns>
    public IReadOnlyCollection<string> GetActiveSessions()
    {
        ThrowIfDisposed();
        return _activeSessions.Keys.ToList().AsReadOnly();
    }

    /// <summary>
    /// Gets all recipient IDs with active sessions.
    /// </summary>
    /// <returns>A collection of recipient IDs.</returns>
    public IReadOnlyCollection<string> GetActiveRecipients()
    {
        ThrowIfDisposed();
        return _recipientToSessionMap.Keys.ToList().AsReadOnly();
    }

    /// <summary>
    /// Removes a session for a recipient.
    /// </summary>
    /// <param name="recipientId">The recipient's identifier.</param>
    /// <returns>True if the session was removed, false if it didn't exist.</returns>
    public async Task<bool> RemoveSessionAsync(string recipientId)
    {
        ThrowIfDisposed();

        if (!_recipientToSessionMap.TryRemove(recipientId, out string? sessionId))
        {
            return false;
        }

        _activeSessions.TryRemove(sessionId, out _);
        _pendingInitialMessages.TryRemove(recipientId, out _);

        // Remove from storage
        if (_sessionStorage != null)
        {
            await _sessionStorage.DeleteSessionAsync(sessionId).ConfigureAwait(false);
        }

        return true;
    }

    /// <summary>
    /// Clears all sessions.
    /// </summary>
    public async Task ClearAllSessionsAsync()
    {
        ThrowIfDisposed();

        string[] sessionIds = [.. _activeSessions.Keys];

        _activeSessions.Clear();
        _recipientToSessionMap.Clear();
        _pendingInitialMessages.Clear();

        // Clear from storage
        if (_sessionStorage != null)
        {
            foreach (string sessionId in sessionIds)
            {
                await _sessionStorage.DeleteSessionAsync(sessionId).ConfigureAwait(false);
            }
        }
    }

    private async Task<BlazorRatchetState> GetOrLoadSessionAsync(string recipientId)
    {
        if (!_recipientToSessionMap.TryGetValue(recipientId, out string? sessionId))
        {
            throw new InvalidOperationException($"No session found for recipient: {recipientId}");
        }

        if (_activeSessions.TryGetValue(sessionId, out BlazorRatchetState? state))
        {
            return state;
        }

        // Try to load from storage
        if (_sessionStorage != null)
        {
            byte[]? sessionData = await _sessionStorage.LoadSessionAsync(sessionId).ConfigureAwait(false);
            if (sessionData != null)
            {
                state = DeserializeRatchetState(sessionData);
                _activeSessions[sessionId] = state;
                return state;
            }
        }

        throw new InvalidOperationException($"Session state not found for session: {sessionId}");
    }

    private static string GenerateSessionId()
    {
        return Guid.NewGuid().ToString("N");
    }

    private static byte[] SerializeRatchetState(BlazorRatchetState state)
    {
        // Simple binary serialization
        using MemoryStream ms = new();
        using BinaryWriter writer = new(ms);

        WriteByteArray(writer, state.DHSendingPublicKey);
        WriteByteArray(writer, state.DHSendingPrivateKey);
        WriteByteArray(writer, state.DHReceivingPublicKey);
        WriteByteArray(writer, state.RootKey);
        WriteByteArray(writer, state.SendingChainKey);
        WriteByteArray(writer, state.ReceivingChainKey);
        writer.Write(state.SendingMessageNumber);
        writer.Write(state.ReceivingMessageNumber);
        writer.Write(state.PreviousSendingChainLength);

        return ms.ToArray();
    }

    private static BlazorRatchetState DeserializeRatchetState(byte[] data)
    {
        using MemoryStream ms = new(data);
        using BinaryReader reader = new(ms);

        return new BlazorRatchetState
        {
            DHSendingPublicKey = ReadByteArray(reader),
            DHSendingPrivateKey = ReadByteArray(reader),
            DHReceivingPublicKey = ReadByteArray(reader),
            RootKey = ReadByteArray(reader),
            SendingChainKey = ReadByteArray(reader),
            ReceivingChainKey = ReadByteArray(reader),
            SendingMessageNumber = reader.ReadInt32(),
            ReceivingMessageNumber = reader.ReadInt32(),
            PreviousSendingChainLength = reader.ReadInt32()
        };
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

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Clear sensitive data
        _activeSessions.Clear();
        _recipientToSessionMap.Clear();
        _pendingInitialMessages.Clear();

        if (_x3dh is IAsyncDisposable x3dhDisposable)
        {
            await x3dhDisposable.DisposeAsync().ConfigureAwait(false);
        }

        if (_doubleRatchet is IAsyncDisposable ratchetDisposable)
        {
            await ratchetDisposable.DisposeAsync().ConfigureAwait(false);
        }
    }
}

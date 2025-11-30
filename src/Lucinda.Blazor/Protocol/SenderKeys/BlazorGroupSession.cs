// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.Protocol.SenderKeys;

/// <summary>
/// Manages a group messaging session using the Sender Keys protocol for Blazor WebAssembly.
/// </summary>
public sealed class BlazorGroupSession : IAsyncDisposable
{
    private readonly WebCryptoInterop _cryptoInterop;
    private readonly string _curve;
    private readonly string _hashAlgorithm;
    private BlazorSenderKeyState? _localSenderKey;
    private readonly Dictionary<string, BlazorSenderKeyState> _remoteSenderKeys = [];
    private bool _disposed;

    private const int NonceSize = 12;
    private const int KeySize = 32;

    private static readonly byte[] MessageKeyInfo = System.Text.Encoding.UTF8.GetBytes("SenderKeyMessage");
    private static readonly byte[] ChainKeyInfo = System.Text.Encoding.UTF8.GetBytes("SenderKeyChain");

    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorGroupSession"/> class.
    /// </summary>
    /// <param name="cryptoInterop">The Web Crypto interop service.</param>
    /// <param name="groupId">The group identifier.</param>
    /// <param name="localParticipantId">The local participant's identifier.</param>
    /// <param name="curve">The elliptic curve to use. Default is P-256.</param>
    /// <param name="hashAlgorithm">The hash algorithm. Default is SHA-256.</param>
    public BlazorGroupSession(
        WebCryptoInterop cryptoInterop,
        string groupId,
        string localParticipantId,
        string curve = "P-256",
        string hashAlgorithm = "SHA-256")
    {
        _cryptoInterop = cryptoInterop ?? throw new ArgumentNullException(nameof(cryptoInterop));
        GroupId = groupId ?? throw new ArgumentNullException(nameof(groupId));
        LocalParticipantId = localParticipantId ?? throw new ArgumentNullException(nameof(localParticipantId));
        _curve = curve;
        _hashAlgorithm = hashAlgorithm;
    }

    /// <summary>
    /// Gets the group ID.
    /// </summary>
    public string GroupId { get; }

    /// <summary>
    /// Gets the local participant ID.
    /// </summary>
    public string LocalParticipantId { get; }

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
    /// </summary>
    /// <param name="keyId">Optional key ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task InitializeAsync(int? keyId = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        // Generate key ID if not provided
        int id = keyId ?? await GenerateRandomKeyIdAsync();

        // Generate chain key
        byte[] chainKey = await _cryptoInterop.GetRandomBytesAsync(KeySize);
        cancellationToken.ThrowIfCancellationRequested();

        // Generate ECDSA key pair for signing
        (byte[]? signaturePublicKey, byte[]? signaturePrivateKey) = await _cryptoInterop.GenerateEcdsaKeyPairAsync(_curve);
        cancellationToken.ThrowIfCancellationRequested();

        _localSenderKey?.Dispose();
        _localSenderKey = new BlazorSenderKeyState(id)
        {
            ChainKey = chainKey,
            SignaturePrivateKey = signaturePrivateKey,
            SignaturePublicKey = signaturePublicKey,
            ChainIndex = 0
        };
    }

    /// <summary>
    /// Creates a sender key distribution message to share with other group members.
    /// </summary>
    /// <returns>The distribution data.</returns>
    public BlazorSenderKeyDistributionData CreateDistributionMessage()
    {
        ThrowIfDisposed();

        if (_localSenderKey == null)
        {
            throw new InvalidOperationException("Local sender key not initialized.");
        }

        return new BlazorSenderKeyDistributionData(
            _localSenderKey.KeyId,
            (byte[])_localSenderKey.ChainKey!.Clone(),
            (byte[])_localSenderKey.SignaturePublicKey!.Clone(),
            _localSenderKey.ChainIndex);
    }

    /// <summary>
    /// Processes a sender key distribution message from another participant.
    /// </summary>
    /// <param name="participantId">The participant ID.</param>
    /// <param name="distributionData">The distribution data.</param>
    public void ProcessDistributionMessage(string participantId, BlazorSenderKeyDistributionData distributionData)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrEmpty(participantId);
        ArgumentNullException.ThrowIfNull(distributionData);

        if (_remoteSenderKeys.TryGetValue(participantId, out BlazorSenderKeyState? existing))
        {
            existing.Dispose();
        }

        BlazorSenderKeyState state = new(distributionData.KeyId)
        {
            ChainKey = (byte[])distributionData.ChainKey.Clone(),
            SignaturePublicKey = (byte[])distributionData.SignaturePublicKey.Clone(),
            ChainIndex = distributionData.ChainIndex
        };

        _remoteSenderKeys[participantId] = state;
    }

    /// <summary>
    /// Encrypts a message for the group.
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The encrypted group message.</returns>
    public async Task<BlazorGroupMessage> EncryptAsync(
        byte[] plaintext,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(plaintext);

        if (_localSenderKey == null)
        {
            throw new InvalidOperationException("Local sender key not initialized.");
        }

        if (_localSenderKey.RequiresRekey)
        {
            throw new InvalidOperationException("Sender key chain exhausted. Re-keying required.");
        }

        // Get message key from chain
        (byte[]? messageKey, byte[]? newChainKey) = await DeriveKeysAsync(_localSenderKey.ChainKey!);
        cancellationToken.ThrowIfCancellationRequested();

        int chainIndex = _localSenderKey.ChainIndex;

        // Update chain key
        Array.Clear(_localSenderKey.ChainKey!, 0, _localSenderKey.ChainKey!.Length);
        _localSenderKey.ChainKey = newChainKey;
        _localSenderKey.ChainIndex++;

        try
        {
            // Encrypt message
            byte[] ciphertext = await _cryptoInterop.AesGcmEncryptAsync(messageKey, plaintext, null);
            cancellationToken.ThrowIfCancellationRequested();

            // Sign the ciphertext
            byte[] signature = await _cryptoInterop.EcdsaSignAsync(
                _localSenderKey.SignaturePrivateKey!,
                ciphertext,
                _curve,
                _hashAlgorithm);
            cancellationToken.ThrowIfCancellationRequested();

            return new BlazorGroupMessage(
                LocalParticipantId,
                _localSenderKey.KeyId,
                chainIndex,
                ciphertext,
                signature);
        }
        finally
        {
            Array.Clear(messageKey, 0, messageKey.Length);
        }
    }

    /// <summary>
    /// Decrypts a message from a group member.
    /// </summary>
    /// <param name="message">The encrypted message.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decrypted plaintext.</returns>
    public async Task<byte[]> DecryptAsync(
        BlazorGroupMessage message,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(message);

        if (!_remoteSenderKeys.TryGetValue(message.SenderId, out BlazorSenderKeyState? senderKey))
        {
            throw new InvalidOperationException($"No sender key for participant: {message.SenderId}");
        }

        if (message.KeyId != senderKey.KeyId)
        {
            throw new InvalidOperationException("Sender key ID mismatch. May need to process new distribution.");
        }

        // Verify signature
        bool isValid = await _cryptoInterop.EcdsaVerifyAsync(
            senderKey.SignaturePublicKey!,
            message.Ciphertext,
            message.Signature,
            _curve,
            _hashAlgorithm);
        cancellationToken.ThrowIfCancellationRequested();

        if (!isValid)
        {
            throw new InvalidOperationException("Message signature verification failed.");
        }

        // Advance chain to message index if needed
        while (senderKey.ChainIndex < message.ChainIndex)
        {
            (byte[] _, byte[]? nextChainKey) = await DeriveKeysAsync(senderKey.ChainKey!);
            Array.Clear(senderKey.ChainKey!, 0, senderKey.ChainKey!.Length);
            senderKey.ChainKey = nextChainKey;
            senderKey.ChainIndex++;
            cancellationToken.ThrowIfCancellationRequested();
        }

        if (senderKey.ChainIndex != message.ChainIndex)
        {
            throw new InvalidOperationException("Message chain index mismatch. Message may have been replayed.");
        }

        // Get message key
        (byte[]? messageKey, byte[]? newChainKey2) = await DeriveKeysAsync(senderKey.ChainKey!);
        Array.Clear(senderKey.ChainKey!, 0, senderKey.ChainKey!.Length);
        senderKey.ChainKey = newChainKey2;
        senderKey.ChainIndex++;

        try
        {
            return await _cryptoInterop.AesGcmDecryptAsync(messageKey, message.Ciphertext, null);
        }
        finally
        {
            Array.Clear(messageKey, 0, messageKey.Length);
        }
    }

    /// <summary>
    /// Gets all known participant IDs.
    /// </summary>
    public IEnumerable<string> GetParticipantIds()
    {
        ThrowIfDisposed();
        return _remoteSenderKeys.Keys.ToList();
    }

    /// <summary>
    /// Removes a participant from the session.
    /// </summary>
    /// <param name="participantId">The participant ID to remove.</param>
    /// <returns>True if the participant was removed.</returns>
    public bool RemoveParticipant(string participantId)
    {
        ThrowIfDisposed();

        if (_remoteSenderKeys.TryGetValue(participantId, out BlazorSenderKeyState? state))
        {
            state.Dispose();
            _remoteSenderKeys.Remove(participantId);
            return true;
        }

        return false;
    }

    private async Task<(byte[] MessageKey, byte[] ChainKey)> DeriveKeysAsync(byte[] chainKey)
    {
        byte[] messageKey = await _cryptoInterop.HkdfDeriveKeyAsync(
            chainKey,
            [],
            MessageKeyInfo,
            KeySize,
            _hashAlgorithm);

        byte[] newChainKey = await _cryptoInterop.HkdfDeriveKeyAsync(
            chainKey,
            [],
            ChainKeyInfo,
            KeySize,
            _hashAlgorithm);

        return (messageKey, newChainKey);
    }

    private async Task<int> GenerateRandomKeyIdAsync()
    {
        byte[] bytes = await _cryptoInterop.GetRandomBytesAsync(4);
        return BitConverter.ToInt32(bytes, 0) & int.MaxValue;
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _localSenderKey?.Dispose();
        foreach (BlazorSenderKeyState state in _remoteSenderKeys.Values)
        {
            state.Dispose();
        }
        _remoteSenderKeys.Clear();

        _disposed = true;
        await ValueTask.CompletedTask;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

/// <summary>
/// Represents an encrypted group message.
/// </summary>
public sealed class BlazorGroupMessage
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorGroupMessage"/> class.
    /// </summary>
    public BlazorGroupMessage(
        string senderId,
        int keyId,
        int chainIndex,
        byte[] ciphertext,
        byte[] signature)
    {
        SenderId = senderId ?? throw new ArgumentNullException(nameof(senderId));
        KeyId = keyId;
        ChainIndex = chainIndex;
        Ciphertext = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));
        Signature = signature ?? throw new ArgumentNullException(nameof(signature));
    }

    /// <summary>
    /// Gets the sender's participant ID.
    /// </summary>
    public string SenderId { get; }

    /// <summary>
    /// Gets the key ID.
    /// </summary>
    public int KeyId { get; }

    /// <summary>
    /// Gets the chain index.
    /// </summary>
    public int ChainIndex { get; }

    /// <summary>
    /// Gets the ciphertext.
    /// </summary>
    public byte[] Ciphertext { get; }

    /// <summary>
    /// Gets the signature.
    /// </summary>
    public byte[] Signature { get; }

    /// <summary>
    /// Serializes to a byte array.
    /// </summary>
    public byte[] ToBytes()
    {
        using MemoryStream ms = new();
        using BinaryWriter writer = new(ms);

        writer.Write((byte)1);
        writer.Write(SenderId);
        writer.Write(KeyId);
        writer.Write(ChainIndex);
        writer.Write(Ciphertext.Length);
        writer.Write(Ciphertext);
        writer.Write(Signature.Length);
        writer.Write(Signature);

        return ms.ToArray();
    }

    /// <summary>
    /// Deserializes from a byte array.
    /// </summary>
    public static BlazorGroupMessage FromBytes(byte[] data)
    {
        using MemoryStream ms = new(data);
        using BinaryReader reader = new(ms);

        byte version = reader.ReadByte();
        if (version != 1)
        {
            throw new InvalidDataException($"Unsupported version: {version}");
        }

        string senderId = reader.ReadString();
        int keyId = reader.ReadInt32();
        int chainIndex = reader.ReadInt32();
        int ctLength = reader.ReadInt32();
        byte[] ciphertext = reader.ReadBytes(ctLength);
        int sigLength = reader.ReadInt32();
        byte[] signature = reader.ReadBytes(sigLength);

        return new BlazorGroupMessage(senderId, keyId, chainIndex, ciphertext, signature);
    }
}

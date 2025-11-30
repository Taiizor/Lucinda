// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

using Lucinda.Blazor.Interop;
using Lucinda.Blazor.Protocol.X3DH;

namespace Lucinda.Blazor.Protocol.DoubleRatchet;

/// <summary>
/// Provides Double Ratchet algorithm implementation for Blazor WebAssembly.
/// </summary>
/// <remarks>
/// <para>
/// The Double Ratchet algorithm combines:
/// <list type="bullet">
/// <item><description>DH Ratchet: Provides break-in recovery through periodic key agreement</description></item>
/// <item><description>Symmetric Ratchet: Provides forward secrecy for each message</description></item>
/// </list>
/// </para>
/// </remarks>
public sealed class BlazorDoubleRatchet : IAsyncDisposable
{
    private readonly WebCryptoInterop _cryptoInterop;
    private readonly string _curve;
    private readonly string _hashAlgorithm;
    private readonly int _maxSkip;
    private bool _disposed;

    private static readonly byte[] RootKdfInfo = System.Text.Encoding.UTF8.GetBytes("RootRatchet");
    private static readonly byte[] MessageKeyConstant = [0x01];
    private static readonly byte[] ChainKeyConstant = [0x02];

    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorDoubleRatchet"/> class.
    /// </summary>
    /// <param name="cryptoInterop">The Web Crypto interop service.</param>
    /// <param name="curve">The elliptic curve to use. Default is P-256.</param>
    /// <param name="hashAlgorithm">The hash algorithm. Default is SHA-256.</param>
    /// <param name="maxSkip">Maximum number of message keys to skip. Default is 100.</param>
    public BlazorDoubleRatchet(
        WebCryptoInterop cryptoInterop,
        string curve = "P-256",
        string hashAlgorithm = "SHA-256",
        int maxSkip = 100)
    {
        _cryptoInterop = cryptoInterop ?? throw new ArgumentNullException(nameof(cryptoInterop));
        _curve = curve;
        _hashAlgorithm = hashAlgorithm;
        _maxSkip = maxSkip;
    }

    /// <summary>
    /// Gets the algorithm name.
    /// </summary>
    public string AlgorithmName => $"DoubleRatchet-{_curve}-HKDF-{_hashAlgorithm}";

    /// <summary>
    /// Initializes a Double Ratchet session as the initiator (Alice).
    /// </summary>
    /// <param name="sharedSecret">The shared secret from X3DH.</param>
    /// <param name="remotePublicKey">The recipient's initial public key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The initialized ratchet state.</returns>
    public async Task<BlazorRatchetState> InitializeAsInitiatorAsync(
        byte[] sharedSecret,
        byte[] remotePublicKey,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(sharedSecret);
        ArgumentNullException.ThrowIfNull(remotePublicKey);

        if (sharedSecret.Length < 32)
        {
            throw new ArgumentException("Shared secret must be at least 32 bytes.", nameof(sharedSecret));
        }

        // Generate our sending key pair
        (byte[]? dhPublicKey, byte[]? dhPrivateKey) = await _cryptoInterop.GenerateEcdhKeyPairAsync(_curve);
        cancellationToken.ThrowIfCancellationRequested();

        BlazorRatchetState state = new()
        {
            DHSendingPrivateKey = dhPrivateKey,
            DHSendingPublicKey = dhPublicKey,
            DHReceivingPublicKey = (byte[])remotePublicKey.Clone(),
            RootKey = (byte[])sharedSecret.Clone(),
            SendingMessageNumber = 0,
            ReceivingMessageNumber = 0,
            PreviousSendingChainLength = 0
        };

        // Perform initial DH ratchet to derive sending chain key
        byte[] dhOutput = await _cryptoInterop.EcdhDeriveBitsAsync(
            state.DHSendingPrivateKey,
            state.DHReceivingPublicKey,
            _curve);
        cancellationToken.ThrowIfCancellationRequested();

        (byte[]? newRootKey, byte[]? chainKey) = await RootKdfAsync(state.RootKey, dhOutput);
        Array.Clear(state.RootKey, 0, state.RootKey.Length);
        state.RootKey = newRootKey;
        state.SendingChainKey = chainKey;

        // Clear sensitive data
        Array.Clear(dhOutput, 0, dhOutput.Length);

        return state;
    }

    /// <summary>
    /// Initializes a Double Ratchet session as the responder (Bob).
    /// </summary>
    /// <param name="sharedSecret">The shared secret from X3DH.</param>
    /// <param name="localKeyPair">The local key pair (signed pre-key used in X3DH).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The initialized ratchet state.</returns>
    public Task<BlazorRatchetState> InitializeAsResponderAsync(
        byte[] sharedSecret,
        BlazorAsymmetricKeyPair localKeyPair,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(sharedSecret);
        ArgumentNullException.ThrowIfNull(localKeyPair);

        if (sharedSecret.Length < 32)
        {
            throw new ArgumentException("Shared secret must be at least 32 bytes.", nameof(sharedSecret));
        }

        cancellationToken.ThrowIfCancellationRequested();

        BlazorRatchetState state = new()
        {
            DHSendingPrivateKey = (byte[])localKeyPair.PrivateKey.Clone(),
            DHSendingPublicKey = (byte[])localKeyPair.PublicKey.Clone(),
            DHReceivingPublicKey = null, // Will be set when first message is received
            RootKey = (byte[])sharedSecret.Clone(),
            SendingChainKey = null, // Will be set after first DH ratchet
            ReceivingChainKey = null,
            SendingMessageNumber = 0,
            ReceivingMessageNumber = 0,
            PreviousSendingChainLength = 0
        };

        return Task.FromResult(state);
    }

    /// <summary>
    /// Encrypts a message using the Double Ratchet protocol.
    /// </summary>
    /// <param name="state">The current ratchet state (will be modified).</param>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <param name="associatedData">Optional associated data for authentication.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The encrypted ratchet message.</returns>
    public async Task<BlazorRatchetMessage> EncryptAsync(
        BlazorRatchetState state,
        byte[] plaintext,
        byte[]? associatedData = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(plaintext);

        if (state.SendingChainKey == null)
        {
            throw new InvalidOperationException("Sending chain not initialized. Have you received a message first?");
        }

        // Derive message key from sending chain
        (byte[]? messageKey, byte[]? newChainKey) = await ChainKdfAsync(state.SendingChainKey);
        Array.Clear(state.SendingChainKey, 0, state.SendingChainKey.Length);
        state.SendingChainKey = newChainKey;
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            // Create header
            BlazorRatchetHeader header = new(
                state.DHSendingPublicKey!,
                state.PreviousSendingChainLength,
                state.SendingMessageNumber);

            // Encrypt plaintext with message key
            byte[] headerBytes = header.ToBytes();
            byte[] aad = associatedData != null
                ? ConcatenateArrays(headerBytes, associatedData)
                : headerBytes;

            byte[] ciphertext = await _cryptoInterop.AesGcmEncryptAsync(messageKey, plaintext, aad);
            cancellationToken.ThrowIfCancellationRequested();

            // Increment message number
            state.SendingMessageNumber++;

            return new BlazorRatchetMessage(header, ciphertext);
        }
        finally
        {
            Array.Clear(messageKey, 0, messageKey.Length);
        }
    }

    /// <summary>
    /// Decrypts a message using the Double Ratchet protocol.
    /// </summary>
    /// <param name="state">The current ratchet state (will be modified).</param>
    /// <param name="message">The encrypted message to decrypt.</param>
    /// <param name="associatedData">Optional associated data for authentication.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decrypted plaintext.</returns>
    public async Task<byte[]> DecryptAsync(
        BlazorRatchetState state,
        BlazorRatchetMessage message,
        byte[]? associatedData = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(message);

        BlazorRatchetHeader header = message.Header;
        byte[] headerBytes = header.ToBytes();
        byte[] aad = associatedData != null
            ? ConcatenateArrays(headerBytes, associatedData)
            : headerBytes;

        // Try to decrypt using a skipped message key
        KeyValuePair<(byte[] DhPublicKey, int MessageNumber), byte[]> skippedKey = state.SkippedMessageKeys
            .FirstOrDefault(kvp => kvp.Key.MessageNumber == header.MessageNumber &&
                                   kvp.Key.DhPublicKey.SequenceEqual(header.DHPublicKey));

        if (skippedKey.Value != null)
        {
            state.SkippedMessageKeys.Remove(skippedKey.Key);
            try
            {
                return await _cryptoInterop.AesGcmDecryptAsync(skippedKey.Value, message.Ciphertext, aad);
            }
            finally
            {
                Array.Clear(skippedKey.Value, 0, skippedKey.Value.Length);
            }
        }

        // Check if we need to perform a DH ratchet step
        bool dhRatchetNeeded = state.DHReceivingPublicKey == null ||
                               !header.DHPublicKey.SequenceEqual(state.DHReceivingPublicKey);

        if (dhRatchetNeeded)
        {
            // Skip message keys in the current receiving chain
            if (state.ReceivingChainKey != null)
            {
                await SkipMessageKeysAsync(state, header.PreviousChainLength, cancellationToken);
            }

            // Perform DH ratchet
            await DhRatchetAsync(state, header.DHPublicKey, cancellationToken);
        }

        // Skip message keys if needed
        await SkipMessageKeysAsync(state, header.MessageNumber, cancellationToken);

        // Derive message key from receiving chain
        (byte[]? messageKey, byte[]? newChainKey) = await ChainKdfAsync(state.ReceivingChainKey!);
        if (state.ReceivingChainKey != null)
        {
            Array.Clear(state.ReceivingChainKey, 0, state.ReceivingChainKey.Length);
        }

        state.ReceivingChainKey = newChainKey;
        state.ReceivingMessageNumber++;

        try
        {
            return await _cryptoInterop.AesGcmDecryptAsync(messageKey, message.Ciphertext, aad);
        }
        finally
        {
            Array.Clear(messageKey, 0, messageKey.Length);
        }
    }

    private async Task DhRatchetAsync(
        BlazorRatchetState state,
        byte[] remotePublicKey,
        CancellationToken cancellationToken)
    {
        state.PreviousSendingChainLength = state.SendingMessageNumber;
        state.SendingMessageNumber = 0;
        state.ReceivingMessageNumber = 0;
        state.DHReceivingPublicKey = (byte[])remotePublicKey.Clone();

        // Derive receiving chain key
        byte[] dhOutput1 = await _cryptoInterop.EcdhDeriveBitsAsync(
            state.DHSendingPrivateKey!,
            state.DHReceivingPublicKey,
            _curve);
        cancellationToken.ThrowIfCancellationRequested();

        (byte[]? rootKey1, byte[]? receivingChainKey) = await RootKdfAsync(state.RootKey!, dhOutput1);
        Array.Clear(dhOutput1, 0, dhOutput1.Length);
        if (state.RootKey != null)
        {
            Array.Clear(state.RootKey, 0, state.RootKey.Length);
        }

        state.RootKey = rootKey1;
        state.ReceivingChainKey = receivingChainKey;

        // Generate new DH key pair
        (byte[]? newPublicKey, byte[]? newPrivateKey) = await _cryptoInterop.GenerateEcdhKeyPairAsync(_curve);
        cancellationToken.ThrowIfCancellationRequested();

        if (state.DHSendingPrivateKey != null)
        {
            Array.Clear(state.DHSendingPrivateKey, 0, state.DHSendingPrivateKey.Length);
        }

        state.DHSendingPrivateKey = newPrivateKey;
        state.DHSendingPublicKey = newPublicKey;

        // Derive sending chain key
        byte[] dhOutput2 = await _cryptoInterop.EcdhDeriveBitsAsync(
            state.DHSendingPrivateKey,
            state.DHReceivingPublicKey,
            _curve);
        cancellationToken.ThrowIfCancellationRequested();

        (byte[]? rootKey2, byte[]? sendingChainKey) = await RootKdfAsync(state.RootKey, dhOutput2);
        Array.Clear(dhOutput2, 0, dhOutput2.Length);
        Array.Clear(state.RootKey, 0, state.RootKey.Length);
        state.RootKey = rootKey2;
        state.SendingChainKey = sendingChainKey;
    }

    private async Task SkipMessageKeysAsync(
        BlazorRatchetState state,
        int until,
        CancellationToken cancellationToken)
    {
        if (state.ReceivingChainKey == null)
        {
            return;
        }

        if (until - state.ReceivingMessageNumber > _maxSkip)
        {
            throw new InvalidOperationException($"Too many skipped messages: {until - state.ReceivingMessageNumber}");
        }

        while (state.ReceivingMessageNumber < until)
        {
            (byte[]? messageKey, byte[]? newChainKey) = await ChainKdfAsync(state.ReceivingChainKey);
            Array.Clear(state.ReceivingChainKey, 0, state.ReceivingChainKey.Length);
            state.ReceivingChainKey = newChainKey;

            // Store skipped key
            if (state.SkippedMessageKeys.Count >= BlazorRatchetState.MaxSkippedMessageKeys)
            {
                // Remove oldest skipped key
                KeyValuePair<(byte[] DhPublicKey, int MessageNumber), byte[]> oldest = state.SkippedMessageKeys.First();
                state.SkippedMessageKeys.Remove(oldest.Key);
                Array.Clear(oldest.Value, 0, oldest.Value.Length);
            }

            state.SkippedMessageKeys[(state.DHReceivingPublicKey!, state.ReceivingMessageNumber)] = messageKey;
            state.ReceivingMessageNumber++;
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    private async Task<(byte[] RootKey, byte[] ChainKey)> RootKdfAsync(byte[] rootKey, byte[] dhOutput)
    {
        // Use HKDF: Extract(rootKey, dhOutput) then Expand(prk, info, 64)
        byte[] prk = await _cryptoInterop.HkdfDeriveKeyAsync(
            dhOutput,
            rootKey,
            RootKdfInfo,
            64,
            _hashAlgorithm);

        byte[] newRootKey = new byte[32];
        byte[] chainKey = new byte[32];
        Buffer.BlockCopy(prk, 0, newRootKey, 0, 32);
        Buffer.BlockCopy(prk, 32, chainKey, 0, 32);
        Array.Clear(prk, 0, prk.Length);

        return (newRootKey, chainKey);
    }

    private async Task<(byte[] MessageKey, byte[] ChainKey)> ChainKdfAsync(byte[] chainKey)
    {
        // Message key = HKDF(chainKey, MessageKeyConstant)
        byte[] messageKey = await _cryptoInterop.HkdfDeriveKeyAsync(
            chainKey,
            [],
            MessageKeyConstant,
            32,
            _hashAlgorithm);

        // New chain key = HKDF(chainKey, ChainKeyConstant)
        byte[] newChainKey = await _cryptoInterop.HkdfDeriveKeyAsync(
            chainKey,
            [],
            ChainKeyConstant,
            32,
            _hashAlgorithm);

        return (messageKey, newChainKey);
    }

    private static byte[] ConcatenateArrays(params byte[][] arrays)
    {
        int totalLength = arrays.Sum(a => a.Length);
        byte[] result = new byte[totalLength];
        int offset = 0;
        foreach (byte[] arr in arrays)
        {
            Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
            offset += arr.Length;
        }
        return result;
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await ValueTask.CompletedTask;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

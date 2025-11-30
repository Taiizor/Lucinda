// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

namespace Lucinda.Blazor.Protocol.SenderKeys;

/// <summary>
/// Represents the state of a Sender Key for group messaging in Blazor WebAssembly.
/// </summary>
public sealed class BlazorSenderKeyState : IDisposable
{
    private const int KeySize = 32;
    private const int MaxChainLength = 2000;
    private bool _disposed;

    /// <summary>
    /// Gets the key ID that identifies this sender key generation.
    /// </summary>
    public int KeyId { get; }

    /// <summary>
    /// Gets or sets the current chain index (message counter).
    /// </summary>
    public int ChainIndex { get; set; }

    /// <summary>
    /// Gets or sets the chain key.
    /// </summary>
    public byte[]? ChainKey { get; set; }

    /// <summary>
    /// Gets or sets the signature private key (only for owner).
    /// </summary>
    public byte[]? SignaturePrivateKey { get; set; }

    /// <summary>
    /// Gets or sets the signature public key.
    /// </summary>
    public byte[]? SignaturePublicKey { get; set; }

    /// <summary>
    /// Gets whether this state has a private key (i.e., is the owner).
    /// </summary>
    public bool IsOwner => SignaturePrivateKey != null;

    /// <summary>
    /// Gets whether a rekey is required (chain too long).
    /// </summary>
    public bool RequiresRekey => ChainIndex >= MaxChainLength;

    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorSenderKeyState"/> class.
    /// </summary>
    /// <param name="keyId">The key ID.</param>
    public BlazorSenderKeyState(int keyId)
    {
        KeyId = keyId;
    }

    /// <summary>
    /// Serializes the sender key state to a byte array.
    /// </summary>
    /// <returns>The serialized state.</returns>
    public byte[] Serialize()
    {
        using MemoryStream ms = new();
        using BinaryWriter writer = new(ms);

        writer.Write((byte)1); // Version
        writer.Write(KeyId);
        writer.Write(ChainIndex);
        WriteByteArray(writer, ChainKey);
        WriteByteArray(writer, SignaturePrivateKey);
        WriteByteArray(writer, SignaturePublicKey);

        return ms.ToArray();
    }

    /// <summary>
    /// Deserializes a sender key state from a byte array.
    /// </summary>
    /// <param name="data">The serialized data.</param>
    /// <returns>The deserialized state.</returns>
    public static BlazorSenderKeyState Deserialize(byte[] data)
    {
        using MemoryStream ms = new(data);
        using BinaryReader reader = new(ms);

        byte version = reader.ReadByte();
        if (version != 1)
        {
            throw new InvalidDataException($"Unsupported state version: {version}");
        }

        int keyId = reader.ReadInt32();
        BlazorSenderKeyState state = new(keyId)
        {
            ChainIndex = reader.ReadInt32(),
            ChainKey = ReadByteArray(reader),
            SignaturePrivateKey = ReadByteArray(reader),
            SignaturePublicKey = ReadByteArray(reader)
        };

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

        if (ChainKey != null)
        {
            Array.Clear(ChainKey, 0, ChainKey.Length);
        }

        if (SignaturePrivateKey != null)
        {
            Array.Clear(SignaturePrivateKey, 0, SignaturePrivateKey.Length);
        }

        _disposed = true;
    }
}

/// <summary>
/// Represents sender key distribution data for sharing with group members.
/// </summary>
public sealed class BlazorSenderKeyDistributionData
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorSenderKeyDistributionData"/> class.
    /// </summary>
    /// <param name="keyId">The key ID.</param>
    /// <param name="chainKey">The current chain key.</param>
    /// <param name="signaturePublicKey">The signature public key.</param>
    /// <param name="chainIndex">The current chain index.</param>
    public BlazorSenderKeyDistributionData(
        int keyId,
        byte[] chainKey,
        byte[] signaturePublicKey,
        int chainIndex)
    {
        KeyId = keyId;
        ChainKey = chainKey ?? throw new ArgumentNullException(nameof(chainKey));
        SignaturePublicKey = signaturePublicKey ?? throw new ArgumentNullException(nameof(signaturePublicKey));
        ChainIndex = chainIndex;
    }

    /// <summary>
    /// Gets the key ID.
    /// </summary>
    public int KeyId { get; }

    /// <summary>
    /// Gets the chain key.
    /// </summary>
    public byte[] ChainKey { get; }

    /// <summary>
    /// Gets the signature public key.
    /// </summary>
    public byte[] SignaturePublicKey { get; }

    /// <summary>
    /// Gets the chain index.
    /// </summary>
    public int ChainIndex { get; }

    /// <summary>
    /// Serializes to a byte array.
    /// </summary>
    public byte[] ToBytes()
    {
        using MemoryStream ms = new();
        using BinaryWriter writer = new(ms);

        writer.Write((byte)1);
        writer.Write(KeyId);
        writer.Write(ChainIndex);
        writer.Write(ChainKey.Length);
        writer.Write(ChainKey);
        writer.Write(SignaturePublicKey.Length);
        writer.Write(SignaturePublicKey);

        return ms.ToArray();
    }

    /// <summary>
    /// Deserializes from a byte array.
    /// </summary>
    public static BlazorSenderKeyDistributionData FromBytes(byte[] data)
    {
        using MemoryStream ms = new(data);
        using BinaryReader reader = new(ms);

        byte version = reader.ReadByte();
        if (version != 1)
        {
            throw new InvalidDataException($"Unsupported version: {version}");
        }

        int keyId = reader.ReadInt32();
        int chainIndex = reader.ReadInt32();
        int chainKeyLength = reader.ReadInt32();
        byte[] chainKey = reader.ReadBytes(chainKeyLength);
        int pubKeyLength = reader.ReadInt32();
        byte[] signaturePublicKey = reader.ReadBytes(pubKeyLength);

        return new BlazorSenderKeyDistributionData(keyId, chainKey, signaturePublicKey, chainIndex);
    }
}

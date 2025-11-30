// <copyright file="BlazorInitialMessageData.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor.Protocol.X3DH;

/// <summary>
/// Represents the initial message data sent from an initiator to a responder
/// to establish a secure session using X3DH.
/// </summary>
public sealed class BlazorInitialMessageData
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorInitialMessageData"/> class.
    /// </summary>
    /// <param name="senderIdentityKey">The sender's identity public key.</param>
    /// <param name="senderEphemeralKey">The sender's ephemeral public key.</param>
    /// <param name="usedOneTimePreKeyId">The ID of the used one-time pre-key, if any.</param>
    public BlazorInitialMessageData(
        byte[] senderIdentityKey,
        byte[] senderEphemeralKey,
        int? usedOneTimePreKeyId = null)
    {
        SenderIdentityKey = senderIdentityKey ?? throw new ArgumentNullException(nameof(senderIdentityKey));
        SenderEphemeralKey = senderEphemeralKey ?? throw new ArgumentNullException(nameof(senderEphemeralKey));
        UsedOneTimePreKeyId = usedOneTimePreKeyId;
    }

    /// <summary>
    /// Gets the sender's identity public key.
    /// </summary>
    public byte[] SenderIdentityKey { get; }

    /// <summary>
    /// Gets the sender's ephemeral public key used in the key agreement.
    /// </summary>
    public byte[] SenderEphemeralKey { get; }

    /// <summary>
    /// Gets the ID of the one-time pre-key used in the key agreement, if any.
    /// </summary>
    public int? UsedOneTimePreKeyId { get; }

    /// <summary>
    /// Serializes this initial message data to a byte array.
    /// </summary>
    /// <returns>The serialized bytes.</returns>
    public byte[] ToBytes()
    {
        using MemoryStream ms = new();
        using BinaryWriter writer = new(ms);

        // Write sender identity key
        writer.Write(SenderIdentityKey.Length);
        writer.Write(SenderIdentityKey);

        // Write sender ephemeral key
        writer.Write(SenderEphemeralKey.Length);
        writer.Write(SenderEphemeralKey);

        // Write used one-time pre-key ID
        writer.Write(UsedOneTimePreKeyId.HasValue);
        if (UsedOneTimePreKeyId.HasValue)
        {
            writer.Write(UsedOneTimePreKeyId.Value);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Deserializes initial message data from a byte array.
    /// </summary>
    /// <param name="data">The serialized data.</param>
    /// <returns>The deserialized initial message data.</returns>
    public static BlazorInitialMessageData FromBytes(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        using MemoryStream ms = new(data);
        using BinaryReader reader = new(ms);

        // Read sender identity key
        int identityKeyLength = reader.ReadInt32();
        byte[] senderIdentityKey = reader.ReadBytes(identityKeyLength);

        // Read sender ephemeral key
        int ephemeralKeyLength = reader.ReadInt32();
        byte[] senderEphemeralKey = reader.ReadBytes(ephemeralKeyLength);

        // Read used one-time pre-key ID
        bool hasOneTimePreKeyId = reader.ReadBoolean();
        int? usedOneTimePreKeyId = hasOneTimePreKeyId ? reader.ReadInt32() : null;

        return new BlazorInitialMessageData(senderIdentityKey, senderEphemeralKey, usedOneTimePreKeyId);
    }

    /// <summary>
    /// Converts this initial message data to a Base64 string.
    /// </summary>
    /// <returns>The Base64 encoded string.</returns>
    public string ToBase64()
    {
        return Convert.ToBase64String(ToBytes());
    }

    /// <summary>
    /// Creates initial message data from a Base64 string.
    /// </summary>
    /// <param name="base64">The Base64 encoded string.</param>
    /// <returns>The deserialized initial message data.</returns>
    public static BlazorInitialMessageData FromBase64(string base64)
    {
        ArgumentNullException.ThrowIfNull(base64);
        return FromBytes(Convert.FromBase64String(base64));
    }
}

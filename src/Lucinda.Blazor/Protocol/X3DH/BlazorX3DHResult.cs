// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

namespace Lucinda.Blazor.Protocol.X3DH;

/// <summary>
/// Represents the result of an X3DH key agreement operation.
/// </summary>
public sealed class BlazorX3DHResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorX3DHResult"/> class.
    /// </summary>
    /// <param name="sharedSecret">The derived shared secret.</param>
    /// <param name="associatedData">The associated data for authentication.</param>
    /// <param name="ephemeralPublicKey">The ephemeral public key (initiator only).</param>
    /// <param name="usedOneTimePreKeyId">The ID of the used one-time pre-key, if any.</param>
    public BlazorX3DHResult(
        byte[] sharedSecret,
        byte[] associatedData,
        byte[]? ephemeralPublicKey = null,
        int? usedOneTimePreKeyId = null)
    {
        SharedSecret = sharedSecret ?? throw new ArgumentNullException(nameof(sharedSecret));
        AssociatedData = associatedData ?? throw new ArgumentNullException(nameof(associatedData));
        EphemeralPublicKey = ephemeralPublicKey;
        UsedOneTimePreKeyId = usedOneTimePreKeyId;
    }

    /// <summary>
    /// Gets the derived shared secret from the X3DH key agreement.
    /// This should be used to initialize the Double Ratchet algorithm.
    /// </summary>
    public byte[] SharedSecret { get; }

    /// <summary>
    /// Gets the associated data that should be authenticated with messages.
    /// Typically contains the concatenated identity public keys of both parties.
    /// </summary>
    public byte[] AssociatedData { get; }

    /// <summary>
    /// Gets the initiator's ephemeral public key.
    /// This key must be sent to the responder as part of the initial message.
    /// </summary>
    public byte[]? EphemeralPublicKey { get; }

    /// <summary>
    /// Gets the ID of the one-time pre-key that was used, if any.
    /// This ID should be sent to the responder so they know which key to use.
    /// </summary>
    public int? UsedOneTimePreKeyId { get; }

    /// <summary>
    /// Gets a value indicating whether a one-time pre-key was used.
    /// </summary>
    public bool UsedOneTimePreKey => UsedOneTimePreKeyId.HasValue;
}

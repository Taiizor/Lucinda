// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

namespace Lucinda.Blazor.Protocol.X3DH;

/// <summary>
/// Represents a pre-key bundle for X3DH key agreement in Blazor WebAssembly.
/// Contains the public keys needed for establishing a secure session.
/// </summary>
public sealed class BlazorPreKeyBundle
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorPreKeyBundle"/> class.
    /// </summary>
    /// <param name="identityKey">The long-term identity public key.</param>
    /// <param name="signedPreKey">The signed pre-key public key.</param>
    /// <param name="signedPreKeySignature">The signature over the signed pre-key.</param>
    /// <param name="signedPreKeyId">The identifier for the signed pre-key.</param>
    /// <param name="oneTimePreKey">Optional one-time pre-key public key.</param>
    /// <param name="oneTimePreKeyId">Optional identifier for the one-time pre-key.</param>
    public BlazorPreKeyBundle(
        byte[] identityKey,
        byte[] signedPreKey,
        byte[] signedPreKeySignature,
        int signedPreKeyId,
        byte[]? oneTimePreKey = null,
        int? oneTimePreKeyId = null)
    {
        IdentityKey = identityKey ?? throw new ArgumentNullException(nameof(identityKey));
        SignedPreKey = signedPreKey ?? throw new ArgumentNullException(nameof(signedPreKey));
        SignedPreKeySignature = signedPreKeySignature ?? throw new ArgumentNullException(nameof(signedPreKeySignature));
        SignedPreKeyId = signedPreKeyId;
        OneTimePreKey = oneTimePreKey;
        OneTimePreKeyId = oneTimePreKeyId;
    }

    /// <summary>
    /// Gets the long-term identity public key (IK).
    /// </summary>
    public byte[] IdentityKey { get; }

    /// <summary>
    /// Gets the signed pre-key public key (SPK).
    /// </summary>
    public byte[] SignedPreKey { get; }

    /// <summary>
    /// Gets the signature over the signed pre-key, created with the identity key.
    /// </summary>
    public byte[] SignedPreKeySignature { get; }

    /// <summary>
    /// Gets the identifier for the signed pre-key.
    /// </summary>
    public int SignedPreKeyId { get; }

    /// <summary>
    /// Gets the one-time pre-key public key (OPK), if available.
    /// </summary>
    public byte[]? OneTimePreKey { get; }

    /// <summary>
    /// Gets the identifier for the one-time pre-key, if available.
    /// </summary>
    public int? OneTimePreKeyId { get; }

    /// <summary>
    /// Gets a value indicating whether this bundle contains a one-time pre-key.
    /// </summary>
    public bool HasOneTimePreKey => OneTimePreKey != null && OneTimePreKeyId.HasValue;
}

/// <summary>
/// Represents a pre-key bundle along with its private keys for the bundle owner.
/// </summary>
public sealed class BlazorPreKeyBundleWithPrivateKeys
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorPreKeyBundleWithPrivateKeys"/> class.
    /// </summary>
    /// <param name="bundle">The public pre-key bundle.</param>
    /// <param name="identityPrivateKey">The private key for the identity key.</param>
    /// <param name="signedPreKeyPrivate">The private key for the signed pre-key.</param>
    /// <param name="oneTimePreKeyPrivates">Dictionary of one-time pre-key private keys by ID.</param>
    public BlazorPreKeyBundleWithPrivateKeys(
        BlazorPreKeyBundle bundle,
        byte[] identityPrivateKey,
        byte[] signedPreKeyPrivate,
        Dictionary<int, byte[]>? oneTimePreKeyPrivates = null)
    {
        Bundle = bundle ?? throw new ArgumentNullException(nameof(bundle));
        IdentityPrivateKey = identityPrivateKey ?? throw new ArgumentNullException(nameof(identityPrivateKey));
        SignedPreKeyPrivate = signedPreKeyPrivate ?? throw new ArgumentNullException(nameof(signedPreKeyPrivate));
        OneTimePreKeyPrivates = oneTimePreKeyPrivates ?? [];
    }

    /// <summary>
    /// Gets the public pre-key bundle.
    /// </summary>
    public BlazorPreKeyBundle Bundle { get; }

    /// <summary>
    /// Gets the identity private key.
    /// </summary>
    public byte[] IdentityPrivateKey { get; }

    /// <summary>
    /// Gets the signed pre-key private key.
    /// </summary>
    public byte[] SignedPreKeyPrivate { get; }

    /// <summary>
    /// Gets the dictionary of one-time pre-key private keys by ID.
    /// </summary>
    public Dictionary<int, byte[]> OneTimePreKeyPrivates { get; }

    /// <summary>
    /// Gets the private key for a specific one-time pre-key ID.
    /// </summary>
    /// <param name="id">The one-time pre-key ID.</param>
    /// <returns>The private key, or null if not found.</returns>
    public byte[]? GetOneTimePreKeyPrivate(int id)
    {
        return OneTimePreKeyPrivates.TryGetValue(id, out byte[]? key) ? key : null;
    }

    /// <summary>
    /// Removes and returns a one-time pre-key private key.
    /// The key should be deleted after use for forward secrecy.
    /// </summary>
    /// <param name="id">The one-time pre-key ID.</param>
    /// <returns>The private key if found, or null.</returns>
    public byte[]? ConsumeOneTimePreKey(int id)
    {
        if (OneTimePreKeyPrivates.TryGetValue(id, out byte[]? key))
        {
            OneTimePreKeyPrivates.Remove(id);
            return key;
        }
        return null;
    }
}

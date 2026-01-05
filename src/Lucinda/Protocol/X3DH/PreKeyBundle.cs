// <copyright file="PreKeyBundle.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
namespace Lucinda.Protocol.X3DH
{
    /// <summary>
    /// Represents a pre-key bundle that is published to a server for X3DH key agreement.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A pre-key bundle contains the public keys needed for other users to establish
    /// a secure session with the bundle owner, even when the owner is offline.
    /// </para>
    /// <para>
    /// Bundle contents:
    /// <list type="bullet">
    /// <item><description>Identity Key (IK): Long-term identity public key</description></item>
    /// <item><description>Signed Pre-Key (SPK): Medium-term pre-key, signed by identity key</description></item>
    /// <item><description>One-Time Pre-Keys (OPK): Single-use keys for additional forward secrecy</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    /// <remarks>
    /// Initializes a new instance of the <see cref="PreKeyBundle"/> class.
    /// </remarks>
    /// <param name="identityKey">The long-term identity public key.</param>
    /// <param name="signedPreKey">The signed pre-key public key.</param>
    /// <param name="signedPreKeySignature">The signature over the signed pre-key.</param>
    /// <param name="signedPreKeyId">The identifier for the signed pre-key.</param>
    /// <param name="oneTimePreKeys">Dictionary of one-time pre-key public keys by ID.</param>
    public sealed class PreKeyBundle(
        byte[] identityKey,
        byte[] signedPreKey,
        byte[] signedPreKeySignature,
        int signedPreKeyId,
        IDictionary<int, byte[]>? oneTimePreKeys = null)
    {
        /// <summary>
        /// Internal sorted dictionary for one-time pre-keys.
        /// Using SortedDictionary ensures O(log n) operations and deterministic ordering.
        /// </summary>
        private readonly SortedDictionary<int, byte[]> _oneTimePreKeys =
            oneTimePreKeys != null ? new SortedDictionary<int, byte[]>(oneTimePreKeys.ToDictionary(kvp => kvp.Key, kvp => (byte[])kvp.Value.Clone())) : [];

        /// <summary>
        /// Gets the long-term identity public key (IK).
        /// </summary>
        /// <value>The identity public key bytes.</value>
        public byte[] IdentityKey { get; } = identityKey ?? throw new ArgumentNullException(nameof(identityKey));

        /// <summary>
        /// Gets the signed pre-key public key (SPK).
        /// </summary>
        /// <value>The signed pre-key public key bytes.</value>
        public byte[] SignedPreKey { get; } = signedPreKey ?? throw new ArgumentNullException(nameof(signedPreKey));

        /// <summary>
        /// Gets the signature over the signed pre-key, created with the identity key.
        /// </summary>
        /// <value>The signature bytes.</value>
        public byte[] SignedPreKeySignature { get; } = signedPreKeySignature ?? throw new ArgumentNullException(nameof(signedPreKeySignature));

        /// <summary>
        /// Gets the identifier for the signed pre-key.
        /// </summary>
        /// <value>The signed pre-key ID.</value>
        public int SignedPreKeyId { get; } = signedPreKeyId;

        /// <summary>
        /// Gets a read-only view of the one-time pre-key public keys (OPK), keyed by ID.
        /// Keys are sorted by ID in ascending order.
        /// </summary>
        /// <value>The one-time pre-keys as a read-only dictionary.</value>
        public IReadOnlyDictionary<int, byte[]> OneTimePreKeys => _oneTimePreKeys;

        /// <summary>
        /// Gets a value indicating whether this bundle contains any one-time pre-keys.
        /// </summary>
        /// <value><c>true</c> if one or more one-time pre-keys are present; otherwise, <c>false</c>.</value>
        /// <remarks>
        /// This property is not thread-safe. If the one-time pre-key collection may be modified concurrently
        /// (for example, by <c>ConsumeOneTimePreKey()</c>), callers must provide their own synchronization
        /// around all accesses to one-time pre-keys, including this property.
        /// </remarks>
        public bool HasOneTimePreKey => _oneTimePreKeys.Count > 0;

        /// <summary>
        /// Gets a specific one-time pre-key public key by ID.
        /// </summary>
        /// <param name="id">The one-time pre-key ID.</param>
        /// <returns>The one-time pre-key public key bytes, or null if not found.</returns>
        public byte[]? GetOneTimePreKey(int id)
        {
            return _oneTimePreKeys.TryGetValue(id, out byte[]? key) ? (byte[])key.Clone() : null;
        }

        /// <summary>
        /// Consumes (removes and returns) the one-time pre-key with the smallest ID.
        /// This method is useful for server-side key distribution simulation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The key with the smallest ID is always selected. Since a SortedDictionary is used internally,
        /// the first element is guaranteed to have the smallest key, and the removal operation has O(log n) complexity.
        /// </para>
        /// <para>
        /// <b>Warning:</b> This method is not thread-safe. If multiple threads access
        /// this method concurrently, race conditions may occur. Use external synchronization
        /// (e.g., locking) when accessing from multiple threads.
        /// </para>
        /// </remarks>
        /// <returns>A tuple of (ID, PublicKey), or null if no keys are available.</returns>
        public (int Id, byte[] Key)? ConsumeOneTimePreKey()
        {
            // SortedDictionary.Keys is already sorted, First() returns smallest key
            using IEnumerator<KeyValuePair<int, byte[]>> enumerator = _oneTimePreKeys.GetEnumerator();
            if (!enumerator.MoveNext())
            {
                return null;
            }

            KeyValuePair<int, byte[]> first = enumerator.Current;
            _oneTimePreKeys.Remove(first.Key);
            return (first.Key, (byte[])first.Value.Clone());
        }

        /// <summary>
        /// Gets the smallest available one-time pre-key ID, if any.
        /// This property provides backward compatibility.
        /// </summary>
        /// <value>The smallest one-time pre-key ID, or null if none available.</value>
        public int? OneTimePreKeyId => _oneTimePreKeys.Count > 0 ? _oneTimePreKeys.Keys.First() : null;

        /// <summary>
        /// Gets the one-time pre-key with the smallest ID, if any.
        /// This property provides backward compatibility.
        /// </summary>
        /// <value>The one-time pre-key bytes with smallest ID, or null if none available.</value>
        public byte[]? OneTimePreKey =>
            _oneTimePreKeys.Count > 0 ? _oneTimePreKeys.Values.First().ToArray() : null;
    }

    /// <summary>
    /// Represents a pre-key bundle along with its private keys for the bundle owner.
    /// </summary>
    /// <remarks>
    /// This class is used by the bundle owner to store the private keys needed to
    /// complete the X3DH key agreement when receiving an initial message.
    /// </remarks>
    /// <remarks>
    /// Initializes a new instance of the <see cref="PreKeyBundleWithPrivateKeys"/> class.
    /// </remarks>
    /// <param name="bundle">The public pre-key bundle.</param>
    /// <param name="signedPreKeyPrivate">The private key for the signed pre-key.</param>
    /// <param name="oneTimePreKeyPrivates">Dictionary of one-time pre-key private keys by ID.</param>
    public sealed class PreKeyBundleWithPrivateKeys(
        PreKeyBundle bundle,
        byte[] signedPreKeyPrivate,
        Dictionary<int, byte[]>? oneTimePreKeyPrivates = null)
    {
        /// <summary>
        /// Gets the public pre-key bundle.
        /// </summary>
        /// <value>The pre-key bundle.</value>
        public PreKeyBundle Bundle { get; } = bundle ?? throw new ArgumentNullException(nameof(bundle));

        /// <summary>
        /// Gets the private key for the signed pre-key.
        /// </summary>
        /// <value>The signed pre-key private key bytes.</value>
        public byte[] SignedPreKeyPrivate { get; } = signedPreKeyPrivate ?? throw new ArgumentNullException(nameof(signedPreKeyPrivate));

        /// <summary>
        /// Gets the dictionary of one-time pre-key private keys, keyed by ID.
        /// </summary>
        /// <value>The one-time pre-key private keys.</value>
        public Dictionary<int, byte[]> OneTimePreKeyPrivates { get; } = oneTimePreKeyPrivates ?? [];

        /// <summary>
        /// Gets the one-time pre-key private key for the specified ID.
        /// </summary>
        /// <param name="id">The one-time pre-key ID.</param>
        /// <returns>The private key bytes, or null if not found.</returns>
        public byte[]? GetOneTimePreKeyPrivate(int id)
        {
            return OneTimePreKeyPrivates.TryGetValue(id, out byte[]? privateKey) ? privateKey : null;
        }

        /// <summary>
        /// Removes and returns a one-time pre-key private key (consuming it).
        /// </summary>
        /// <param name="id">The one-time pre-key ID.</param>
        /// <returns>The private key bytes, or null if not found.</returns>
        public byte[]? ConsumeOneTimePreKeyPrivate(int id)
        {
            if (OneTimePreKeyPrivates.TryGetValue(id, out byte[]? privateKey))
            {
                OneTimePreKeyPrivates.Remove(id);
                return privateKey;
            }
            return null;
        }
    }
}
#endif
// <copyright file="X3DHResult.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
namespace Lucinda.Protocol.X3DH
{
    /// <summary>
    /// Represents the result of an X3DH key agreement operation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The X3DH result contains:
    /// <list type="bullet">
    /// <item><description>Shared Secret: The derived shared secret for initializing Double Ratchet</description></item>
    /// <item><description>Associated Data: Data that should be included in the initial message</description></item>
    /// <item><description>Ephemeral Public Key: The initiator's ephemeral public key (for initial message)</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    /// <remarks>
    /// Initializes a new instance of the <see cref="X3DHResult"/> class.
    /// </remarks>
    /// <param name="sharedSecret">The derived shared secret.</param>
    /// <param name="associatedData">The associated data for authentication.</param>
    /// <param name="ephemeralPublicKey">The ephemeral public key (initiator only).</param>
    /// <param name="usedOneTimePreKeyId">The ID of the used one-time pre-key, if any.</param>
    public sealed class X3DHResult(
        byte[] sharedSecret,
        byte[] associatedData,
        byte[]? ephemeralPublicKey = null,
        int? usedOneTimePreKeyId = null)
    {
        /// <summary>
        /// Gets the derived shared secret from the X3DH key agreement.
        /// </summary>
        /// <value>The shared secret bytes (typically 32 bytes).</value>
        /// <remarks>
        /// This shared secret should be used to initialize the Double Ratchet algorithm.
        /// </remarks>
        public byte[] SharedSecret { get; } = sharedSecret ?? throw new ArgumentNullException(nameof(sharedSecret));

        /// <summary>
        /// Gets the associated data that should be authenticated with messages.
        /// </summary>
        /// <value>The associated data bytes.</value>
        /// <remarks>
        /// Typically contains the concatenated identity public keys of both parties.
        /// This data is included in the AEAD encryption to provide authentication.
        /// </remarks>
        public byte[] AssociatedData { get; } = associatedData ?? throw new ArgumentNullException(nameof(associatedData));

        /// <summary>
        /// Gets the initiator's ephemeral public key.
        /// </summary>
        /// <value>The ephemeral public key bytes, or null for responder.</value>
        /// <remarks>
        /// This key must be sent to the responder as part of the initial message.
        /// </remarks>
        public byte[]? EphemeralPublicKey { get; } = ephemeralPublicKey;

        /// <summary>
        /// Gets the ID of the one-time pre-key that was used, if any.
        /// </summary>
        /// <value>The one-time pre-key ID, or null if none was used.</value>
        /// <remarks>
        /// This ID should be sent to the responder so they know which one-time pre-key
        /// to use for completing the key agreement.
        /// </remarks>
        public int? UsedOneTimePreKeyId { get; } = usedOneTimePreKeyId;

        /// <summary>
        /// Gets a value indicating whether a one-time pre-key was used.
        /// </summary>
        /// <value><c>true</c> if a one-time pre-key was used; otherwise, <c>false</c>.</value>
        public bool UsedOneTimePreKey => UsedOneTimePreKeyId.HasValue;
    }
}
#endif
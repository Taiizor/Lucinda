// <copyright file="IX3DHKeyAgreement.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using Lucinda.Protocol.X3DH;

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for X3DH (Extended Triple Diffie-Hellman) key agreement operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// X3DH is designed for asynchronous environments where the recipient may be offline.
    /// It provides forward secrecy and cryptographic deniability.
    /// </para>
    /// <para>
    /// The protocol uses three or four DH computations:
    /// <list type="bullet">
    /// <item><description>DH1: Sender Identity Key + Recipient Signed Pre-Key</description></item>
    /// <item><description>DH2: Sender Ephemeral Key + Recipient Identity Key</description></item>
    /// <item><description>DH3: Sender Ephemeral Key + Recipient Signed Pre-Key</description></item>
    /// <item><description>DH4 (optional): Sender Ephemeral Key + Recipient One-Time Pre-Key</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public interface IX3DHKeyAgreement
    {
        /// <summary>
        /// Gets the name of the key agreement algorithm.
        /// </summary>
        /// <value>The algorithm name (e.g., "X3DH-P256", "X3DH-X25519").</value>
        string AlgorithmName { get; }

        /// <summary>
        /// Performs the initiator side of the X3DH key agreement.
        /// </summary>
        /// <param name="senderIdentityKeyPair">The sender's long-term identity key pair.</param>
        /// <param name="recipientBundle">The recipient's pre-key bundle.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the X3DH result on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// The initiator generates an ephemeral key pair internally and includes the public key in the result.
        /// </remarks>
        CryptoResult<X3DHResult> InitiatorAgree(
            AsymmetricKeyPair senderIdentityKeyPair,
            PreKeyBundle recipientBundle);

        /// <summary>
        /// Performs the responder side of the X3DH key agreement.
        /// </summary>
        /// <param name="recipientIdentityKeyPair">The recipient's long-term identity key pair.</param>
        /// <param name="recipientSignedPreKeyPair">The recipient's signed pre-key pair.</param>
        /// <param name="recipientOneTimePreKeyPair">The recipient's one-time pre-key pair (optional).</param>
        /// <param name="senderIdentityPublicKey">The sender's identity public key.</param>
        /// <param name="senderEphemeralPublicKey">The sender's ephemeral public key.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the X3DH result on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<X3DHResult> ResponderAgree(
            AsymmetricKeyPair recipientIdentityKeyPair,
            AsymmetricKeyPair recipientSignedPreKeyPair,
            AsymmetricKeyPair? recipientOneTimePreKeyPair,
            byte[] senderIdentityPublicKey,
            byte[] senderEphemeralPublicKey);

        /// <summary>
        /// Generates a new pre-key bundle for publishing to a server.
        /// </summary>
        /// <param name="identityKeyPair">The long-term identity key pair.</param>
        /// <param name="signedPreKeyId">The ID for the signed pre-key.</param>
        /// <param name="oneTimePreKeyIds">Optional array of IDs for one-time pre-keys.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the generated pre-key bundle on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<PreKeyBundleWithPrivateKeys> GeneratePreKeyBundle(
            AsymmetricKeyPair identityKeyPair,
            int signedPreKeyId,
            int[]? oneTimePreKeyIds = null);
    }
}
#endif
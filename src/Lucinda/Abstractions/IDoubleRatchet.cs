// <copyright file="IDoubleRatchet.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using Lucinda.Protocol.DoubleRatchet;

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for the Double Ratchet algorithm operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Double Ratchet algorithm provides forward secrecy and break-in recovery
    /// by combining a Diffie-Hellman ratchet with a symmetric-key ratchet.
    /// </para>
    /// <para>
    /// Key features:
    /// <list type="bullet">
    /// <item><description>Forward Secrecy: Past messages remain secure even if keys are compromised</description></item>
    /// <item><description>Break-in Recovery: Future messages become secure after a compromise</description></item>
    /// <item><description>Out-of-order Messages: Supports decrypting messages received out of order</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public interface IDoubleRatchet
    {
        /// <summary>
        /// Gets the name of the ratchet algorithm configuration.
        /// </summary>
        /// <value>The algorithm configuration name.</value>
        string AlgorithmName { get; }

        /// <summary>
        /// Initializes a new ratchet state for the initiator (Alice).
        /// </summary>
        /// <param name="sharedSecret">The shared secret from X3DH key agreement.</param>
        /// <param name="remotePublicKey">The recipient's public key for the first DH ratchet.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the initialized ratchet state on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<RatchetState> InitializeAsInitiator(byte[] sharedSecret, byte[] remotePublicKey);

        /// <summary>
        /// Initializes a new ratchet state for the responder (Bob).
        /// </summary>
        /// <param name="sharedSecret">The shared secret from X3DH key agreement.</param>
        /// <param name="localKeyPair">The local key pair for the DH ratchet.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the initialized ratchet state on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<RatchetState> InitializeAsResponder(byte[] sharedSecret, AsymmetricKeyPair localKeyPair);

        /// <summary>
        /// Encrypts a message using the current ratchet state.
        /// </summary>
        /// <param name="state">The current ratchet state (will be modified).</param>
        /// <param name="plaintext">The plaintext message to encrypt.</param>
        /// <param name="associatedData">Optional additional data to authenticate.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the encrypted message with header on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This method advances the sending chain and may trigger a DH ratchet step.
        /// The state is modified in place to reflect the new ratchet position.
        /// </remarks>
        CryptoResult<RatchetMessage> Encrypt(RatchetState state, byte[] plaintext, byte[]? associatedData = null);

        /// <summary>
        /// Decrypts a message using the current ratchet state.
        /// </summary>
        /// <param name="state">The current ratchet state (will be modified).</param>
        /// <param name="message">The encrypted message with header.</param>
        /// <param name="associatedData">Optional additional data that was authenticated.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted plaintext on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This method handles out-of-order messages by storing skipped message keys.
        /// A DH ratchet step is performed if a new public key is received.
        /// </remarks>
        CryptoResult<byte[]> Decrypt(RatchetState state, RatchetMessage message, byte[]? associatedData = null);
    }
}
#endif
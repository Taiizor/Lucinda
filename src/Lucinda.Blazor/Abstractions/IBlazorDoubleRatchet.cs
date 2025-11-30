// <copyright file="IBlazorDoubleRatchet.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Blazor.Protocol.DoubleRatchet;
using Lucinda.Blazor.Protocol.X3DH;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for the Double Ratchet algorithm operations in Blazor.
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
    public interface IBlazorDoubleRatchet
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
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the initialized ratchet state on success,
        /// or an error message on failure.
        /// </returns>
        Task<BlazorCryptoResult<BlazorRatchetState>> InitializeAsInitiatorAsync(byte[] sharedSecret, byte[] remotePublicKey);

        /// <summary>
        /// Initializes a new ratchet state for the responder (Bob).
        /// </summary>
        /// <param name="sharedSecret">The shared secret from X3DH key agreement.</param>
        /// <param name="localKeyPair">The local key pair for the DH ratchet.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the initialized ratchet state on success,
        /// or an error message on failure.
        /// </returns>
        Task<BlazorCryptoResult<BlazorRatchetState>> InitializeAsResponderAsync(byte[] sharedSecret, BlazorAsymmetricKeyPair localKeyPair);

        /// <summary>
        /// Encrypts a message using the current ratchet state.
        /// </summary>
        /// <param name="state">The current ratchet state (will be modified).</param>
        /// <param name="plaintext">The plaintext message to encrypt.</param>
        /// <param name="associatedData">Optional additional data to authenticate.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the encrypted message with header on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This method advances the sending chain and may trigger a DH ratchet step.
        /// The state is modified in place to reflect the new ratchet position.
        /// </remarks>
        Task<BlazorCryptoResult<BlazorRatchetMessage>> EncryptAsync(BlazorRatchetState state, byte[] plaintext, byte[]? associatedData = null);

        /// <summary>
        /// Decrypts a message using the current ratchet state.
        /// </summary>
        /// <param name="state">The current ratchet state (will be modified).</param>
        /// <param name="message">The encrypted message with header.</param>
        /// <param name="associatedData">Optional additional data that was authenticated.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the decrypted plaintext on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This method may perform a DH ratchet step if the message contains a new public key.
        /// The state is modified in place to reflect the new ratchet position.
        /// </remarks>
        Task<BlazorCryptoResult<byte[]>> DecryptAsync(BlazorRatchetState state, BlazorRatchetMessage message, byte[]? associatedData = null);
    }
}
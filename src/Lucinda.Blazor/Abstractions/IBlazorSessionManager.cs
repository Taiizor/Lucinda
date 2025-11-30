// <copyright file="IBlazorSessionManager.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Blazor.Protocol.DoubleRatchet;
using Lucinda.Blazor.Protocol.X3DH;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for managing secure messaging sessions in Blazor.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The session manager handles:
    /// <list type="bullet">
    /// <item><description>Session creation and initialization using X3DH</description></item>
    /// <item><description>Session state persistence and retrieval</description></item>
    /// <item><description>Session lifecycle management</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public interface IBlazorSessionManager
    {
        /// <summary>
        /// Creates a new session with a recipient using their pre-key bundle.
        /// </summary>
        /// <param name="recipientId">The unique identifier for the recipient.</param>
        /// <param name="preKeyBundle">The recipient's pre-key bundle.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the session ID on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This performs the X3DH key agreement and initializes the Double Ratchet.
        /// </remarks>
        Task<BlazorCryptoResult<string>> CreateSessionAsync(string recipientId, BlazorPreKeyBundle preKeyBundle);

        /// <summary>
        /// Creates a session from an incoming initial message.
        /// </summary>
        /// <param name="senderId">The unique identifier of the sender.</param>
        /// <param name="senderIdentityPublicKey">The sender's identity public key.</param>
        /// <param name="senderEphemeralPublicKey">The sender's ephemeral public key.</param>
        /// <param name="usedOneTimePreKeyId">The ID of the one-time pre-key that was used (if any).</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the session ID on success,
        /// or an error message on failure.
        /// </returns>
        Task<BlazorCryptoResult<string>> CreateSessionFromInitialMessageAsync(
            string senderId,
            byte[] senderIdentityPublicKey,
            byte[] senderEphemeralPublicKey,
            int? usedOneTimePreKeyId);

        /// <summary>
        /// Gets the ratchet state for an existing session.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the ratchet state on success,
        /// or an error message on failure.
        /// </returns>
        Task<BlazorCryptoResult<BlazorRatchetState>> GetSessionAsync(string sessionId);

        /// <summary>
        /// Gets a session by recipient ID.
        /// </summary>
        /// <param name="recipientId">The recipient's unique identifier.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the ratchet state on success,
        /// or an error message on failure.
        /// </returns>
        Task<BlazorCryptoResult<BlazorRatchetState>> GetSessionByRecipientIdAsync(string recipientId);

        /// <summary>
        /// Stores or updates the ratchet state for a session.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <param name="state">The ratchet state to store.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> indicating success or failure.
        /// </returns>
        Task<BlazorCryptoResult<bool>> StoreSessionAsync(string sessionId, BlazorRatchetState state);

        /// <summary>
        /// Deletes a session.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> indicating success or failure.
        /// </returns>
        Task<BlazorCryptoResult<bool>> DeleteSessionAsync(string sessionId);

        /// <summary>
        /// Checks if a session exists.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with true if the session exists.
        /// </returns>
        Task<BlazorCryptoResult<bool>> SessionExistsAsync(string sessionId);

        /// <summary>
        /// Gets all session IDs.
        /// </summary>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the list of session IDs.
        /// </returns>
        Task<BlazorCryptoResult<string[]>> GetAllSessionIdsAsync();
    }
}
// <copyright file="ISessionManager.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using Lucinda.Protocol.DoubleRatchet;
using Lucinda.Protocol.X3DH;

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for managing secure messaging sessions.
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
    public interface ISessionManager
    {
        /// <summary>
        /// Creates a new session with a recipient using their pre-key bundle.
        /// </summary>
        /// <param name="recipientId">The unique identifier for the recipient.</param>
        /// <param name="preKeyBundle">The recipient's pre-key bundle.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the session ID on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This performs the X3DH key agreement and initializes the Double Ratchet.
        /// </remarks>
        CryptoResult<string> CreateSession(string recipientId, PreKeyBundle preKeyBundle);

        /// <summary>
        /// Creates a session from an incoming initial message.
        /// </summary>
        /// <param name="senderId">The unique identifier of the sender.</param>
        /// <param name="senderIdentityPublicKey">The sender's identity public key.</param>
        /// <param name="senderEphemeralPublicKey">The sender's ephemeral public key.</param>
        /// <param name="usedOneTimePreKeyId">The ID of the one-time pre-key that was used (if any).</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the session ID on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<string> CreateSessionFromInitialMessage(
            string senderId,
            byte[] senderIdentityPublicKey,
            byte[] senderEphemeralPublicKey,
            int? usedOneTimePreKeyId);

        /// <summary>
        /// Gets the ratchet state for an existing session.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the ratchet state on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<RatchetState> GetSession(string sessionId);

        /// <summary>
        /// Gets a session by recipient ID.
        /// </summary>
        /// <param name="recipientId">The recipient's unique identifier.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the ratchet state on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<RatchetState> GetSessionByRecipientId(string recipientId);

        /// <summary>
        /// Stores or updates the ratchet state for a session.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <param name="state">The ratchet state to store.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure.
        /// </returns>
        CryptoResult<bool> StoreSession(string sessionId, RatchetState state);

        /// <summary>
        /// Deletes a session.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure.
        /// </returns>
        CryptoResult<bool> DeleteSession(string sessionId);

        /// <summary>
        /// Checks if a session exists.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing true if the session exists.
        /// </returns>
        CryptoResult<bool> SessionExists(string sessionId);

        /// <summary>
        /// Checks if a session exists for the specified recipient.
        /// </summary>
        /// <param name="recipientId">The recipient's unique identifier.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing true if a session exists.
        /// </returns>
        CryptoResult<bool> HasSessionForRecipient(string recipientId);

        /// <summary>
        /// Lists all active session IDs.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing an array of session IDs.
        /// </returns>
        CryptoResult<string[]> ListSessions();
    }
}
#endif
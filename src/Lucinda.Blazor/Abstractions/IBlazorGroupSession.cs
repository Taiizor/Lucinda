// <copyright file="IBlazorGroupSession.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Interface for group messaging sessions using Sender Keys protocol in Blazor.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Group sessions enable efficient encrypted group messaging where each participant
    /// maintains their own sender key that is distributed to other group members.
    /// </para>
    /// <para>
    /// Key features:
    /// <list type="bullet">
    /// <item><description>Efficient: Single encryption for all recipients using sender keys</description></item>
    /// <item><description>Forward Secrecy: Regular key rotation provides forward secrecy</description></item>
    /// <item><description>Scalability: Performance scales well with group size</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public interface IBlazorGroupSession : IAsyncDisposable
    {
        /// <summary>
        /// Gets the group identifier.
        /// </summary>
        string GroupId { get; }

        /// <summary>
        /// Gets the local participant's identifier.
        /// </summary>
        string LocalParticipantId { get; }

        /// <summary>
        /// Gets whether the session is initialized.
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// Initializes the local sender key.
        /// </summary>
        /// <param name="keyId">Optional key ID.</param>
        /// <returns>A task containing a result indicating success or failure.</returns>
        Task<BlazorCryptoResult<bool>> InitializeAsync(int? keyId = null);

        /// <summary>
        /// Creates a distribution message to share with other group members.
        /// </summary>
        /// <returns>A task containing the serialized distribution data.</returns>
        Task<BlazorCryptoResult<byte[]>> CreateDistributionMessageAsync();

        /// <summary>
        /// Processes a distribution message from another participant.
        /// </summary>
        /// <param name="participantId">The sender's participant ID.</param>
        /// <param name="distributionData">The distribution data.</param>
        /// <returns>A task containing a result indicating success or failure.</returns>
        Task<BlazorCryptoResult<bool>> ProcessDistributionMessageAsync(string participantId, byte[] distributionData);

        /// <summary>
        /// Encrypts a message for the group.
        /// </summary>
        /// <param name="plaintext">The message to encrypt.</param>
        /// <returns>A task containing the serialized encrypted message.</returns>
        Task<BlazorCryptoResult<byte[]>> EncryptAsync(byte[] plaintext);

        /// <summary>
        /// Decrypts a message from the group.
        /// </summary>
        /// <param name="messageData">The serialized encrypted message.</param>
        /// <returns>A task containing the decrypted plaintext.</returns>
        Task<BlazorCryptoResult<byte[]>> DecryptAsync(byte[] messageData);

        /// <summary>
        /// Re-keys the local sender key.
        /// </summary>
        /// <returns>A task containing the new distribution data.</returns>
        Task<BlazorCryptoResult<byte[]>> ReKeyAsync();

        /// <summary>
        /// Removes a participant from the session.
        /// </summary>
        /// <param name="participantId">The participant ID to remove.</param>
        Task RemoveParticipantAsync(string participantId);

        /// <summary>
        /// Gets all known participant IDs.
        /// </summary>
        /// <returns>The list of participant IDs.</returns>
        IEnumerable<string> GetParticipants();

        /// <summary>
        /// Checks if a participant is known.
        /// </summary>
        /// <param name="participantId">The participant ID.</param>
        /// <returns>True if the participant is known.</returns>
        bool HasParticipant(string participantId);
    }
}
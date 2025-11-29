// -----------------------------------------------------------------------
// <copyright file="IGroupSession.cs" company="Taiizor">
// Copyright (c) Taiizor. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.
// </copyright>
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Interface for group messaging sessions using Sender Keys protocol.
    /// </summary>
    public interface IGroupSession : IDisposable
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
        /// <returns>A CryptoResult indicating success or failure.</returns>
        CryptoResult<bool> Initialize(int? keyId = null);

        /// <summary>
        /// Creates a distribution message to share with other group members.
        /// </summary>
        /// <returns>A CryptoResult containing the serialized distribution data.</returns>
        CryptoResult<byte[]> CreateDistributionMessage();

        /// <summary>
        /// Processes a distribution message from another participant.
        /// </summary>
        /// <param name="participantId">The sender's participant ID.</param>
        /// <param name="distributionData">The distribution data.</param>
        /// <returns>A CryptoResult indicating success or failure.</returns>
        CryptoResult<bool> ProcessDistributionMessage(string participantId, byte[] distributionData);

        /// <summary>
        /// Encrypts a message for the group.
        /// </summary>
        /// <param name="plaintext">The message to encrypt.</param>
        /// <returns>A CryptoResult containing the serialized encrypted message.</returns>
        CryptoResult<byte[]> Encrypt(byte[] plaintext);

        /// <summary>
        /// Decrypts a message from the group.
        /// </summary>
        /// <param name="messageData">The serialized encrypted message.</param>
        /// <returns>A CryptoResult containing the decrypted plaintext.</returns>
        CryptoResult<byte[]> Decrypt(byte[] messageData);

        /// <summary>
        /// Re-keys the local sender key.
        /// </summary>
        /// <returns>A CryptoResult containing the new distribution data.</returns>
        CryptoResult<byte[]> ReKey();

        /// <summary>
        /// Removes a participant from the session.
        /// </summary>
        /// <param name="participantId">The participant ID to remove.</param>
        void RemoveParticipant(string participantId);

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
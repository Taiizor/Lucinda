// <copyright file="ISessionStorage.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for secure session storage operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Session storage is used to persist session state between application runs.
    /// Implementations should ensure secure storage of sensitive session data including:
    /// <list type="bullet">
    /// <item><description>Ratchet state (keys, counters)</description></item>
    /// <item><description>Skipped message keys</description></item>
    /// <item><description>Session metadata</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Implementations should securely clear sensitive data from memory when sessions are deleted.
    /// </para>
    /// </remarks>
    public interface ISessionStorage
    {
        /// <summary>
        /// Gets the name of the storage provider.
        /// </summary>
        /// <value>The provider name (e.g., "InMemory", "SQLite", "FileSystem").</value>
        string ProviderName { get; }

        /// <summary>
        /// Stores session data for the specified session ID.
        /// </summary>
        /// <param name="sessionId">The unique identifier for the session.</param>
        /// <param name="sessionData">The serialized session data to store.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure of the operation.
        /// </returns>
        CryptoResult<bool> StoreSession(string sessionId, byte[] sessionData);

        /// <summary>
        /// Loads session data for the specified session ID.
        /// </summary>
        /// <param name="sessionId">The unique identifier for the session.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the session data on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> LoadSession(string sessionId);

        /// <summary>
        /// Deletes session data for the specified session ID.
        /// </summary>
        /// <param name="sessionId">The unique identifier for the session.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure of the operation.
        /// </returns>
        /// <remarks>
        /// Implementations should securely clear the session data from memory/storage.
        /// </remarks>
        CryptoResult<bool> DeleteSession(string sessionId);

        /// <summary>
        /// Checks if a session exists for the specified session ID.
        /// </summary>
        /// <param name="sessionId">The unique identifier for the session.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing true if the session exists, false otherwise.
        /// </returns>
        CryptoResult<bool> SessionExists(string sessionId);

        /// <summary>
        /// Gets all session IDs currently stored.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing an array of session IDs on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<string[]> GetAllSessionIds();
    }
}
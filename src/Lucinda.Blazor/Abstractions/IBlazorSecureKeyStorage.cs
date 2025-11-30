// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Blazor WebAssembly interface for secure key storage operations.
    /// Provides persistent key storage using browser storage APIs (IndexedDB).
    /// All operations are async for browser compatibility.
    /// </summary>
    public interface IBlazorSecureKeyStorage : IAsyncDisposable
    {
        /// <summary>
        /// Gets the name of the storage provider.
        /// </summary>
        string ProviderName { get; }

        /// <summary>
        /// Stores a key securely with the specified identifier.
        /// </summary>
        /// <param name="keyId">The unique identifier for the key.</param>
        /// <param name="keyData">The key data to store.</param>
        /// <param name="keyType">The type of key being stored.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if the key was stored successfully.</returns>
        Task<bool> StoreKeyAsync(
            string keyId,
            byte[] keyData,
            BlazorKeyType keyType,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Stores a key with additional metadata.
        /// </summary>
        /// <param name="keyId">The unique identifier for the key.</param>
        /// <param name="keyData">The key data to store.</param>
        /// <param name="metadata">Additional metadata for the key.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if the key was stored successfully.</returns>
        Task<bool> StoreKeyAsync(
            string keyId,
            byte[] keyData,
            BlazorKeyMetadata metadata,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves a key by its identifier.
        /// </summary>
        /// <param name="keyId">The unique identifier of the key to retrieve.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The key data, or null if not found.</returns>
        Task<byte[]?> RetrieveKeyAsync(
            string keyId,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Deletes a key by its identifier.
        /// </summary>
        /// <param name="keyId">The unique identifier of the key to delete.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if the key was deleted, false if it didn't exist.</returns>
        Task<bool> DeleteKeyAsync(
            string keyId,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Checks if a key exists with the specified identifier.
        /// </summary>
        /// <param name="keyId">The unique identifier to check.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if the key exists.</returns>
        Task<bool> KeyExistsAsync(
            string keyId,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the metadata for a stored key.
        /// </summary>
        /// <param name="keyId">The unique identifier of the key.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The key metadata, or null if not found.</returns>
        Task<BlazorKeyMetadata?> GetKeyMetadataAsync(
            string keyId,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Lists all key identifiers in the storage.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An array of key identifiers.</returns>
        Task<string[]> ListKeyIdsAsync(
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Lists key identifiers filtered by key type.
        /// </summary>
        /// <param name="keyType">The type of keys to list.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An array of key identifiers matching the type.</returns>
        Task<string[]> ListKeyIdsByTypeAsync(
            BlazorKeyType keyType,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears all expired keys from storage.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The number of keys deleted.</returns>
        Task<int> ClearExpiredKeysAsync(
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears all keys from storage.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A task representing the operation.</returns>
        Task ClearAllAsync(
            CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Blazor WebAssembly interface for session storage operations.
    /// Provides persistent session storage using browser storage APIs (IndexedDB).
    /// </summary>
    public interface IBlazorSessionStorage : IAsyncDisposable
    {
        /// <summary>
        /// Gets the name of the storage provider.
        /// </summary>
        string ProviderName { get; }

        /// <summary>
        /// Stores session data for the specified session ID.
        /// </summary>
        /// <param name="sessionId">The unique identifier for the session.</param>
        /// <param name="sessionData">The serialized session data to store.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if the session was stored successfully.</returns>
        Task<bool> StoreSessionAsync(
            string sessionId,
            byte[] sessionData,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Loads session data for the specified session ID.
        /// </summary>
        /// <param name="sessionId">The unique identifier for the session.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The session data, or null if not found.</returns>
        Task<byte[]?> LoadSessionAsync(
            string sessionId,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Deletes session data for the specified session ID.
        /// </summary>
        /// <param name="sessionId">The unique identifier for the session.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if the session was deleted, false if it didn't exist.</returns>
        Task<bool> DeleteSessionAsync(
            string sessionId,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Checks if a session exists for the specified session ID.
        /// </summary>
        /// <param name="sessionId">The unique identifier for the session.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if the session exists.</returns>
        Task<bool> SessionExistsAsync(
            string sessionId,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets all session IDs currently stored.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An array of session IDs.</returns>
        Task<string[]> GetAllSessionIdsAsync(
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears all sessions from storage.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A task representing the operation.</returns>
        Task ClearAllAsync(
            CancellationToken cancellationToken = default);
    }
}
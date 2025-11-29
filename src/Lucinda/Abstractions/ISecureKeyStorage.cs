// <copyright file="ISecureKeyStorage.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
using System.Threading.Tasks;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for secure storage and retrieval of cryptographic keys.
    /// Implementations should provide appropriate security measures for protecting stored keys.
    /// </summary>
    /// <remarks>
    /// Different implementations may use various storage backends:
    /// <list type="bullet">
    /// <item><description>Hardware Security Modules (HSM)</description></item>
    /// <item><description>Operating system key stores (Windows DPAPI, macOS Keychain)</description></item>
    /// <item><description>Encrypted file-based storage</description></item>
    /// <item><description>In-memory protected storage</description></item>
    /// </list>
    /// </remarks>
    public interface ISecureKeyStorage : IDisposable
    {
        /// <summary>
        /// Gets the name of the storage provider.
        /// </summary>
        /// <value>The storage provider name (e.g., "InMemory", "DPAPI", "FileSystem").</value>
        string ProviderName { get; }

        /// <summary>
        /// Stores a key securely with the specified identifier.
        /// </summary>
        /// <param name="keyId">The unique identifier for the key.</param>
        /// <param name="keyData">The key data to store.</param>
        /// <param name="keyType">The type of key being stored.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure of the storage operation.
        /// </returns>
        CryptoResult<bool> StoreKey(string keyId, byte[] keyData, KeyType keyType);

        /// <summary>
        /// Retrieves a key by its identifier.
        /// </summary>
        /// <param name="keyId">The unique identifier of the key to retrieve.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the key data on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> RetrieveKey(string keyId);

        /// <summary>
        /// Deletes a key by its identifier.
        /// </summary>
        /// <param name="keyId">The unique identifier of the key to delete.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure of the deletion.
        /// </returns>
        CryptoResult<bool> DeleteKey(string keyId);

        /// <summary>
        /// Checks if a key exists with the specified identifier.
        /// </summary>
        /// <param name="keyId">The unique identifier to check.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing <c>true</c> if the key exists,
        /// <c>false</c> if it does not, or an error message on failure.
        /// </returns>
        CryptoResult<bool> KeyExists(string keyId);

        /// <summary>
        /// Gets the metadata for a stored key.
        /// </summary>
        /// <param name="keyId">The unique identifier of the key.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the key metadata on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<KeyMetadata> GetKeyMetadata(string keyId);

        /// <summary>
        /// Lists all key identifiers in the storage.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing an array of key identifiers on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<string[]> ListKeyIds();

        /// <summary>
        /// Stores a key securely with the specified identifier asynchronously.
        /// </summary>
        /// <param name="keyId">The unique identifier for the key.</param>
        /// <param name="keyData">The key data to store.</param>
        /// <param name="keyType">The type of key being stored.</param>
        /// <returns>
        /// A task representing the asynchronous operation, containing a <see cref="CryptoResult{T}"/>
        /// indicating success or failure.
        /// </returns>
        Task<CryptoResult<bool>> StoreKeyAsync(string keyId, byte[] keyData, KeyType keyType);

        /// <summary>
        /// Retrieves a key by its identifier asynchronously.
        /// </summary>
        /// <param name="keyId">The unique identifier of the key to retrieve.</param>
        /// <returns>
        /// A task representing the asynchronous operation, containing a <see cref="CryptoResult{T}"/>
        /// with the key data on success.
        /// </returns>
        Task<CryptoResult<byte[]>> RetrieveKeyAsync(string keyId);

        /// <summary>
        /// Deletes a key by its identifier asynchronously.
        /// </summary>
        /// <param name="keyId">The unique identifier of the key to delete.</param>
        /// <returns>
        /// A task representing the asynchronous operation, containing a <see cref="CryptoResult{T}"/>
        /// indicating success or failure.
        /// </returns>
        Task<CryptoResult<bool>> DeleteKeyAsync(string keyId);
    }
}
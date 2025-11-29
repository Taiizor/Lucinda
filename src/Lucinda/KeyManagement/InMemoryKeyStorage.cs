// <copyright file="InMemoryKeyStorage.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
#else
using System.Collections.Concurrent;
#endif

using Lucinda.Abstractions;
using Lucinda.Utilities;

namespace Lucinda.KeyManagement
{
    /// <summary>
    /// Provides in-memory secure storage for cryptographic keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This implementation stores keys in memory with secure clearing on disposal.
    /// Keys are not persisted and will be lost when the application terminates.
    /// </para>
    /// <para>
    /// For production use with persistence requirements, consider implementing
    /// <see cref="ISecureKeyStorage"/> with platform-specific secure storage
    /// (e.g., Windows DPAPI, macOS Keychain, Azure Key Vault).
    /// </para>
    /// </remarks>
    public sealed class InMemoryKeyStorage : ISecureKeyStorage
    {
#if NETFRAMEWORK || NETSTANDARD
        private readonly Dictionary<string, StoredKey> _keys = [];
        private readonly object _lock = new();
#else
        private readonly ConcurrentDictionary<string, StoredKey> _keys = new();
#endif
        private bool _disposed;

        /// <inheritdoc/>
        public string ProviderName => "InMemory";

        /// <inheritdoc/>
        public CryptoResult<bool> StoreKey(string keyId, byte[] keyData, KeyType keyType)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(keyId))
            {
                return CryptoResult<bool>.Failure("Key ID cannot be null or empty.");
            }

            if (keyData == null || keyData.Length == 0)
            {
                return CryptoResult<bool>.Failure("Key data cannot be null or empty.");
            }

            try
            {
                StoredKey storedKey = new()
                {
                    KeyData = CopyArray(keyData),
                    Metadata = new KeyMetadata
                    {
                        KeyId = keyId,
                        KeyType = keyType,
                        KeySizeInBits = keyData.Length * 8,
                        CreatedAt = DateTime.UtcNow,
                        IsActive = true,
                        IsExportable = true
                    }
                };

#if NETFRAMEWORK || NETSTANDARD
                lock (_lock)
                {
                    // Remove existing key if present
                    if (_keys.TryGetValue(keyId, out StoredKey existingKey))
                    {
                        existingKey.Dispose();
                    }
                    _keys[keyId] = storedKey;
                }
#else
                // Remove existing key if present
                if (_keys.TryRemove(keyId, out StoredKey? existingKey))
                {
                    existingKey.Dispose();
                }
                _keys[keyId] = storedKey;
#endif

                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to store key: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> RetrieveKey(string keyId)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(keyId))
            {
                return CryptoResult<byte[]>.Failure("Key ID cannot be null or empty.");
            }

            try
            {
                StoredKey? storedKey;

#if NETFRAMEWORK || NETSTANDARD
                lock (_lock)
                {
                    _keys.TryGetValue(keyId, out storedKey);
                }
#else
                _keys.TryGetValue(keyId, out storedKey);
#endif

                if (storedKey == null)
                {
                    return CryptoResult<byte[]>.Failure($"Key with ID '{keyId}' not found.");
                }

                if (storedKey.Metadata.IsExpired)
                {
                    return CryptoResult<byte[]>.Failure($"Key with ID '{keyId}' has expired.");
                }

                if (!storedKey.Metadata.IsActive)
                {
                    return CryptoResult<byte[]>.Failure($"Key with ID '{keyId}' is not active.");
                }

                return CryptoResult<byte[]>.Success(CopyArray(storedKey.KeyData));
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to retrieve key: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> DeleteKey(string keyId)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(keyId))
            {
                return CryptoResult<bool>.Failure("Key ID cannot be null or empty.");
            }

            try
            {
                StoredKey? storedKey;

#if NETFRAMEWORK || NETSTANDARD
                lock (_lock)
                {
                    if (_keys.TryGetValue(keyId, out storedKey))
                    {
                        _keys.Remove(keyId);
                    }
                }
#else
                _keys.TryRemove(keyId, out storedKey);
#endif

                if (storedKey != null)
                {
                    storedKey.Dispose();
                    return CryptoResult<bool>.Success(true);
                }

                return CryptoResult<bool>.Failure($"Key with ID '{keyId}' not found.");
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to delete key: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> KeyExists(string keyId)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(keyId))
            {
                return CryptoResult<bool>.Failure("Key ID cannot be null or empty.");
            }

            try
            {
                bool exists;
#if NETFRAMEWORK || NETSTANDARD
                lock (_lock)
                {
                    exists = _keys.ContainsKey(keyId);
                }
#else
                exists = _keys.ContainsKey(keyId);
#endif

                return CryptoResult<bool>.Success(exists);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to check key existence: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<KeyMetadata> GetKeyMetadata(string keyId)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(keyId))
            {
                return CryptoResult<KeyMetadata>.Failure("Key ID cannot be null or empty.");
            }

            try
            {
                StoredKey? storedKey;

#if NETFRAMEWORK || NETSTANDARD
                lock (_lock)
                {
                    _keys.TryGetValue(keyId, out storedKey);
                }
#else
                _keys.TryGetValue(keyId, out storedKey);
#endif

                if (storedKey == null)
                {
                    return CryptoResult<KeyMetadata>.Failure($"Key with ID '{keyId}' not found.");
                }

                return CryptoResult<KeyMetadata>.Success(storedKey.Metadata);
            }
            catch (Exception ex)
            {
                return CryptoResult<KeyMetadata>.Failure($"Failed to get key metadata: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<string[]> ListKeyIds()
        {
            ThrowIfDisposed();

            try
            {
                string[] keyIds;
#if NETFRAMEWORK || NETSTANDARD
                lock (_lock)
                {
                    keyIds = new string[_keys.Count];
                    _keys.Keys.CopyTo(keyIds, 0);
                }
#else
                keyIds = [.. _keys.Keys];
#endif

                return CryptoResult<string[]>.Success(keyIds);
            }
            catch (Exception ex)
            {
                return CryptoResult<string[]>.Failure($"Failed to list keys: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public Task<CryptoResult<bool>> StoreKeyAsync(string keyId, byte[] keyData, KeyType keyType)
        {
            return Task.FromResult(StoreKey(keyId, keyData, keyType));
        }

        /// <inheritdoc/>
        public Task<CryptoResult<byte[]>> RetrieveKeyAsync(string keyId)
        {
            return Task.FromResult(RetrieveKey(keyId));
        }

        /// <inheritdoc/>
        public Task<CryptoResult<bool>> DeleteKeyAsync(string keyId)
        {
            return Task.FromResult(DeleteKey(keyId));
        }

        /// <summary>
        /// Sets the expiration time for a stored key.
        /// </summary>
        /// <param name="keyId">The key identifier.</param>
        /// <param name="expiresAt">The expiration time in UTC.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure.
        /// </returns>
        public CryptoResult<bool> SetKeyExpiration(string keyId, DateTime expiresAt)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(keyId))
            {
                return CryptoResult<bool>.Failure("Key ID cannot be null or empty.");
            }

            try
            {
                StoredKey? storedKey;

#if NETFRAMEWORK || NETSTANDARD
                lock (_lock)
                {
                    _keys.TryGetValue(keyId, out storedKey);
                }
#else
                _keys.TryGetValue(keyId, out storedKey);
#endif

                if (storedKey == null)
                {
                    return CryptoResult<bool>.Failure($"Key with ID '{keyId}' not found.");
                }

                storedKey.Metadata.ExpiresAt = expiresAt;
                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to set key expiration: {ex.Message}");
            }
        }

        /// <summary>
        /// Deactivates a stored key without deleting it.
        /// </summary>
        /// <param name="keyId">The key identifier.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure.
        /// </returns>
        public CryptoResult<bool> DeactivateKey(string keyId)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(keyId))
            {
                return CryptoResult<bool>.Failure("Key ID cannot be null or empty.");
            }

            try
            {
                StoredKey? storedKey;

#if NETFRAMEWORK || NETSTANDARD
                lock (_lock)
                {
                    _keys.TryGetValue(keyId, out storedKey);
                }
#else
                _keys.TryGetValue(keyId, out storedKey);
#endif

                if (storedKey == null)
                {
                    return CryptoResult<bool>.Failure($"Key with ID '{keyId}' not found.");
                }

                storedKey.Metadata.IsActive = false;
                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to deactivate key: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

#if NETFRAMEWORK || NETSTANDARD
            lock (_lock)
            {
                foreach (StoredKey key in _keys.Values)
                {
                    key.Dispose();
                }
                _keys.Clear();
            }
#else
            foreach (StoredKey key in _keys.Values)
            {
                key.Dispose();
            }
            _keys.Clear();
#endif

            _disposed = true;
        }

        private static byte[] CopyArray(byte[] source)
        {
            byte[] copy = new byte[source.Length];
            Array.Copy(source, copy, source.Length);
            return copy;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(InMemoryKeyStorage));
            }
        }

        private sealed class StoredKey : IDisposable
        {
            public byte[] KeyData { get; set; } = Array.Empty<byte>();
            public KeyMetadata Metadata { get; set; } = new KeyMetadata();

            public void Dispose()
            {
                CryptoHelpers.SecureClear(KeyData);
            }
        }
    }
}
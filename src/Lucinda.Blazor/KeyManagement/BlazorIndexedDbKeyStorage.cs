// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.KeyManagement
{
    /// <summary>
    /// IndexedDB-based secure key storage for Blazor WebAssembly.
    /// Provides persistent key storage across browser sessions.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="BlazorIndexedDbKeyStorage"/> class.
    /// </remarks>
    /// <param name="cryptoInterop">The Web Crypto interop service.</param>
    public sealed class BlazorIndexedDbKeyStorage(WebCryptoInterop cryptoInterop) : IBlazorSecureKeyStorage
    {
        private readonly WebCryptoInterop _cryptoInterop = cryptoInterop ?? throw new ArgumentNullException(nameof(cryptoInterop));
        private bool _disposed;

        /// <inheritdoc/>
        public string ProviderName => "IndexedDB";

        /// <inheritdoc/>
        public Task<bool> StoreKeyAsync(
            string keyId,
            byte[] keyData,
            BlazorKeyType keyType,
            CancellationToken cancellationToken = default)
        {
            BlazorKeyMetadata metadata = new()
            {
                KeyId = keyId,
                KeyType = keyType,
                KeySizeInBits = keyData.Length * 8,
                CreatedAt = DateTime.UtcNow,
                IsActive = true,
                IsExportable = true
            };

            return StoreKeyAsync(keyId, keyData, metadata, cancellationToken);
        }

        /// <inheritdoc/>
        public async Task<bool> StoreKeyAsync(
            string keyId,
            byte[] keyData,
            BlazorKeyMetadata metadata,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(keyId);
            ArgumentNullException.ThrowIfNull(keyData);
            ArgumentNullException.ThrowIfNull(metadata);

            if (keyData.Length == 0)
            {
                throw new ArgumentException("Key data cannot be empty.", nameof(keyData));
            }

            cancellationToken.ThrowIfCancellationRequested();

            KeyStorageMetadata storageMetadata = new()
            {
                KeyType = (int)metadata.KeyType,
                KeySizeInBits = metadata.KeySizeInBits > 0 ? metadata.KeySizeInBits : keyData.Length * 8,
                Algorithm = metadata.Algorithm,
                CreatedAt = metadata.CreatedAt.ToString("O"),
                ExpiresAt = metadata.ExpiresAt?.ToString("O"),
                IsActive = metadata.IsActive,
                IsExportable = metadata.IsExportable,
                Tags = metadata.Tags
            };

            return await _cryptoInterop.StoreKeyAsync(keyId, keyData, storageMetadata);
        }

        /// <inheritdoc/>
        public async Task<byte[]?> RetrieveKeyAsync(
            string keyId,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(keyId);

            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.RetrieveKeyAsync(keyId);
        }

        /// <inheritdoc/>
        public async Task<bool> DeleteKeyAsync(
            string keyId,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(keyId);

            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.DeleteKeyAsync(keyId);
        }

        /// <inheritdoc/>
        public async Task<bool> KeyExistsAsync(
            string keyId,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(keyId);

            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.KeyExistsAsync(keyId);
        }

        /// <inheritdoc/>
        public async Task<BlazorKeyMetadata?> GetKeyMetadataAsync(
            string keyId,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(keyId);

            cancellationToken.ThrowIfCancellationRequested();

            KeyStorageMetadata? storageMetadata = await _cryptoInterop.GetKeyMetadataAsync(keyId);
            if (storageMetadata == null)
            {
                return null;
            }

            return new BlazorKeyMetadata
            {
                KeyId = keyId,
                KeyType = (BlazorKeyType)storageMetadata.KeyType,
                KeySizeInBits = storageMetadata.KeySizeInBits,
                Algorithm = storageMetadata.Algorithm,
                CreatedAt = DateTime.TryParse(storageMetadata.CreatedAt, out DateTime created) ? created : DateTime.UtcNow,
                ExpiresAt = !string.IsNullOrEmpty(storageMetadata.ExpiresAt) && DateTime.TryParse(storageMetadata.ExpiresAt, out DateTime expires) ? expires : null,
                IsActive = storageMetadata.IsActive,
                IsExportable = storageMetadata.IsExportable,
                Tags = storageMetadata.Tags
            };
        }

        /// <inheritdoc/>
        public async Task<string[]> ListKeyIdsAsync(
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.ListKeyIdsAsync();
        }

        /// <inheritdoc/>
        public async Task<string[]> ListKeyIdsByTypeAsync(
            BlazorKeyType keyType,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.ListKeyIdsByTypeAsync((int)keyType);
        }

        /// <inheritdoc/>
        public async Task<int> ClearExpiredKeysAsync(
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.ClearExpiredKeysAsync();
        }

        /// <inheritdoc/>
        public async Task ClearAllAsync(
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            await _cryptoInterop.ClearAllKeysAsync();
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            await ValueTask.CompletedTask;
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
        }
    }
}
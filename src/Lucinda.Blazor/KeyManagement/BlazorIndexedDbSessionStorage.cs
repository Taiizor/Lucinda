// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.KeyManagement
{
    /// <summary>
    /// IndexedDB-based session storage for Blazor WebAssembly.
    /// Provides persistent session storage across browser sessions.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="BlazorIndexedDbSessionStorage"/> class.
    /// </remarks>
    /// <param name="cryptoInterop">The Web Crypto interop service.</param>
    public sealed class BlazorIndexedDbSessionStorage(WebCryptoInterop cryptoInterop) : IBlazorSessionStorage
    {
        private readonly WebCryptoInterop _cryptoInterop = cryptoInterop ?? throw new ArgumentNullException(nameof(cryptoInterop));
        private bool _disposed;

        /// <inheritdoc/>
        public string ProviderName => "IndexedDB";

        /// <inheritdoc/>
        public async Task<bool> StoreSessionAsync(
            string sessionId,
            byte[] sessionData,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(sessionId);
            ArgumentNullException.ThrowIfNull(sessionData);

            if (sessionData.Length == 0)
            {
                throw new ArgumentException("Session data cannot be empty.", nameof(sessionData));
            }

            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.StoreSessionAsync(sessionId, sessionData);
        }

        /// <inheritdoc/>
        public async Task<byte[]?> LoadSessionAsync(
            string sessionId,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(sessionId);

            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.LoadSessionAsync(sessionId);
        }

        /// <inheritdoc/>
        public async Task<bool> DeleteSessionAsync(
            string sessionId,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(sessionId);

            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.DeleteSessionAsync(sessionId);
        }

        /// <inheritdoc/>
        public async Task<bool> SessionExistsAsync(
            string sessionId,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(sessionId);

            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.SessionExistsAsync(sessionId);
        }

        /// <inheritdoc/>
        public async Task<string[]> GetAllSessionIdsAsync(
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            return await _cryptoInterop.GetAllSessionIdsAsync();
        }

        /// <inheritdoc/>
        public async Task ClearAllAsync(
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            await _cryptoInterop.ClearAllSessionsAsync();
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
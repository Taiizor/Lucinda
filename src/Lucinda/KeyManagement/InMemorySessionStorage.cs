// <copyright file="InMemorySessionStorage.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
using System.Collections.Generic;
using System.Linq;
#endif
using Lucinda.Abstractions;
using Lucinda.Symmetric;
using Lucinda.Utilities;
using System.Collections.Concurrent;

namespace Lucinda.KeyManagement
{
    /// <summary>
    /// Provides in-memory session storage for Double Ratchet sessions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This implementation stores sessions in memory and is suitable for:
    /// <list type="bullet">
    /// <item><description>Development and testing</description></item>
    /// <item><description>Single-session applications</description></item>
    /// <item><description>Short-lived processes</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// For production use with session persistence across restarts, consider
    /// implementing <see cref="ISessionStorage"/> with a database or file-based backend.
    /// </para>
    /// </remarks>
    public sealed class InMemorySessionStorage : ISessionStorage, IDisposable
    {
        private readonly ConcurrentDictionary<string, byte[]> _sessions = new();
        private bool _disposed;

        /// <inheritdoc/>
        public string ProviderName => "InMemory";

        /// <inheritdoc/>
        public CryptoResult<bool> StoreSession(string sessionId, byte[] sessionData)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(sessionId))
            {
                return CryptoResult<bool>.Failure("Session ID cannot be null or empty.");
            }

            if (sessionData == null || sessionData.Length == 0)
            {
                return CryptoResult<bool>.Failure("Session data cannot be null or empty.");
            }

            try
            {
                // Create a copy to avoid external modification
                byte[] dataCopy = [.. sessionData];
                _sessions.AddOrUpdate(sessionId, dataCopy, (_, oldValue) =>
                {
                    // Securely clear old data
                    CryptoHelpers.SecureClear(oldValue);
                    return dataCopy;
                });

                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to store session: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> LoadSession(string sessionId)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(sessionId))
            {
                return CryptoResult<byte[]>.Failure("Session ID cannot be null or empty.");
            }

            try
            {
                if (_sessions.TryGetValue(sessionId, out byte[]? sessionData))
                {
                    // Return a copy to prevent external modification
                    return CryptoResult<byte[]>.Success([.. sessionData]);
                }

                return CryptoResult<byte[]>.Failure($"Session not found: {sessionId}");
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to load session: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> DeleteSession(string sessionId)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(sessionId))
            {
                return CryptoResult<bool>.Failure("Session ID cannot be null or empty.");
            }

            try
            {
                if (_sessions.TryRemove(sessionId, out byte[]? sessionData))
                {
                    // Securely clear removed data
                    CryptoHelpers.SecureClear(sessionData);
                    return CryptoResult<bool>.Success(true);
                }

                return CryptoResult<bool>.Success(false);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to delete session: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> SessionExists(string sessionId)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(sessionId))
            {
                return CryptoResult<bool>.Failure("Session ID cannot be null or empty.");
            }

            return CryptoResult<bool>.Success(_sessions.ContainsKey(sessionId));
        }

        /// <inheritdoc/>
        public CryptoResult<string[]> GetAllSessionIds()
        {
            ThrowIfDisposed();

            try
            {
                return CryptoResult<string[]>.Success([.. _sessions.Keys]);
            }
            catch (Exception ex)
            {
                return CryptoResult<string[]>.Failure($"Failed to get session IDs: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the number of sessions currently stored.
        /// </summary>
        /// <returns>The session count.</returns>
        public int Count => _sessions.Count;

        /// <summary>
        /// Clears all stored sessions.
        /// </summary>
        /// <returns>A result indicating success or failure.</returns>
        public CryptoResult<bool> Clear()
        {
            ThrowIfDisposed();

            try
            {
                foreach (KeyValuePair<string, byte[]> kvp in _sessions)
                {
                    CryptoHelpers.SecureClear(kvp.Value);
                }

                _sessions.Clear();
                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to clear sessions: {ex.Message}");
            }
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(InMemorySessionStorage));
            }
#endif
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (!_disposed)
            {
                // Securely clear all session data
                foreach (KeyValuePair<string, byte[]> kvp in _sessions)
                {
                    CryptoHelpers.SecureClear(kvp.Value);
                }

                _sessions.Clear();
                _disposed = true;
            }
        }
    }
}
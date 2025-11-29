// <copyright file="AsymmetricKeyPair.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Represents an asymmetric key pair containing both public and private key components.
    /// This class provides secure handling of cryptographic key material.
    /// </summary>
    /// <remarks>
    /// Implements <see cref="IDisposable"/> to ensure secure cleanup of sensitive key material.
    /// The private key data is cleared from memory when the object is disposed.
    /// </remarks>
    public sealed class AsymmetricKeyPair : IDisposable
    {
        private byte[] _privateKey;
        private byte[] _publicKey;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKeyPair"/> class.
        /// </summary>
        /// <param name="publicKey">The public key bytes.</param>
        /// <param name="privateKey">The private key bytes.</param>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="publicKey"/> or <paramref name="privateKey"/> is null.
        /// </exception>
        public AsymmetricKeyPair(byte[] publicKey, byte[] privateKey)
        {
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        }

        /// <summary>
        /// Gets a copy of the public key bytes.
        /// </summary>
        /// <value>A new array containing the public key bytes.</value>
        /// <exception cref="ObjectDisposedException">Thrown when the object has been disposed.</exception>
        public byte[] PublicKey
        {
            get
            {
                ThrowIfDisposed();
                byte[] copy = new byte[_publicKey.Length];
                Array.Copy(_publicKey, copy, _publicKey.Length);
                return copy;
            }
        }

        /// <summary>
        /// Gets a copy of the private key bytes.
        /// </summary>
        /// <value>A new array containing the private key bytes.</value>
        /// <exception cref="ObjectDisposedException">Thrown when the object has been disposed.</exception>
        /// <remarks>
        /// Handle the returned key material with care. Consider clearing the array
        /// after use to minimize the time sensitive data remains in memory.
        /// </remarks>
        public byte[] PrivateKey
        {
            get
            {
                ThrowIfDisposed();
                byte[] copy = new byte[_privateKey.Length];
                Array.Copy(_privateKey, copy, _privateKey.Length);
                return copy;
            }
        }

        /// <summary>
        /// Gets the size of the public key in bytes.
        /// </summary>
        /// <value>The public key size in bytes.</value>
        public int PublicKeySize => _publicKey?.Length ?? 0;

        /// <summary>
        /// Gets the size of the private key in bytes.
        /// </summary>
        /// <value>The private key size in bytes.</value>
        public int PrivateKeySize => _privateKey?.Length ?? 0;

        /// <summary>
        /// Releases all resources used by the <see cref="AsymmetricKeyPair"/>.
        /// Securely clears the private key material from memory.
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            // Securely clear private key
            if (_privateKey != null)
            {
                Array.Clear(_privateKey, 0, _privateKey.Length);
                _privateKey = Array.Empty<byte>();
            }

            // Clear public key
            if (_publicKey != null)
            {
                Array.Clear(_publicKey, 0, _publicKey.Length);
                _publicKey = Array.Empty<byte>();
            }

            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(AsymmetricKeyPair));
            }
        }
    }
}
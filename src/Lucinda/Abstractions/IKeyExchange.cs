// <copyright file="IKeyExchange.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for key exchange algorithms.
    /// Key exchange allows two parties to securely establish a shared secret over an insecure channel.
    /// </summary>
    /// <remarks>
    /// Implementations typically use Diffie-Hellman or Elliptic Curve Diffie-Hellman (ECDH) algorithms.
    /// The derived shared secret should be used with a key derivation function before use as an encryption key.
    /// </remarks>
    public interface IKeyExchange : IDisposable
    {
        /// <summary>
        /// Gets the name of the key exchange algorithm.
        /// </summary>
        /// <value>The algorithm name (e.g., "ECDH-P256", "X25519").</value>
        string AlgorithmName { get; }

        /// <summary>
        /// Gets the key size in bits used by this key exchange instance.
        /// </summary>
        /// <value>The key size in bits.</value>
        int KeySizeInBits { get; }

        /// <summary>
        /// Gets a value indicating whether a private key is available.
        /// </summary>
        /// <value><c>true</c> if the private key is available; otherwise, <c>false</c>.</value>
        bool HasPrivateKey { get; }

        /// <summary>
        /// Generates a new key pair for key exchange.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the generated key pair on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<AsymmetricKeyPair> GenerateKeyPair();

        /// <summary>
        /// Derives a shared secret from the local private key and a remote public key.
        /// </summary>
        /// <param name="remotePublicKey">The remote party's public key bytes.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the derived shared secret on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// The shared secret should be passed through a key derivation function (KDF)
        /// before being used as an encryption key. Both parties will derive the same
        /// shared secret when using their respective private keys and the other's public key.
        /// </remarks>
        CryptoResult<byte[]> DeriveSharedSecret(byte[] remotePublicKey);

        /// <summary>
        /// Gets the public key bytes for sharing with the remote party.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the public key bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> GetPublicKey();

        /// <summary>
        /// Imports a private key for key exchange operations.
        /// </summary>
        /// <param name="privateKeyData">The private key data to import.</param>
        /// <param name="format">The format of the key data.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure of the import.
        /// </returns>
        CryptoResult<bool> ImportPrivateKey(byte[] privateKeyData, KeyFormat format);

        /// <summary>
        /// Exports the public key in the specified format.
        /// </summary>
        /// <param name="format">The format to export the key in.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the exported public key bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> ExportPublicKey(KeyFormat format);
    }
}
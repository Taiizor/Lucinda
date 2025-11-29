// <copyright file="IAsymmetricEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for asymmetric (public-key) encryption algorithms.
    /// Asymmetric encryption uses a key pair: a public key for encryption and a private key for decryption.
    /// </summary>
    /// <remarks>
    /// Implementations of this interface should ensure:
    /// <list type="bullet">
    /// <item><description>Secure key pair generation</description></item>
    /// <item><description>Proper handling of public and private key materials</description></item>
    /// <item><description>Support for key import/export in standard formats</description></item>
    /// </list>
    /// </remarks>
    public interface IAsymmetricEncryption : IDisposable
    {
        /// <summary>
        /// Gets the name of the asymmetric encryption algorithm.
        /// </summary>
        /// <value>The algorithm name (e.g., "RSA", "ECDH").</value>
        string AlgorithmName { get; }

        /// <summary>
        /// Gets the key size in bits used by this encryption instance.
        /// </summary>
        /// <value>The key size in bits (e.g., 2048, 3072, 4096 for RSA).</value>
        int KeySizeInBits { get; }

        /// <summary>
        /// Gets a value indicating whether a private key is available for decryption operations.
        /// </summary>
        /// <value><c>true</c> if the private key is available; otherwise, <c>false</c>.</value>
        bool HasPrivateKey { get; }

        /// <summary>
        /// Encrypts the specified plaintext data using the public key.
        /// </summary>
        /// <param name="plaintext">The plaintext data to encrypt.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the encrypted data on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// Due to the size limitations of asymmetric encryption, this method is typically
        /// used for encrypting small amounts of data such as symmetric keys.
        /// For larger data, consider using hybrid encryption with <see cref="IHybridEncryption"/>.
        /// </remarks>
        CryptoResult<byte[]> Encrypt(byte[] plaintext);

        /// <summary>
        /// Decrypts the specified ciphertext data using the private key.
        /// </summary>
        /// <param name="ciphertext">The ciphertext data to decrypt.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted plaintext on success,
        /// or an error message on failure.
        /// </returns>
        /// <exception cref="InvalidOperationException">Thrown when no private key is available.</exception>
        CryptoResult<byte[]> Decrypt(byte[] ciphertext);

        /// <summary>
        /// Generates a new key pair for this asymmetric algorithm.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the generated key pair on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<AsymmetricKeyPair> GenerateKeyPair();

        /// <summary>
        /// Exports the public key in the specified format.
        /// </summary>
        /// <param name="format">The format to export the key in.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the exported public key bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> ExportPublicKey(KeyFormat format);

        /// <summary>
        /// Exports the private key in the specified format.
        /// </summary>
        /// <param name="format">The format to export the key in.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the exported private key bytes on success,
        /// or an error message on failure.
        /// </returns>
        /// <exception cref="InvalidOperationException">Thrown when no private key is available.</exception>
        CryptoResult<byte[]> ExportPrivateKey(KeyFormat format);

        /// <summary>
        /// Imports a public key from the specified bytes.
        /// </summary>
        /// <param name="keyData">The public key data to import.</param>
        /// <param name="format">The format of the key data.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure of the import operation.
        /// </returns>
        CryptoResult<bool> ImportPublicKey(byte[] keyData, KeyFormat format);

        /// <summary>
        /// Imports a private key from the specified bytes.
        /// </summary>
        /// <param name="keyData">The private key data to import.</param>
        /// <param name="format">The format of the key data.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure of the import operation.
        /// </returns>
        CryptoResult<bool> ImportPrivateKey(byte[] keyData, KeyFormat format);
    }
}
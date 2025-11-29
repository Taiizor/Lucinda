// <copyright file="IHybridEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for hybrid encryption, combining asymmetric and symmetric encryption.
    /// Hybrid encryption uses asymmetric encryption to protect a symmetric key, which is then
    /// used to encrypt the actual data.
    /// </summary>
    /// <remarks>
    /// This approach combines the benefits of both encryption types:
    /// <list type="bullet">
    /// <item><description>Asymmetric: Secure key exchange without pre-shared secrets</description></item>
    /// <item><description>Symmetric: Fast encryption of arbitrarily large data</description></item>
    /// </list>
    /// </remarks>
    public interface IHybridEncryption : IDisposable
    {
        /// <summary>
        /// Gets the name of the asymmetric algorithm used for key encapsulation.
        /// </summary>
        /// <value>The asymmetric algorithm name (e.g., "RSA-OAEP", "ECDH").</value>
        string AsymmetricAlgorithmName { get; }

        /// <summary>
        /// Gets the name of the symmetric algorithm used for data encryption.
        /// </summary>
        /// <value>The symmetric algorithm name (e.g., "AES-GCM-256").</value>
        string SymmetricAlgorithmName { get; }

        /// <summary>
        /// Encrypts data using hybrid encryption with the recipient's public key.
        /// </summary>
        /// <param name="plaintext">The plaintext data to encrypt.</param>
        /// <param name="recipientPublicKey">The recipient's public key for encrypting the symmetric key.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the <see cref="HybridEncryptedData"/> on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// The returned data contains both the encrypted symmetric key and the encrypted data.
        /// Only the holder of the corresponding private key can decrypt this data.
        /// </remarks>
        CryptoResult<HybridEncryptedData> Encrypt(byte[] plaintext, byte[] recipientPublicKey);

        /// <summary>
        /// Encrypts data with additional authenticated data using hybrid encryption.
        /// </summary>
        /// <param name="plaintext">The plaintext data to encrypt.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <param name="associatedData">Additional data to authenticate but not encrypt.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the <see cref="HybridEncryptedData"/> on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<HybridEncryptedData> Encrypt(byte[] plaintext, byte[] recipientPublicKey, byte[]? associatedData);

        /// <summary>
        /// Decrypts hybrid-encrypted data using the recipient's private key.
        /// </summary>
        /// <param name="encryptedData">The encrypted data including the encapsulated key.</param>
        /// <param name="recipientPrivateKey">The recipient's private key for decrypting the symmetric key.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted plaintext on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> Decrypt(HybridEncryptedData encryptedData, byte[] recipientPrivateKey);

        /// <summary>
        /// Decrypts hybrid-encrypted data with associated data verification.
        /// </summary>
        /// <param name="encryptedData">The encrypted data including the encapsulated key.</param>
        /// <param name="recipientPrivateKey">The recipient's private key.</param>
        /// <param name="associatedData">Additional data to verify during decryption.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted plaintext on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> Decrypt(HybridEncryptedData encryptedData, byte[] recipientPrivateKey, byte[]? associatedData);
    }
}
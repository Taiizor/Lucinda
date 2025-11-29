// <copyright file="ISymmetricEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for symmetric encryption algorithms.
    /// Symmetric encryption uses the same key for both encryption and decryption operations.
    /// </summary>
    /// <remarks>
    /// Implementations of this interface should ensure:
    /// <list type="bullet">
    /// <item><description>Thread-safe operations for concurrent usage</description></item>
    /// <item><description>Secure memory handling for sensitive data</description></item>
    /// <item><description>Proper disposal of cryptographic resources</description></item>
    /// </list>
    /// </remarks>
    public interface ISymmetricEncryption : IDisposable
    {
        /// <summary>
        /// Gets the name of the symmetric encryption algorithm.
        /// </summary>
        /// <value>The algorithm name (e.g., "AES-GCM", "AES-CBC").</value>
        string AlgorithmName { get; }

        /// <summary>
        /// Gets the key size in bits used by this encryption instance.
        /// </summary>
        /// <value>The key size in bits (e.g., 128, 192, or 256).</value>
        int KeySizeInBits { get; }

        /// <summary>
        /// Gets the block size in bits used by this encryption algorithm.
        /// </summary>
        /// <value>The block size in bits.</value>
        int BlockSizeInBits { get; }

        /// <summary>
        /// Encrypts the specified plaintext data using the current key.
        /// </summary>
        /// <param name="plaintext">The plaintext data to encrypt.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the encrypted data (ciphertext with IV/nonce prepended) 
        /// on success, or an error message on failure.
        /// </returns>
        /// <remarks>
        /// The returned ciphertext includes any necessary initialization vectors (IVs) or nonces
        /// prepended to the encrypted data, allowing for self-contained decryption.
        /// </remarks>
        CryptoResult<byte[]> Encrypt(byte[] plaintext);

        /// <summary>
        /// Encrypts the specified plaintext data with additional authenticated data (AAD).
        /// </summary>
        /// <param name="plaintext">The plaintext data to encrypt.</param>
        /// <param name="associatedData">Additional data to authenticate but not encrypt.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the encrypted and authenticated data on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This method is only supported by authenticated encryption modes (e.g., AES-GCM).
        /// The associated data is authenticated but not encrypted, providing integrity protection
        /// for metadata like headers or timestamps.
        /// </remarks>
        CryptoResult<byte[]> Encrypt(byte[] plaintext, byte[]? associatedData);

        /// <summary>
        /// Decrypts the specified ciphertext data using the current key.
        /// </summary>
        /// <param name="ciphertext">The ciphertext data to decrypt (including IV/nonce).</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted plaintext on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// The ciphertext should include any IVs or nonces that were prepended during encryption.
        /// For authenticated modes, this method will also verify the authentication tag.
        /// </remarks>
        CryptoResult<byte[]> Decrypt(byte[] ciphertext);

        /// <summary>
        /// Decrypts the specified ciphertext data with additional authenticated data verification.
        /// </summary>
        /// <param name="ciphertext">The ciphertext data to decrypt (including IV/nonce and tag).</param>
        /// <param name="associatedData">Additional data to verify during decryption.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted plaintext on success,
        /// or an error message on failure (including authentication failures).
        /// </returns>
        /// <remarks>
        /// The associated data must match exactly what was provided during encryption.
        /// Any mismatch will result in authentication failure and decryption will not proceed.
        /// </remarks>
        CryptoResult<byte[]> Decrypt(byte[] ciphertext, byte[]? associatedData);

        /// <summary>
        /// Generates a new cryptographically secure random key appropriate for this algorithm.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the generated key bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> GenerateKey();

        /// <summary>
        /// Generates a new cryptographically secure random initialization vector (IV) or nonce.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the generated IV/nonce bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> GenerateIV();
    }
}
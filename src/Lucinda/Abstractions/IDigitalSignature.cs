// <copyright file="IDigitalSignature.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for digital signature algorithms.
    /// Digital signatures provide authentication, non-repudiation, and integrity verification.
    /// </summary>
    /// <remarks>
    /// Implementations should support:
    /// <list type="bullet">
    /// <item><description>RSA signatures (PKCS#1 v1.5 and PSS)</description></item>
    /// <item><description>ECDSA signatures</description></item>
    /// <item><description>Various hash algorithms (SHA-256, SHA-384, SHA-512)</description></item>
    /// </list>
    /// </remarks>
    public interface IDigitalSignature : IDisposable
    {
        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        /// <value>The algorithm name (e.g., "RSA-SHA256", "ECDSA-P256").</value>
        string AlgorithmName { get; }

        /// <summary>
        /// Gets the key size in bits used by this signature instance.
        /// </summary>
        /// <value>The key size in bits.</value>
        int KeySizeInBits { get; }

        /// <summary>
        /// Gets a value indicating whether a private key is available for signing.
        /// </summary>
        /// <value><c>true</c> if the private key is available; otherwise, <c>false</c>.</value>
        bool HasPrivateKey { get; }

        /// <summary>
        /// Signs the specified data using the private key.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the digital signature on success,
        /// or an error message on failure.
        /// </returns>
        /// <exception cref="InvalidOperationException">Thrown when no private key is available.</exception>
        CryptoResult<byte[]> Sign(byte[] data);

        /// <summary>
        /// Signs the hash of the data using the private key.
        /// </summary>
        /// <param name="hash">The pre-computed hash of the data to sign.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the digital signature on success,
        /// or an error message on failure.
        /// </returns>
        /// <exception cref="InvalidOperationException">Thrown when no private key is available.</exception>
        /// <remarks>
        /// Use this method when the data has already been hashed.
        /// The hash must match the expected size for the configured hash algorithm.
        /// </remarks>
        CryptoResult<byte[]> SignHash(byte[] hash);

        /// <summary>
        /// Verifies a digital signature against the specified data using the public key.
        /// </summary>
        /// <param name="data">The original data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing <c>true</c> if the signature is valid,
        /// <c>false</c> if invalid, or an error message on failure.
        /// </returns>
        CryptoResult<bool> Verify(byte[] data, byte[] signature);

        /// <summary>
        /// Verifies a digital signature against the pre-computed hash using the public key.
        /// </summary>
        /// <param name="hash">The hash of the original data.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing <c>true</c> if the signature is valid,
        /// <c>false</c> if invalid, or an error message on failure.
        /// </returns>
        CryptoResult<bool> VerifyHash(byte[] hash, byte[] signature);

        /// <summary>
        /// Generates a new key pair for signing and verification.
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
        CryptoResult<byte[]> ExportPrivateKey(KeyFormat format);

        /// <summary>
        /// Imports a public key for signature verification.
        /// </summary>
        /// <param name="keyData">The public key data to import.</param>
        /// <param name="format">The format of the key data.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure of the import.
        /// </returns>
        CryptoResult<bool> ImportPublicKey(byte[] keyData, KeyFormat format);

        /// <summary>
        /// Imports a private key for signing operations.
        /// </summary>
        /// <param name="keyData">The private key data to import.</param>
        /// <param name="format">The format of the key data.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> indicating success or failure of the import.
        /// </returns>
        CryptoResult<bool> ImportPrivateKey(byte[] keyData, KeyFormat format);
    }
}
// <copyright file="IKeyDerivation.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for key derivation functions (KDFs).
    /// Key derivation functions are used to derive cryptographic keys from passwords, 
    /// shared secrets, or other key material.
    /// </summary>
    /// <remarks>
    /// Implementations should support:
    /// <list type="bullet">
    /// <item><description>Password-based key derivation (PBKDF2)</description></item>
    /// <item><description>HMAC-based key derivation (HKDF)</description></item>
    /// <item><description>Configurable parameters for security strength</description></item>
    /// </list>
    /// </remarks>
    public interface IKeyDerivation : IDisposable
    {
        /// <summary>
        /// Gets the name of the key derivation algorithm.
        /// </summary>
        /// <value>The algorithm name (e.g., "PBKDF2-SHA256", "HKDF-SHA256").</value>
        string AlgorithmName { get; }

        /// <summary>
        /// Derives a cryptographic key from the specified password and salt.
        /// </summary>
        /// <param name="password">The password to derive the key from.</param>
        /// <param name="salt">The salt value to use in the derivation.</param>
        /// <param name="iterations">The number of iterations to perform.</param>
        /// <param name="derivedKeyLength">The desired length of the derived key in bytes.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the derived key bytes on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This method is primarily intended for password-based key derivation (PBKDF2).
        /// Higher iteration counts provide better security but require more computation time.
        /// </remarks>
        CryptoResult<byte[]> DeriveKey(string password, byte[] salt, int iterations, int derivedKeyLength);

        /// <summary>
        /// Derives a cryptographic key from the specified input key material.
        /// </summary>
        /// <param name="inputKeyMaterial">The input key material to derive from.</param>
        /// <param name="salt">Optional salt value (can be null for some algorithms).</param>
        /// <param name="info">Optional context information for key separation.</param>
        /// <param name="derivedKeyLength">The desired length of the derived key in bytes.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the derived key bytes on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This method is primarily intended for HKDF-style key derivation from
        /// shared secrets or other high-entropy key material.
        /// </remarks>
        CryptoResult<byte[]> DeriveKey(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int derivedKeyLength);

        /// <summary>
        /// Generates a cryptographically secure random salt of the specified length.
        /// </summary>
        /// <param name="saltLength">The desired length of the salt in bytes.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the generated salt bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> GenerateSalt(int saltLength);
    }
}
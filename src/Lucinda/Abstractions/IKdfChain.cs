// <copyright file="IKdfChain.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Defines the contract for KDF (Key Derivation Function) chain operations used in ratcheting protocols.
    /// </summary>
    /// <remarks>
    /// <para>
    /// KDF chains are used in the Double Ratchet algorithm to derive message keys and advance chain keys.
    /// This interface provides two types of KDF operations:
    /// <list type="bullet">
    /// <item><description>Root KDF: Derives new root key and chain key from DH output</description></item>
    /// <item><description>Chain KDF: Derives message key and advances the chain key</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public interface IKdfChain
    {
        /// <summary>
        /// Gets the name of the KDF algorithm being used.
        /// </summary>
        /// <value>The algorithm name (e.g., "HKDF-SHA256").</value>
        string AlgorithmName { get; }

        /// <summary>
        /// Performs the root key derivation function.
        /// Takes the current root key and DH output to derive a new root key and chain key.
        /// </summary>
        /// <param name="rootKey">The current root key (32 bytes).</param>
        /// <param name="dhOutput">The output from a Diffie-Hellman operation.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing a tuple of (NewRootKey, ChainKey) on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This is used during the DH ratchet step to derive new keys for the symmetric ratchet.
        /// </remarks>
        CryptoResult<(byte[] RootKey, byte[] ChainKey)> RootKdf(byte[] rootKey, byte[] dhOutput);

        /// <summary>
        /// Performs the chain key derivation function.
        /// Derives a message key from the current chain key and advances the chain.
        /// </summary>
        /// <param name="chainKey">The current chain key (32 bytes).</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing a tuple of (MessageKey, NextChainKey) on success,
        /// or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This is used to derive individual message keys while advancing the symmetric ratchet.
        /// </remarks>
        CryptoResult<(byte[] MessageKey, byte[] NextChainKey)> ChainKdf(byte[] chainKey);
    }
}
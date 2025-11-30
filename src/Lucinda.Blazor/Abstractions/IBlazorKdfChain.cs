// <copyright file="IBlazorKdfChain.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for KDF (Key Derivation Function) chain operations 
    /// used in ratcheting protocols for Blazor.
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
    public interface IBlazorKdfChain
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
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with a tuple of (NewRootKey, ChainKey) 
        /// on success, or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This is used during the DH ratchet step to derive new keys for the symmetric ratchet.
        /// </remarks>
        Task<BlazorCryptoResult<(byte[] RootKey, byte[] ChainKey)>> RootKdfAsync(byte[] rootKey, byte[] dhOutput);

        /// <summary>
        /// Performs the chain key derivation function.
        /// Derives a message key from the current chain key and advances the chain.
        /// </summary>
        /// <param name="chainKey">The current chain key (32 bytes).</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with a tuple of (MessageKey, NextChainKey) 
        /// on success, or an error message on failure.
        /// </returns>
        /// <remarks>
        /// This is used to derive individual message keys while advancing the symmetric ratchet.
        /// </remarks>
        Task<BlazorCryptoResult<(byte[] MessageKey, byte[] NextChainKey)>> ChainKdfAsync(byte[] chainKey);
    }
}
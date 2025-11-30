// -----------------------------------------------------------------------
// <copyright file="IBlazorKeyExchange.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for async key exchange operations in Blazor WebAssembly.
    /// </summary>
    public interface IBlazorKeyExchange : IAsyncDisposable
    {
        /// <summary>
        /// Gets the name of the key exchange algorithm.
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// Gets the curve name (for ECDH).
        /// </summary>
        string CurveName { get; }

        /// <summary>
        /// Generates a new key pair asynchronously.
        /// </summary>
        /// <returns>A CryptoResult containing the key pair.</returns>
        Task<CryptoResult<AsymmetricKeyPair>> GenerateKeyPairAsync();

        /// <summary>
        /// Derives a shared secret from the local private key and remote public key asynchronously.
        /// </summary>
        /// <param name="privateKey">The local private key.</param>
        /// <param name="publicKey">The remote public key.</param>
        /// <returns>A CryptoResult containing the shared secret.</returns>
        Task<CryptoResult<byte[]>> DeriveSharedSecretAsync(byte[] privateKey, byte[] publicKey);

        /// <summary>
        /// Derives a shared secret with a specified output length asynchronously.
        /// </summary>
        /// <param name="privateKey">The local private key.</param>
        /// <param name="publicKey">The remote public key.</param>
        /// <param name="outputLengthBytes">The desired output length in bytes.</param>
        /// <returns>A CryptoResult containing the shared secret.</returns>
        Task<CryptoResult<byte[]>> DeriveSharedSecretAsync(byte[] privateKey, byte[] publicKey, int outputLengthBytes);
    }
}
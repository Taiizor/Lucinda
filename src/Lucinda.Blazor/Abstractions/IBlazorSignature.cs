// -----------------------------------------------------------------------
// <copyright file="IBlazorSignature.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for async digital signature operations in Blazor WebAssembly.
    /// </summary>
    public interface IBlazorSignature : IAsyncDisposable
    {
        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// Generates a new key pair for signing asynchronously.
        /// </summary>
        /// <returns>A CryptoResult containing the key pair.</returns>
        Task<CryptoResult<AsymmetricKeyPair>> GenerateKeyPairAsync();

        /// <summary>
        /// Signs data using the private key asynchronously.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="privateKey">The private key used for signing.</param>
        /// <returns>A CryptoResult containing the signature.</returns>
        Task<CryptoResult<byte[]>> SignAsync(byte[] data, byte[] privateKey);

        /// <summary>
        /// Verifies a signature using the public key asynchronously.
        /// </summary>
        /// <param name="data">The original data.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKey">The public key used for verification.</param>
        /// <returns>A CryptoResult containing whether the signature is valid.</returns>
        Task<CryptoResult<bool>> VerifyAsync(byte[] data, byte[] signature, byte[] publicKey);
    }
}
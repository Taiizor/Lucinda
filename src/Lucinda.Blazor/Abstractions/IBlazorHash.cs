// -----------------------------------------------------------------------
// <copyright file="IBlazorHash.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for async hashing operations in Blazor WebAssembly.
    /// </summary>
    public interface IBlazorHash : IAsyncDisposable
    {
        /// <summary>
        /// Gets the name of the hash algorithm.
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// Gets the hash output size in bytes.
        /// </summary>
        int HashSize { get; }

        /// <summary>
        /// Computes a hash of the data asynchronously.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>A CryptoResult containing the hash.</returns>
        Task<CryptoResult<byte[]>> ComputeHashAsync(byte[] data);

        /// <summary>
        /// Computes an HMAC of the data asynchronously.
        /// </summary>
        /// <param name="data">The data to compute HMAC for.</param>
        /// <param name="key">The HMAC key.</param>
        /// <returns>A CryptoResult containing the HMAC.</returns>
        Task<CryptoResult<byte[]>> ComputeHmacAsync(byte[] data, byte[] key);

        /// <summary>
        /// Verifies an HMAC asynchronously.
        /// </summary>
        /// <param name="data">The data to verify.</param>
        /// <param name="expectedHmac">The expected HMAC value.</param>
        /// <param name="key">The HMAC key.</param>
        /// <returns>A CryptoResult containing whether the HMAC is valid.</returns>
        Task<CryptoResult<bool>> VerifyHmacAsync(byte[] data, byte[] expectedHmac, byte[] key);
    }
}
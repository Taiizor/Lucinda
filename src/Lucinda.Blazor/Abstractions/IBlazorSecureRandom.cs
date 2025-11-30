// -----------------------------------------------------------------------
// <copyright file="IBlazorSecureRandom.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for async secure random number generation in Blazor WebAssembly.
    /// </summary>
    public interface IBlazorSecureRandom : IAsyncDisposable
    {
        /// <summary>
        /// Generates a cryptographically secure random byte array asynchronously.
        /// </summary>
        /// <param name="length">The number of random bytes to generate.</param>
        /// <returns>A CryptoResult containing the random bytes.</returns>
        Task<CryptoResult<byte[]>> GenerateBytesAsync(int length);

        /// <summary>
        /// Fills the provided buffer with cryptographically secure random bytes asynchronously.
        /// </summary>
        /// <param name="buffer">The buffer to fill with random bytes.</param>
        /// <returns>A CryptoResult indicating success or failure.</returns>
        Task<CryptoResult<byte[]>> FillAsync(byte[] buffer);

        /// <summary>
        /// Generates a cryptographically secure random integer within the specified range asynchronously.
        /// </summary>
        /// <param name="minValue">The inclusive minimum value.</param>
        /// <param name="maxValue">The exclusive maximum value.</param>
        /// <returns>A CryptoResult containing the random integer.</returns>
        Task<CryptoResult<int>> NextIntAsync(int minValue, int maxValue);
    }
}
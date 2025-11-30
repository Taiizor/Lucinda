// -----------------------------------------------------------------------
// <copyright file="IBlazorPasswordKeyDerivation.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for async password-based key derivation operations in Blazor WebAssembly.
    /// </summary>
    public interface IBlazorPasswordKeyDerivation : IAsyncDisposable
    {
        /// <summary>
        /// Gets the name of the key derivation algorithm.
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// Derives a key from a password asynchronously.
        /// </summary>
        /// <param name="password">The password to derive a key from.</param>
        /// <param name="salt">The salt value.</param>
        /// <param name="outputLength">The desired output length in bytes.</param>
        /// <returns>A CryptoResult containing the derived key.</returns>
        Task<CryptoResult<byte[]>> DeriveKeyAsync(string password, byte[] salt, int outputLength);

        /// <summary>
        /// Derives a key from a password with specified iterations asynchronously.
        /// </summary>
        /// <param name="password">The password to derive a key from.</param>
        /// <param name="salt">The salt value.</param>
        /// <param name="iterations">The number of iterations.</param>
        /// <param name="outputLength">The desired output length in bytes.</param>
        /// <returns>A CryptoResult containing the derived key.</returns>
        Task<CryptoResult<byte[]>> DeriveKeyAsync(string password, byte[] salt, int iterations, int outputLength);

        /// <summary>
        /// Generates a random salt asynchronously.
        /// </summary>
        /// <param name="length">The desired salt length in bytes.</param>
        /// <returns>A CryptoResult containing the generated salt.</returns>
        Task<CryptoResult<byte[]>> GenerateSaltAsync(int length = 16);
    }
}
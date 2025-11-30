// -----------------------------------------------------------------------
// <copyright file="IBlazorKeyDerivation.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for async key derivation operations in Blazor WebAssembly.
    /// </summary>
    public interface IBlazorKeyDerivation : IAsyncDisposable
    {
        /// <summary>
        /// Gets the name of the key derivation algorithm.
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// Derives a key from input keying material asynchronously.
        /// </summary>
        /// <param name="inputKeyMaterial">The input keying material.</param>
        /// <param name="outputLength">The desired output length in bytes.</param>
        /// <returns>A CryptoResult containing the derived key.</returns>
        Task<CryptoResult<byte[]>> DeriveKeyAsync(byte[] inputKeyMaterial, int outputLength);

        /// <summary>
        /// Derives a key from input keying material with salt asynchronously.
        /// </summary>
        /// <param name="inputKeyMaterial">The input keying material.</param>
        /// <param name="salt">The salt value.</param>
        /// <param name="outputLength">The desired output length in bytes.</param>
        /// <returns>A CryptoResult containing the derived key.</returns>
        Task<CryptoResult<byte[]>> DeriveKeyAsync(byte[] inputKeyMaterial, byte[] salt, int outputLength);

        /// <summary>
        /// Derives a key from input keying material with salt and context info asynchronously.
        /// </summary>
        /// <param name="inputKeyMaterial">The input keying material.</param>
        /// <param name="salt">The salt value.</param>
        /// <param name="info">Context and application-specific information.</param>
        /// <param name="outputLength">The desired output length in bytes.</param>
        /// <returns>A CryptoResult containing the derived key.</returns>
        Task<CryptoResult<byte[]>> DeriveKeyAsync(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength);
    }
}
// -----------------------------------------------------------------------
// <copyright file="IBlazorSymmetricEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for async symmetric encryption operations in Blazor WebAssembly.
    /// </summary>
    /// <remarks>
    /// This interface mirrors <see cref="ISymmetricEncryption"/> but with async methods
    /// suitable for JavaScript interop in Blazor WASM.
    /// </remarks>
    public interface IBlazorSymmetricEncryption : IAsyncDisposable
    {
        /// <summary>
        /// Gets the name of the encryption algorithm.
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// Gets the key size in bits.
        /// </summary>
        int KeySize { get; }

        /// <summary>
        /// Encrypts plaintext data with a key asynchronously.
        /// </summary>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <returns>A CryptoResult containing the encrypted data.</returns>
        Task<CryptoResult<byte[]>> EncryptAsync(byte[] plaintext, byte[] key);

        /// <summary>
        /// Encrypts plaintext data with additional authenticated data asynchronously.
        /// </summary>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="associatedData">Additional authenticated data (optional).</param>
        /// <returns>A CryptoResult containing the encrypted data.</returns>
        Task<CryptoResult<byte[]>> EncryptAsync(byte[] plaintext, byte[] key, byte[]? associatedData);

        /// <summary>
        /// Decrypts ciphertext data with a key asynchronously.
        /// </summary>
        /// <param name="ciphertext">The data to decrypt.</param>
        /// <param name="key">The decryption key.</param>
        /// <returns>A CryptoResult containing the decrypted data.</returns>
        Task<CryptoResult<byte[]>> DecryptAsync(byte[] ciphertext, byte[] key);

        /// <summary>
        /// Decrypts ciphertext data with additional authenticated data asynchronously.
        /// </summary>
        /// <param name="ciphertext">The data to decrypt.</param>
        /// <param name="key">The decryption key.</param>
        /// <param name="associatedData">Additional authenticated data (optional).</param>
        /// <returns>A CryptoResult containing the decrypted data.</returns>
        Task<CryptoResult<byte[]>> DecryptAsync(byte[] ciphertext, byte[] key, byte[]? associatedData);

        /// <summary>
        /// Generates a new encryption key asynchronously.
        /// </summary>
        /// <returns>A CryptoResult containing the generated key.</returns>
        Task<CryptoResult<byte[]>> GenerateKeyAsync();

        /// <summary>
        /// Generates a new IV (initialization vector) asynchronously.
        /// </summary>
        /// <returns>A CryptoResult containing the generated IV.</returns>
        Task<CryptoResult<byte[]>> GenerateIvAsync();
    }
}
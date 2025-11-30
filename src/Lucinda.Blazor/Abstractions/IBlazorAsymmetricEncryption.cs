// -----------------------------------------------------------------------
// <copyright file="IBlazorAsymmetricEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Abstractions;

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Defines the contract for async asymmetric encryption operations in Blazor WebAssembly.
    /// </summary>
    public interface IBlazorAsymmetricEncryption : IAsyncDisposable
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
        /// Generates a new key pair asynchronously.
        /// </summary>
        /// <returns>A CryptoResult containing the key pair.</returns>
        Task<CryptoResult<AsymmetricKeyPair>> GenerateKeyPairAsync();

        /// <summary>
        /// Encrypts data using the public key asynchronously.
        /// </summary>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="publicKey">The public key.</param>
        /// <returns>A CryptoResult containing the encrypted data.</returns>
        Task<CryptoResult<byte[]>> EncryptAsync(byte[] plaintext, byte[] publicKey);

        /// <summary>
        /// Decrypts data using the private key asynchronously.
        /// </summary>
        /// <param name="ciphertext">The data to decrypt.</param>
        /// <param name="privateKey">The private key.</param>
        /// <returns>A CryptoResult containing the decrypted data.</returns>
        Task<CryptoResult<byte[]>> DecryptAsync(byte[] ciphertext, byte[] privateKey);
    }
}
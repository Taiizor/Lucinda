// <copyright file="IBlazorHeaderEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Interface for header encryption operations in Double Ratchet for Blazor.
    /// Header encryption protects metadata such as message numbers and ratchet public keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Header encryption provides an additional layer of privacy by encrypting
    /// the message header that contains:
    /// <list type="bullet">
    /// <item><description>DH ratchet public key</description></item>
    /// <item><description>Message number in the sending chain</description></item>
    /// <item><description>Previous chain length</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Without header encryption, these values are visible to anyone who can see
    /// the ciphertext, potentially revealing communication patterns.
    /// </para>
    /// </remarks>
    public interface IBlazorHeaderEncryption
    {
        /// <summary>
        /// Encrypts a header.
        /// </summary>
        /// <param name="headerBytes">The serialized header bytes.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the encrypted header data 
        /// (nonce + ciphertext + tag) on success, or an error message on failure.
        /// </returns>
        Task<BlazorCryptoResult<byte[]>> EncryptAsync(byte[] headerBytes);

        /// <summary>
        /// Decrypts an encrypted header.
        /// </summary>
        /// <param name="encryptedData">The encrypted header data.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> with the decrypted header bytes 
        /// on success, or an error message on failure.
        /// </returns>
        Task<BlazorCryptoResult<byte[]>> DecryptAsync(byte[] encryptedData);

        /// <summary>
        /// Updates the header keys after a DH ratchet step.
        /// </summary>
        /// <param name="newRootKey">The new root key after ratchet.</param>
        /// <returns>
        /// A task containing a <see cref="BlazorCryptoResult{T}"/> indicating success or failure.
        /// </returns>
        Task<BlazorCryptoResult<bool>> RatchetKeysAsync(byte[] newRootKey);
    }
}
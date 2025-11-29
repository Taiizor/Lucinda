// -----------------------------------------------------------------------
// <copyright file="IHeaderEncryption.cs" company="Taiizor">
// Copyright (c) Taiizor. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.
// </copyright>
// -----------------------------------------------------------------------

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Interface for header encryption operations in Double Ratchet.
    /// Header encryption protects metadata such as message numbers and ratchet public keys.
    /// </summary>
    public interface IHeaderEncryption
    {
        /// <summary>
        /// Encrypts a header.
        /// </summary>
        /// <param name="headerBytes">The serialized header bytes.</param>
        /// <returns>A CryptoResult containing the encrypted header data (nonce + ciphertext + tag).</returns>
        CryptoResult<byte[]> Encrypt(byte[] headerBytes);

        /// <summary>
        /// Decrypts an encrypted header.
        /// </summary>
        /// <param name="encryptedData">The encrypted header data.</param>
        /// <returns>A CryptoResult containing the decrypted header bytes.</returns>
        CryptoResult<byte[]> Decrypt(byte[] encryptedData);

        /// <summary>
        /// Updates the header keys after a DH ratchet step.
        /// </summary>
        /// <param name="newRootKey">The new root key after ratchet.</param>
        /// <returns>A CryptoResult indicating success or failure.</returns>
        CryptoResult<bool> RatchetKeys(byte[] newRootKey);
    }
}
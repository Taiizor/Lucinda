// <copyright file="KeyType.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Specifies the type of cryptographic key.
    /// </summary>
    public enum KeyType
    {
        /// <summary>
        /// A symmetric encryption key (e.g., AES key).
        /// Used for both encryption and decryption operations.
        /// </summary>
        Symmetric = 0,

        /// <summary>
        /// An asymmetric public key (e.g., RSA or EC public key).
        /// Used for encryption or signature verification.
        /// </summary>
        PublicKey = 1,

        /// <summary>
        /// An asymmetric private key (e.g., RSA or EC private key).
        /// Used for decryption or signing operations.
        /// </summary>
        PrivateKey = 2,

        /// <summary>
        /// A key pair containing both public and private keys.
        /// </summary>
        KeyPair = 3,

        /// <summary>
        /// A derived key from key derivation functions.
        /// </summary>
        DerivedKey = 4,

        /// <summary>
        /// A master key used for deriving other keys.
        /// </summary>
        MasterKey = 5,

        /// <summary>
        /// A session key for temporary use.
        /// </summary>
        SessionKey = 6,

        /// <summary>
        /// A pre-shared key for symmetric key exchange.
        /// </summary>
        PreSharedKey = 7
    }
}
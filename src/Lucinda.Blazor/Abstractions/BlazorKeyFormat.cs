// <copyright file="BlazorKeyFormat.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Specifies the format for exporting or importing cryptographic keys in Blazor.
    /// These formats align with Web Crypto API supported formats.
    /// </summary>
    public enum BlazorKeyFormat
    {
        /// <summary>
        /// Raw key bytes without any encoding or structure.
        /// Suitable for symmetric keys or when interoperability is not a concern.
        /// Supported by Web Crypto API for symmetric keys and EC public keys.
        /// </summary>
        Raw = 0,

        /// <summary>
        /// PKCS#8 format for private keys.
        /// This is the standard format for storing private key information.
        /// Supported by Web Crypto API for RSA and EC private keys.
        /// </summary>
        Pkcs8 = 1,

        /// <summary>
        /// Subject Public Key Info (SPKI) format for public keys.
        /// This is the standard X.509 format for public keys.
        /// Supported by Web Crypto API for RSA and EC public keys.
        /// </summary>
        SubjectPublicKeyInfo = 2,

        /// <summary>
        /// JSON Web Key (JWK) format.
        /// Used in web applications and APIs for key representation.
        /// Supported by Web Crypto API for all key types.
        /// </summary>
        Jwk = 3
    }
}
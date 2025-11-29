// <copyright file="KeyFormat.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Specifies the format for exporting or importing cryptographic keys.
    /// </summary>
    public enum KeyFormat
    {
        /// <summary>
        /// Raw key bytes without any encoding or structure.
        /// Suitable for symmetric keys or when interoperability is not a concern.
        /// </summary>
        Raw = 0,

        /// <summary>
        /// PKCS#8 format for private keys.
        /// This is the standard format for storing private key information.
        /// </summary>
        Pkcs8 = 1,

        /// <summary>
        /// Subject Public Key Info (SPKI) format for public keys.
        /// This is the standard X.509 format for public keys.
        /// </summary>
        SubjectPublicKeyInfo = 2,

        /// <summary>
        /// RSA-specific format (RSAParameters structure).
        /// Contains the RSA key components directly.
        /// </summary>
        RsaParameters = 3,

        /// <summary>
        /// Elliptic Curve-specific format (ECParameters structure).
        /// Contains the EC key components directly.
        /// </summary>
        EcParameters = 4,

        /// <summary>
        /// PEM-encoded format with base64 encoding and headers.
        /// Commonly used for text-based key storage and transmission.
        /// </summary>
        Pem = 5,

        /// <summary>
        /// JSON Web Key (JWK) format.
        /// Used in web applications and APIs for key representation.
        /// </summary>
        Jwk = 6
    }
}
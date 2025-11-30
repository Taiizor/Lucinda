// -----------------------------------------------------------------------
// <copyright file="LucindaBlazorOptions.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Lucinda.Blazor
{
    /// <summary>
    /// Configuration options for Lucinda Blazor services.
    /// </summary>
    public class LucindaBlazorOptions
    {
        /// <summary>
        /// Gets or sets the AES key size in bits.
        /// Valid values: 128, 192, 256. Default is 256.
        /// </summary>
        public int AesKeySize { get; set; } = 256;

        /// <summary>
        /// Gets or sets whether to use AES-GCM (true) or AES-CBC (false).
        /// Default is true (AES-GCM recommended for authenticated encryption).
        /// </summary>
        public bool UseAesGcm { get; set; } = true;

        /// <summary>
        /// Gets or sets the RSA key size in bits.
        /// Valid values: 1024-4096. Default is 2048.
        /// </summary>
        public int RsaKeySize { get; set; } = 2048;

        /// <summary>
        /// Gets or sets the hash algorithm for RSA-OAEP encryption.
        /// Valid values: SHA-256, SHA-384, SHA-512. Default is SHA-256.
        /// </summary>
        public string RsaHashAlgorithm { get; set; } = "SHA-256";

        /// <summary>
        /// Gets or sets the elliptic curve for ECDH key exchange.
        /// Valid values: P-256, P-384, P-521. Default is P-256.
        /// </summary>
        public string EcdhCurve { get; set; } = "P-256";

        /// <summary>
        /// Gets or sets whether to use ECDSA (true) or RSA-PSS (false) for signatures.
        /// Default is true (ECDSA recommended for performance).
        /// </summary>
        public bool UseEcdsaSignature { get; set; } = true;

        /// <summary>
        /// Gets or sets the elliptic curve for ECDSA signatures.
        /// Valid values: P-256, P-384, P-521. Default is P-256.
        /// </summary>
        public string EcdsaCurve { get; set; } = "P-256";

        /// <summary>
        /// Gets or sets the hash algorithm for ECDSA signatures.
        /// Valid values: SHA-256, SHA-384, SHA-512. Default is SHA-256.
        /// </summary>
        public string EcdsaHashAlgorithm { get; set; } = "SHA-256";

        /// <summary>
        /// Gets or sets the hash algorithm for RSA-PSS signatures.
        /// Valid values: SHA-256, SHA-384, SHA-512. Default is SHA-256.
        /// </summary>
        public string RsaPssHashAlgorithm { get; set; } = "SHA-256";

        /// <summary>
        /// Gets or sets the salt length for RSA-PSS signatures in bytes.
        /// Default is 32 (same as SHA-256 hash output).
        /// </summary>
        public int RsaPssSaltLength { get; set; } = 32;

        /// <summary>
        /// Gets or sets the hash algorithm for HKDF key derivation.
        /// Valid values: SHA-256, SHA-384, SHA-512. Default is SHA-256.
        /// </summary>
        public string HkdfHashAlgorithm { get; set; } = "SHA-256";

        /// <summary>
        /// Gets or sets the hash algorithm for PBKDF2 key derivation.
        /// Valid values: SHA-256, SHA-384, SHA-512. Default is SHA-256.
        /// </summary>
        public string Pbkdf2HashAlgorithm { get; set; } = "SHA-256";

        /// <summary>
        /// Gets or sets the number of iterations for PBKDF2.
        /// OWASP recommends at least 600,000 for SHA-256. Default is 600000.
        /// </summary>
        public int Pbkdf2Iterations { get; set; } = 600000;

        /// <summary>
        /// Gets or sets the default hash algorithm for general hashing operations.
        /// Valid values: SHA-1, SHA-256, SHA-384, SHA-512. Default is SHA-256.
        /// Note: SHA-1 is not recommended for security-sensitive operations.
        /// </summary>
        public string DefaultHashAlgorithm { get; set; } = "SHA-256";
    }
}

// <copyright file="EndToEndEncryptionOptions.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
using System.Security.Cryptography;

namespace Lucinda
{
    /// <summary>
    /// Configuration options for the <see cref="EndToEndEncryption"/> class.
    /// </summary>
    public sealed class EndToEndEncryptionOptions
    {
        /// <summary>
        /// Gets or sets the RSA key size in bits for key encapsulation.
        /// </summary>
        /// <value>The RSA key size in bits. Default is 2048.</value>
        public int RsaKeySizeInBits { get; set; } = 2048;

        /// <summary>
        /// Gets or sets the AES key size in bits for data encryption.
        /// </summary>
        /// <value>The AES key size in bits. Default is 256.</value>
        public int AesKeySizeInBits { get; set; } = 256;

        /// <summary>
        /// Gets or sets the elliptic curve for signatures.
        /// </summary>
        /// <value>The elliptic curve. Default is P-256.</value>
        public ECCurve SignatureCurve { get; set; } = ECCurve.NamedCurves.nistP256;

        /// <summary>
        /// Gets or sets the hash algorithm for key derivation and signatures.
        /// </summary>
        /// <value>The hash algorithm. Default is SHA-256.</value>
        public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

        /// <summary>
        /// Gets or sets a value indicating whether to enable digital signatures.
        /// </summary>
        /// <value><c>true</c> to enable signatures; otherwise, <c>false</c>. Default is true.</value>
        public bool EnableSignatures { get; set; } = true;

        /// <summary>
        /// Creates default options optimized for security.
        /// </summary>
        /// <returns>A new <see cref="EndToEndEncryptionOptions"/> instance with secure defaults.</returns>
        public static EndToEndEncryptionOptions Secure()
        {
            return new EndToEndEncryptionOptions
            {
                RsaKeySizeInBits = 4096,
                AesKeySizeInBits = 256,
                SignatureCurve = ECCurve.NamedCurves.nistP384,
                HashAlgorithm = HashAlgorithmName.SHA384,
                EnableSignatures = true
            };
        }

        /// <summary>
        /// Creates default options optimized for performance.
        /// </summary>
        /// <returns>A new <see cref="EndToEndEncryptionOptions"/> instance with performance-oriented defaults.</returns>
        public static EndToEndEncryptionOptions Fast()
        {
            return new EndToEndEncryptionOptions
            {
                RsaKeySizeInBits = 2048,
                AesKeySizeInBits = 128,
                SignatureCurve = ECCurve.NamedCurves.nistP256,
                HashAlgorithm = HashAlgorithmName.SHA256,
                EnableSignatures = false
            };
        }
    }
}
#endif
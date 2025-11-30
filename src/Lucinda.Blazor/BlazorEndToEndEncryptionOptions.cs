// <copyright file="BlazorEndToEndEncryptionOptions.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor;

/// <summary>
/// Configuration options for the <see cref="BlazorEndToEndEncryption"/> class.
/// </summary>
public sealed class BlazorEndToEndEncryptionOptions
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
    /// Gets or sets the ECDSA curve name for signatures.
    /// </summary>
    /// <value>The ECDSA curve name. Default is "P-256".</value>
    public string SignatureCurve { get; set; } = "P-256";

    /// <summary>
    /// Gets or sets the hash algorithm name for key derivation and signatures.
    /// </summary>
    /// <value>The hash algorithm name. Default is "SHA-256".</value>
    public string HashAlgorithm { get; set; } = "SHA-256";

    /// <summary>
    /// Gets or sets a value indicating whether to enable digital signatures.
    /// </summary>
    /// <value><c>true</c> to enable signatures; otherwise, <c>false</c>. Default is true.</value>
    public bool EnableSignatures { get; set; } = true;

    /// <summary>
    /// Creates default options optimized for security.
    /// </summary>
    /// <returns>A new <see cref="BlazorEndToEndEncryptionOptions"/> instance with secure defaults.</returns>
    public static BlazorEndToEndEncryptionOptions Secure()
    {
        return new BlazorEndToEndEncryptionOptions
        {
            RsaKeySizeInBits = 4096,
            AesKeySizeInBits = 256,
            SignatureCurve = "P-384",
            HashAlgorithm = "SHA-384",
            EnableSignatures = true
        };
    }

    /// <summary>
    /// Creates default options optimized for performance.
    /// </summary>
    /// <returns>A new <see cref="BlazorEndToEndEncryptionOptions"/> instance with performance-oriented defaults.</returns>
    public static BlazorEndToEndEncryptionOptions Fast()
    {
        return new BlazorEndToEndEncryptionOptions
        {
            RsaKeySizeInBits = 2048,
            AesKeySizeInBits = 128,
            SignatureCurve = "P-256",
            HashAlgorithm = "SHA-256",
            EnableSignatures = false
        };
    }
}

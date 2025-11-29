// <copyright file="SecureMessagingOptions.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using System.Security.Cryptography;

namespace Lucinda
{
    /// <summary>
    /// Configuration options for the <see cref="SecureMessaging"/> class.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These options control the cryptographic algorithms and parameters used for
    /// secure messaging with the Signal Protocol-like implementation.
    /// </para>
    /// </remarks>
    public sealed class SecureMessagingOptions
    {
        /// <summary>
        /// Gets or sets the elliptic curve to use for key exchange.
        /// Default is P-256 (NIST P-256).
        /// </summary>
        /// <value>The EC curve for ECDH operations.</value>
        public ECCurve Curve { get; set; } = ECCurve.NamedCurves.nistP256;

        /// <summary>
        /// Gets or sets the hash algorithm for HKDF operations.
        /// Default is SHA-256.
        /// </summary>
        /// <value>The hash algorithm name.</value>
        public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

        /// <summary>
        /// Gets or sets the maximum number of message keys to skip when handling
        /// out-of-order messages.
        /// Default is 100.
        /// </summary>
        /// <value>The maximum skip count.</value>
        public int MaxSkipMessageKeys { get; set; } = 100;

        /// <summary>
        /// Gets or sets the number of one-time pre-keys to generate.
        /// Default is 100.
        /// </summary>
        /// <value>The number of one-time pre-keys.</value>
        public int OneTimePreKeyCount { get; set; } = 100;

        /// <summary>
        /// Gets or sets a value indicating whether to automatically delete
        /// one-time pre-keys after they are used.
        /// Default is true.
        /// </summary>
        /// <value><c>true</c> to auto-delete used keys; otherwise, <c>false</c>.</value>
        public bool AutoDeleteUsedOneTimePreKeys { get; set; } = true;
    }
}
#endif
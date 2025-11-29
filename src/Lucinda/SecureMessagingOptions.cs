// <copyright file="SecureMessagingOptions.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using Lucinda.Abstractions;
using System;
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
        /// <remarks>
        /// This curve is used when <see cref="Curve25519Provider"/> is null.
        /// For Signal Protocol compatibility, consider using X25519 via the
        /// <see cref="Curve25519Provider"/> property instead.
        /// </remarks>
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

        /// <summary>
        /// Gets or sets a value indicating whether to enable header encryption.
        /// When enabled, message headers (containing ratchet public keys and message numbers)
        /// are encrypted to protect metadata.
        /// Default is false.
        /// </summary>
        /// <value><c>true</c> to enable header encryption; otherwise, <c>false</c>.</value>
        public bool EnableHeaderEncryption { get; set; } = false;

        /// <summary>
        /// Gets or sets the signed pre-key rotation interval.
        /// Signed pre-keys should be rotated periodically for security.
        /// Default is 7 days.
        /// </summary>
        /// <value>The rotation interval.</value>
        public TimeSpan SignedPreKeyRotationInterval { get; set; } = TimeSpan.FromDays(7);

        /// <summary>
        /// Gets or sets the session expiration time.
        /// Sessions that have been inactive for longer than this period may be cleaned up.
        /// Default is 30 days.
        /// </summary>
        /// <value>The session expiration time.</value>
        public TimeSpan SessionExpirationTime { get; set; } = TimeSpan.FromDays(30);

        /// <summary>
        /// Gets or sets an optional X25519/Curve25519 implementation provider.
        /// When set, this provider will be used instead of the default NIST curve.
        /// This allows using external libraries like libsodium-net or BouncyCastle
        /// for Signal Protocol compatible key exchange.
        /// Default is null (use NIST curves).
        /// </summary>
        /// <value>The X25519 provider, or null to use default NIST curves.</value>
        /// <example>
        /// <code>
        /// // Example with custom provider
        /// var options = new SecureMessagingOptions
        /// {
        ///     Curve25519Provider = new MySodiumCurve25519Provider()
        /// };
        /// </code>
        /// </example>
        public ICurve25519? Curve25519Provider { get; set; } = null;

        /// <summary>
        /// Gets or sets an optional Ed25519 signature implementation provider.
        /// When set, this provider will be used for signing operations instead of ECDSA.
        /// This allows using external libraries for Signal Protocol compatible signatures.
        /// Default is null (use ECDSA).
        /// </summary>
        /// <value>The Ed25519 provider, or null to use default ECDSA.</value>
        /// <example>
        /// <code>
        /// // Example with custom provider
        /// var options = new SecureMessagingOptions
        /// {
        ///     EdDSAProvider = new MySodiumEd25519Provider()
        /// };
        /// </code>
        /// </example>
        public IEdDSA? EdDSAProvider { get; set; } = null;

        /// <summary>
        /// Gets or sets the maximum chain length before re-keying is required.
        /// This limits the number of messages that can be sent with the same sending chain key.
        /// Default is 2000.
        /// </summary>
        /// <value>The maximum chain length.</value>
        public int MaxChainLength { get; set; } = 2000;

        /// <summary>
        /// Gets or sets a value indicating whether to store skipped message keys.
        /// When enabled, message keys for skipped messages are stored to allow
        /// decryption of out-of-order messages.
        /// Default is true.
        /// </summary>
        /// <value><c>true</c> to store skipped keys; otherwise, <c>false</c>.</value>
        public bool StoreSkippedMessageKeys { get; set; } = true;
    }
}
#endif
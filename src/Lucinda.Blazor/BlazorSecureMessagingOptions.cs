// <copyright file="BlazorSecureMessagingOptions.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor;

/// <summary>
/// Configuration options for the <see cref="BlazorSecureMessaging"/> class.
/// </summary>
/// <remarks>
/// <para>
/// These options control the cryptographic algorithms and parameters used for
/// secure messaging with the Signal Protocol-like implementation in Blazor WebAssembly.
/// </para>
/// </remarks>
public sealed class BlazorSecureMessagingOptions
{
    /// <summary>
    /// Gets or sets the ECDH curve name to use for key exchange.
    /// Default is "P-256" (NIST P-256).
    /// </summary>
    /// <value>The ECDH curve name.</value>
    /// <remarks>
    /// Web Crypto API supports P-256, P-384, and P-521 curves.
    /// </remarks>
    public string CurveName { get; set; } = "P-256";

    /// <summary>
    /// Gets or sets the hash algorithm for HKDF operations.
    /// Default is "SHA-256".
    /// </summary>
    /// <value>The hash algorithm name.</value>
    public string HashAlgorithm { get; set; } = "SHA-256";

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
    /// Gets or sets the signed pre-key rotation interval in days.
    /// Signed pre-keys should be rotated periodically for security.
    /// Default is 7 days.
    /// </summary>
    /// <value>The rotation interval in days.</value>
    public int SignedPreKeyRotationDays { get; set; } = 7;

    /// <summary>
    /// Gets or sets the session expiration time in days.
    /// Sessions that have been inactive for longer than this period may be cleaned up.
    /// Default is 30 days.
    /// </summary>
    /// <value>The session expiration time in days.</value>
    public int SessionExpirationDays { get; set; } = 30;

    /// <summary>
    /// Gets or sets a value indicating whether to persist sessions to IndexedDB.
    /// Default is true.
    /// </summary>
    /// <value><c>true</c> to persist sessions; otherwise, <c>false</c>.</value>
    public bool PersistSessions { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether to persist keys to IndexedDB.
    /// Default is true.
    /// </summary>
    /// <value><c>true</c> to persist keys; otherwise, <c>false</c>.</value>
    public bool PersistKeys { get; set; } = true;
}

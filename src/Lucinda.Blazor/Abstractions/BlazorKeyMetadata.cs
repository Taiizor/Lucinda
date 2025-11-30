// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Represents the type of cryptographic key.
    /// </summary>
    public enum BlazorKeyType
    {
        /// <summary>
        /// Unknown key type.
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// Symmetric key for encryption/decryption (e.g., AES).
        /// </summary>
        Symmetric = 1,

        /// <summary>
        /// Asymmetric public key (e.g., RSA, ECDH, ECDSA public).
        /// </summary>
        PublicKey = 2,

        /// <summary>
        /// Asymmetric private key (e.g., RSA, ECDH, ECDSA private).
        /// </summary>
        PrivateKey = 3,

        /// <summary>
        /// Key used for signing operations.
        /// </summary>
        SigningKey = 4,

        /// <summary>
        /// Key used for verification operations.
        /// </summary>
        VerificationKey = 5,

        /// <summary>
        /// Key exchange key (e.g., ECDH).
        /// </summary>
        KeyExchangeKey = 6,

        /// <summary>
        /// Pre-key for X3DH protocol.
        /// </summary>
        PreKey = 7,

        /// <summary>
        /// One-time pre-key for X3DH protocol.
        /// </summary>
        OneTimePreKey = 8,

        /// <summary>
        /// Identity key for Signal protocol.
        /// </summary>
        IdentityKey = 9,

        /// <summary>
        /// Ratchet key for Double Ratchet protocol.
        /// </summary>
        RatchetKey = 10,

        /// <summary>
        /// Sender key for group messaging.
        /// </summary>
        SenderKey = 11
    }

    /// <summary>
    /// Metadata associated with a stored key.
    /// </summary>
    public sealed class BlazorKeyMetadata
    {
        /// <summary>
        /// Gets or sets the unique identifier for the key.
        /// </summary>
        public string KeyId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the type of the key.
        /// </summary>
        public BlazorKeyType KeyType { get; set; }

        /// <summary>
        /// Gets or sets the key size in bits.
        /// </summary>
        public int KeySizeInBits { get; set; }

        /// <summary>
        /// Gets or sets the algorithm associated with the key.
        /// </summary>
        public string Algorithm { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the date and time when the key was created.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Gets or sets the date and time when the key expires.
        /// </summary>
        public DateTime? ExpiresAt { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the key is active.
        /// </summary>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the key can be exported.
        /// </summary>
        public bool IsExportable { get; set; } = true;

        /// <summary>
        /// Gets or sets custom tags associated with the key.
        /// </summary>
        public Dictionary<string, string> Tags { get; set; } = [];

        /// <summary>
        /// Gets a value indicating whether the key has expired.
        /// </summary>
        public bool IsExpired => ExpiresAt.HasValue && DateTime.UtcNow > ExpiresAt.Value;
    }
}
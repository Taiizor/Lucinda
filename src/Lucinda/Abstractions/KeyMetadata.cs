// <copyright file="KeyMetadata.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Represents metadata associated with a stored cryptographic key.
    /// </summary>
    public sealed class KeyMetadata
    {
        /// <summary>
        /// Gets or sets the unique identifier of the key.
        /// </summary>
        /// <value>The key identifier.</value>
        public string KeyId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the type of the key.
        /// </summary>
        /// <value>The <see cref="Abstractions.KeyType"/> of the key.</value>
        public KeyType KeyType { get; set; }

        /// <summary>
        /// Gets or sets the name of the algorithm associated with this key.
        /// </summary>
        /// <value>The algorithm name (e.g., "AES-256", "RSA-2048").</value>
        public string AlgorithmName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the size of the key in bits.
        /// </summary>
        /// <value>The key size in bits.</value>
        public int KeySizeInBits { get; set; }

        /// <summary>
        /// Gets or sets the date and time when the key was created.
        /// </summary>
        /// <value>The creation timestamp in UTC.</value>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Gets or sets the date and time when the key expires.
        /// </summary>
        /// <value>The expiration timestamp in UTC, or null if the key does not expire.</value>
        public DateTime? ExpiresAt { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the key is exportable.
        /// </summary>
        /// <value><c>true</c> if the key can be exported; otherwise, <c>false</c>.</value>
        public bool IsExportable { get; set; }

        /// <summary>
        /// Gets or sets an optional description of the key's purpose.
        /// </summary>
        /// <value>A description of the key, or null if not provided.</value>
        public string? Description { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the key is currently active.
        /// </summary>
        /// <value><c>true</c> if the key is active; otherwise, <c>false</c>.</value>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// Gets a value indicating whether the key has expired.
        /// </summary>
        /// <value><c>true</c> if the key has expired; otherwise, <c>false</c>.</value>
        public bool IsExpired => ExpiresAt.HasValue && ExpiresAt.Value < DateTime.UtcNow;
    }
}
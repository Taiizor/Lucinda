// -----------------------------------------------------------------------
// <copyright file="ICurve25519.cs" company="Taiizor">
// Copyright (c) Taiizor. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.
// </copyright>
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Interface for Curve25519/X25519 key exchange operations.
    /// Implement this interface to provide X25519 support using external libraries
    /// such as libsodium-net, BouncyCastle, or Noise.NET.
    /// </summary>
    /// <remarks>
    /// X25519 is the Diffie-Hellman function over Curve25519, as specified in RFC 7748.
    /// Signal Protocol uses X25519 for all key exchanges (identity keys, pre-keys, ephemeral keys).
    /// 
    /// Implementation requirements:
    /// - Private keys must be 32 bytes (256 bits)
    /// - Public keys must be 32 bytes (256 bits)
    /// - Shared secrets must be 32 bytes (256 bits)
    /// - Private keys should be clamped according to X25519 specification
    /// </remarks>
    public interface ICurve25519
    {
        /// <summary>
        /// Gets the key size in bytes. Should return 32 for X25519.
        /// </summary>
        int KeySize { get; }

        /// <summary>
        /// Generates a new X25519 key pair.
        /// </summary>
        /// <returns>A CryptoResult containing the key pair (private key, public key).</returns>
        CryptoResult<Curve25519KeyPair> GenerateKeyPair();

        /// <summary>
        /// Computes the shared secret using X25519 Diffie-Hellman.
        /// </summary>
        /// <param name="privateKey">The local private key (32 bytes).</param>
        /// <param name="publicKey">The remote public key (32 bytes).</param>
        /// <returns>A CryptoResult containing the 32-byte shared secret.</returns>
        CryptoResult<byte[]> ComputeSharedSecret(byte[] privateKey, byte[] publicKey);

        /// <summary>
        /// Derives the public key from a private key.
        /// </summary>
        /// <param name="privateKey">The private key (32 bytes).</param>
        /// <returns>A CryptoResult containing the 32-byte public key.</returns>
        CryptoResult<byte[]> GetPublicKey(byte[] privateKey);

        /// <summary>
        /// Validates a public key.
        /// </summary>
        /// <param name="publicKey">The public key to validate.</param>
        /// <returns>True if the public key is valid, false otherwise.</returns>
        bool ValidatePublicKey(byte[] publicKey);
    }

    /// <summary>
    /// Represents an X25519 key pair.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the Curve25519KeyPair class.
    /// </remarks>
    /// <param name="privateKey">The private key.</param>
    /// <param name="publicKey">The public key.</param>
    public class Curve25519KeyPair(byte[] privateKey, byte[] publicKey)
    {
        /// <summary>
        /// Gets the private key (32 bytes).
        /// </summary>
        public byte[] PrivateKey { get; } = privateKey ?? throw new ArgumentNullException(nameof(privateKey));

        /// <summary>
        /// Gets the public key (32 bytes).
        /// </summary>
        public byte[] PublicKey { get; } = publicKey ?? throw new ArgumentNullException(nameof(publicKey));

        /// <summary>
        /// Securely clears the key material from memory.
        /// </summary>
        public void Clear()
        {
#if NET6_0_OR_GREATER
            CryptographicOperations.ZeroMemory(PrivateKey);
            CryptographicOperations.ZeroMemory(PublicKey);
#else
            Array.Clear(PrivateKey, 0, PrivateKey.Length);
            Array.Clear(PublicKey, 0, PublicKey.Length);
#endif
        }
    }
}
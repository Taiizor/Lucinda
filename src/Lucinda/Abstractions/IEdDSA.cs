// -----------------------------------------------------------------------
// <copyright file="IEdDSA.cs" company="Taiizor">
// Copyright (c) Taiizor. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.
// </copyright>
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Interface for Ed25519 digital signature operations.
    /// Implement this interface to provide Ed25519 support using external libraries
    /// such as libsodium-net, BouncyCastle, or NSec.
    /// </summary>
    /// <remarks>
    /// Ed25519 is an EdDSA signature scheme using SHA-512 and Curve25519, as specified in RFC 8032.
    /// Signal Protocol uses Ed25519 for signing identity keys and pre-keys.
    /// 
    /// Implementation requirements:
    /// - Private keys must be 32 bytes (256 bits) or 64 bytes (expanded)
    /// - Public keys must be 32 bytes (256 bits)
    /// - Signatures must be 64 bytes (512 bits)
    /// - Must be deterministic (same message + key = same signature)
    /// </remarks>
    public interface IEdDSA
    {
        /// <summary>
        /// Gets the private key size in bytes. Should return 32 or 64 for Ed25519.
        /// </summary>
        int PrivateKeySize { get; }

        /// <summary>
        /// Gets the public key size in bytes. Should return 32 for Ed25519.
        /// </summary>
        int PublicKeySize { get; }

        /// <summary>
        /// Gets the signature size in bytes. Should return 64 for Ed25519.
        /// </summary>
        int SignatureSize { get; }

        /// <summary>
        /// Generates a new Ed25519 key pair.
        /// </summary>
        /// <returns>A CryptoResult containing the key pair (private key, public key).</returns>
        CryptoResult<EdDSAKeyPair> GenerateKeyPair();

        /// <summary>
        /// Signs a message using Ed25519.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="message">The message to sign.</param>
        /// <returns>A CryptoResult containing the 64-byte signature.</returns>
        CryptoResult<byte[]> Sign(byte[] privateKey, byte[] message);

        /// <summary>
        /// Verifies an Ed25519 signature.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="message">The original message.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>A CryptoResult containing true if valid, false otherwise.</returns>
        CryptoResult<bool> Verify(byte[] publicKey, byte[] message, byte[] signature);

        /// <summary>
        /// Derives the public key from a private key.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <returns>A CryptoResult containing the 32-byte public key.</returns>
        CryptoResult<byte[]> GetPublicKey(byte[] privateKey);
    }

    /// <summary>
    /// Represents an Ed25519 key pair.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the EdDSAKeyPair class.
    /// </remarks>
    /// <param name="privateKey">The private key.</param>
    /// <param name="publicKey">The public key.</param>
    public class EdDSAKeyPair(byte[] privateKey, byte[] publicKey)
    {
        /// <summary>
        /// Gets the private key (32 or 64 bytes depending on implementation).
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
// <copyright file="ICryptoProvider.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Abstractions;

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Platform
{
    /// <summary>
    /// Provides a platform-agnostic factory interface for creating cryptographic implementations.
    /// This interface enables runtime selection of appropriate crypto providers based on platform capabilities.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This interface is the main entry point for creating cryptographic instances in a platform-independent manner.
    /// It abstracts the underlying platform differences between native .NET and browser (WebAssembly) environments.
    /// </para>
    /// <para>
    /// In native environments, implementations use the standard System.Security.Cryptography APIs.
    /// In browser environments (Blazor WebAssembly), implementations use the Web Crypto API via JavaScript interop.
    /// </para>
    /// </remarks>
    public interface ICryptoProvider : IDisposable
    {
        /// <summary>
        /// Gets the platform type this provider is designed for.
        /// </summary>
        /// <value>The <see cref="CryptoPlatformType"/> this provider supports.</value>
        CryptoPlatformType PlatformType { get; }

        /// <summary>
        /// Gets a value indicating whether this provider is available on the current platform.
        /// </summary>
        /// <value><c>true</c> if the provider can be used; otherwise, <c>false</c>.</value>
        bool IsAvailable { get; }

        /// <summary>
        /// Creates an AES-GCM symmetric encryption instance.
        /// </summary>
        /// <param name="key">The encryption key (16, 24, or 32 bytes for AES-128/192/256).</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the symmetric encryption instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<ISymmetricEncryption> CreateAesGcm(byte[] key);

        /// <summary>
        /// Creates an AES-CBC symmetric encryption instance with HMAC authentication.
        /// </summary>
        /// <param name="key">The encryption key (16, 24, or 32 bytes for AES-128/192/256).</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the symmetric encryption instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<ISymmetricEncryption> CreateAesCbc(byte[] key);

        /// <summary>
        /// Creates an RSA asymmetric encryption instance with the specified key size.
        /// </summary>
        /// <param name="keySizeInBits">The key size in bits (2048, 3072, or 4096).</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the asymmetric encryption instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<IAsymmetricEncryption> CreateRsa(int keySizeInBits = 2048);

        /// <summary>
        /// Creates an RSA asymmetric encryption instance from existing key data.
        /// </summary>
        /// <param name="keyData">The key data to import.</param>
        /// <param name="format">The format of the key data.</param>
        /// <param name="isPrivateKey">Whether the key data contains a private key.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the asymmetric encryption instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<IAsymmetricEncryption> CreateRsa(byte[] keyData, KeyFormat format, bool isPrivateKey);

        /// <summary>
        /// Creates an ECDH key exchange instance with the specified curve.
        /// </summary>
        /// <param name="curveName">The elliptic curve name (e.g., "P-256", "P-384", "P-521").</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the key exchange instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<IKeyExchange> CreateEcdh(string curveName = "P-256");

        /// <summary>
        /// Creates an ECDH key exchange instance from existing key data.
        /// </summary>
        /// <param name="keyData">The key data to import.</param>
        /// <param name="format">The format of the key data.</param>
        /// <param name="curveName">The elliptic curve name.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the key exchange instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<IKeyExchange> CreateEcdh(byte[] keyData, KeyFormat format, string curveName = "P-256");

        /// <summary>
        /// Creates an ECDSA digital signature instance with the specified curve.
        /// </summary>
        /// <param name="curveName">The elliptic curve name (e.g., "P-256", "P-384", "P-521").</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the digital signature instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<IDigitalSignature> CreateEcdsa(string curveName = "P-256");

        /// <summary>
        /// Creates an ECDSA digital signature instance from existing key data.
        /// </summary>
        /// <param name="keyData">The key data to import.</param>
        /// <param name="format">The format of the key data.</param>
        /// <param name="isPrivateKey">Whether the key data contains a private key.</param>
        /// <param name="curveName">The elliptic curve name.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the digital signature instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<IDigitalSignature> CreateEcdsa(byte[] keyData, KeyFormat format, bool isPrivateKey, string curveName = "P-256");

        /// <summary>
        /// Creates an RSA digital signature instance with the specified key size.
        /// </summary>
        /// <param name="keySizeInBits">The key size in bits (2048, 3072, or 4096).</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the digital signature instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<IDigitalSignature> CreateRsaSignature(int keySizeInBits = 2048);

        /// <summary>
        /// Creates an HKDF key derivation instance.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm name (e.g., "SHA256", "SHA384", "SHA512").</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the key derivation instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<IKeyDerivation> CreateHkdf(string hashAlgorithm = "SHA256");

        /// <summary>
        /// Creates a PBKDF2 key derivation instance.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm name (e.g., "SHA256", "SHA384", "SHA512").</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the key derivation instance on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<IKeyDerivation> CreatePbkdf2(string hashAlgorithm = "SHA256");

        /// <summary>
        /// Generates cryptographically secure random bytes.
        /// </summary>
        /// <param name="length">The number of random bytes to generate.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the random bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> GenerateRandomBytes(int length);

        /// <summary>
        /// Computes a SHA-256 hash of the specified data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the hash bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> ComputeSha256(byte[] data);

        /// <summary>
        /// Computes a SHA-384 hash of the specified data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the hash bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> ComputeSha384(byte[] data);

        /// <summary>
        /// Computes a SHA-512 hash of the specified data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the hash bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> ComputeSha512(byte[] data);

        /// <summary>
        /// Computes an HMAC using the specified hash algorithm.
        /// </summary>
        /// <param name="key">The HMAC key.</param>
        /// <param name="data">The data to authenticate.</param>
        /// <param name="hashAlgorithm">The hash algorithm name (e.g., "SHA256", "SHA384", "SHA512").</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the HMAC bytes on success,
        /// or an error message on failure.
        /// </returns>
        CryptoResult<byte[]> ComputeHmac(byte[] key, byte[] data, string hashAlgorithm = "SHA256");
    }
}
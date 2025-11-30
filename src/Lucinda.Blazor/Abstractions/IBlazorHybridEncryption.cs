// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Blazor WebAssembly interface for hybrid encryption operations.
    /// Combines asymmetric encryption (for key encapsulation) with symmetric encryption (for data).
    /// All operations are async for Web Crypto API compatibility.
    /// </summary>
    public interface IBlazorHybridEncryption : IAsyncDisposable
    {
        /// <summary>
        /// Gets the name of the asymmetric algorithm used for key encapsulation.
        /// </summary>
        string AsymmetricAlgorithmName { get; }

        /// <summary>
        /// Gets the name of the symmetric algorithm used for data encryption.
        /// </summary>
        string SymmetricAlgorithmName { get; }

        /// <summary>
        /// Encrypts plaintext using hybrid encryption.
        /// Generates a random symmetric key, encrypts the data with it,
        /// then encrypts the symmetric key with the recipient's public key.
        /// </summary>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="recipientPublicKey">The recipient's RSA public key (SPKI format).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The hybrid encrypted data containing both the encapsulated key and ciphertext.</returns>
        Task<BlazorHybridEncryptedData> EncryptAsync(
            byte[] plaintext,
            byte[] recipientPublicKey,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Encrypts plaintext using hybrid encryption with associated data.
        /// The associated data is authenticated but not encrypted.
        /// </summary>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="recipientPublicKey">The recipient's RSA public key (SPKI format).</param>
        /// <param name="associatedData">Additional data to authenticate but not encrypt.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The hybrid encrypted data containing both the encapsulated key and ciphertext.</returns>
        Task<BlazorHybridEncryptedData> EncryptAsync(
            byte[] plaintext,
            byte[] recipientPublicKey,
            byte[]? associatedData,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Decrypts hybrid encrypted data.
        /// First decrypts the symmetric key using the recipient's private key,
        /// then uses it to decrypt the actual data.
        /// </summary>
        /// <param name="encryptedData">The hybrid encrypted data to decrypt.</param>
        /// <param name="recipientPrivateKey">The recipient's RSA private key (PKCS8 format).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The decrypted plaintext.</returns>
        Task<byte[]> DecryptAsync(
            BlazorHybridEncryptedData encryptedData,
            byte[] recipientPrivateKey,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Decrypts hybrid encrypted data with associated data verification.
        /// </summary>
        /// <param name="encryptedData">The hybrid encrypted data to decrypt.</param>
        /// <param name="recipientPrivateKey">The recipient's RSA private key (PKCS8 format).</param>
        /// <param name="associatedData">The associated data that was used during encryption.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The decrypted plaintext.</returns>
        Task<byte[]> DecryptAsync(
            BlazorHybridEncryptedData encryptedData,
            byte[] recipientPrivateKey,
            byte[]? associatedData,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Generates a new RSA key pair for hybrid encryption.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A tuple containing the public key (SPKI) and private key (PKCS8).</returns>
        Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateKeyPairAsync(
            CancellationToken cancellationToken = default);
    }
}
// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.Asymmetric
{
    /// <summary>
    /// RSA-AES hybrid encryption implementation for Blazor WebAssembly.
    /// Uses RSA-OAEP for key encapsulation and AES-GCM for data encryption.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="BlazorRsaAesHybridEncryption"/> class.
    /// </remarks>
    /// <param name="cryptoInterop">The Web Crypto interop service.</param>
    public sealed class BlazorRsaAesHybridEncryption(WebCryptoInterop cryptoInterop) : IBlazorHybridEncryption
    {
        private readonly WebCryptoInterop _cryptoInterop = cryptoInterop ?? throw new ArgumentNullException(nameof(cryptoInterop));
        private bool _disposed;

        /// <summary>
        /// Default AES key size in bits.
        /// </summary>
        public const int DefaultAesKeySize = 256;

        /// <summary>
        /// Default RSA modulus length in bits.
        /// </summary>
        public const int DefaultRsaModulusLength = 2048;

        /// <inheritdoc/>
        public string AsymmetricAlgorithmName => "RSA-OAEP";

        /// <inheritdoc/>
        public string SymmetricAlgorithmName => "AES-GCM-256";

        /// <inheritdoc/>
        public Task<BlazorHybridEncryptedData> EncryptAsync(
            byte[] plaintext,
            byte[] recipientPublicKey,
            CancellationToken cancellationToken = default)
        {
            return EncryptAsync(plaintext, recipientPublicKey, null, cancellationToken);
        }

        /// <inheritdoc/>
        public async Task<BlazorHybridEncryptedData> EncryptAsync(
            byte[] plaintext,
            byte[] recipientPublicKey,
            byte[]? associatedData,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(plaintext);
            ArgumentNullException.ThrowIfNull(recipientPublicKey);

            // Generate a random AES key for this message
            byte[] aesKey = await _cryptoInterop.GetRandomBytesAsync(DefaultAesKeySize / 8);
            cancellationToken.ThrowIfCancellationRequested();

            // Encrypt the AES key with RSA-OAEP (key encapsulation)
            byte[] encapsulatedKey = await _cryptoInterop.RsaEncryptAsync(recipientPublicKey, aesKey);
            cancellationToken.ThrowIfCancellationRequested();

            // Encrypt the plaintext with AES-GCM
            // The AES-GCM encryption includes IV in the output
            byte[] ciphertext = await _cryptoInterop.AesGcmEncryptAsync(aesKey, plaintext, associatedData);
            cancellationToken.ThrowIfCancellationRequested();

            // Securely clear the AES key from memory
            Array.Clear(aesKey, 0, aesKey.Length);

            return new BlazorHybridEncryptedData(encapsulatedKey, ciphertext);
        }

        /// <inheritdoc/>
        public Task<byte[]> DecryptAsync(
            BlazorHybridEncryptedData encryptedData,
            byte[] recipientPrivateKey,
            CancellationToken cancellationToken = default)
        {
            return DecryptAsync(encryptedData, recipientPrivateKey, null, cancellationToken);
        }

        /// <inheritdoc/>
        public async Task<byte[]> DecryptAsync(
            BlazorHybridEncryptedData encryptedData,
            byte[] recipientPrivateKey,
            byte[]? associatedData,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(encryptedData);
            ArgumentNullException.ThrowIfNull(recipientPrivateKey);

            // Decrypt the AES key using RSA-OAEP
            byte[] aesKey = await _cryptoInterop.RsaDecryptAsync(recipientPrivateKey, encryptedData.EncapsulatedKey);
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                // Decrypt the ciphertext using AES-GCM
                byte[] plaintext = await _cryptoInterop.AesGcmDecryptAsync(aesKey, encryptedData.Ciphertext, associatedData);
                return plaintext;
            }
            finally
            {
                // Securely clear the AES key from memory
                Array.Clear(aesKey, 0, aesKey.Length);
            }
        }

        /// <inheritdoc/>
        public async Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateKeyPairAsync(
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            (byte[] PublicKey, byte[] PrivateKey) keyPair = await _cryptoInterop.GenerateRsaKeyPairAsync(DefaultRsaModulusLength);
            return keyPair;
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            await ValueTask.CompletedTask;
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
        }
    }
}
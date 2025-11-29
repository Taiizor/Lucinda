// <copyright file="RsaAesHybridEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
using Lucinda.Abstractions;
using Lucinda.Symmetric;
using Lucinda.Utilities;
using System.Security.Cryptography;

namespace Lucinda.Asymmetric
{
    /// <summary>
    /// Provides hybrid encryption using RSA for key encapsulation and AES-GCM for data encryption.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Hybrid encryption combines the benefits of asymmetric and symmetric encryption:
    /// <list type="bullet">
    /// <item><description>RSA encrypts a randomly generated AES key (key encapsulation)</description></item>
    /// <item><description>AES-GCM encrypts the actual data with authenticated encryption</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// This approach allows encrypting data of any size while maintaining the security
    /// benefits of public-key cryptography for key exchange.
    /// </para>
    /// </remarks>
    public sealed class RsaAesHybridEncryption : IHybridEncryption
    {
        private readonly int _rsaKeySizeInBits;
        private readonly int _aesKeySizeInBits;
        private readonly RSAEncryptionPadding _rsaPadding;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAesHybridEncryption"/> class.
        /// </summary>
        /// <param name="rsaKeySizeInBits">The RSA key size in bits. Default is 2048.</param>
        /// <param name="aesKeySizeInBits">The AES key size in bits. Default is 256.</param>
        /// <param name="rsaPadding">The RSA padding mode. Default is OAEP with SHA-256.</param>
        public RsaAesHybridEncryption(
            int rsaKeySizeInBits = 2048,
            int aesKeySizeInBits = 256,
            RSAEncryptionPadding? rsaPadding = null)
        {
            ValidateRsaKeySize(rsaKeySizeInBits);
            ValidateAesKeySize(aesKeySizeInBits);

            _rsaKeySizeInBits = rsaKeySizeInBits;
            _aesKeySizeInBits = aesKeySizeInBits;
            _rsaPadding = rsaPadding ?? RSAEncryptionPadding.OaepSHA256;
        }

        /// <inheritdoc/>
        public string AsymmetricAlgorithmName => $"RSA-{_rsaKeySizeInBits}";

        /// <inheritdoc/>
        public string SymmetricAlgorithmName => $"AES-GCM-{_aesKeySizeInBits}";

        /// <inheritdoc/>
        public CryptoResult<HybridEncryptedData> Encrypt(byte[] plaintext, byte[] recipientPublicKey)
        {
            return Encrypt(plaintext, recipientPublicKey, null);
        }

        /// <inheritdoc/>
        public CryptoResult<HybridEncryptedData> Encrypt(
            byte[] plaintext,
            byte[] recipientPublicKey,
            byte[]? associatedData)
        {
            ThrowIfDisposed();

            if (plaintext == null)
            {
                return CryptoResult<HybridEncryptedData>.Failure("Plaintext cannot be null.");
            }

            if (recipientPublicKey == null)
            {
                return CryptoResult<HybridEncryptedData>.Failure("Recipient public key cannot be null.");
            }

            try
            {
                // Generate a random AES key
                byte[] aesKey = SecureRandom.GenerateKey(_aesKeySizeInBits);

                try
                {
                    // Encrypt the data with AES-GCM
                    byte[] ciphertext;
                    using (AesGcmEncryption aes = new(aesKey))
                    {
                        CryptoResult<byte[]> encryptResult = aes.Encrypt(plaintext, associatedData);
                        if (encryptResult.IsFailure)
                        {
                            return CryptoResult<HybridEncryptedData>.Failure(encryptResult.Error);
                        }
                        ciphertext = encryptResult.Value;
                    }

                    // Encrypt the AES key with RSA
                    byte[] encapsulatedKey;
                    using (RSA rsa = RSA.Create())
                    {
                        rsa.ImportSubjectPublicKeyInfo(recipientPublicKey, out _);
                        encapsulatedKey = rsa.Encrypt(aesKey, _rsaPadding);
                    }

                    HybridEncryptedData result = new(encapsulatedKey, ciphertext)
                    {
                        Version = 1
                    };

                    return CryptoResult<HybridEncryptedData>.Success(result);
                }
                finally
                {
                    // Securely clear the AES key
                    CryptoHelpers.SecureClear(aesKey);
                }
            }
            catch (Exception ex)
            {
                return CryptoResult<HybridEncryptedData>.Failure($"Encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Decrypt(HybridEncryptedData encryptedData, byte[] recipientPrivateKey)
        {
            return Decrypt(encryptedData, recipientPrivateKey, null);
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Decrypt(
            HybridEncryptedData encryptedData,
            byte[] recipientPrivateKey,
            byte[]? associatedData)
        {
            ThrowIfDisposed();

            if (encryptedData == null)
            {
                return CryptoResult<byte[]>.Failure("Encrypted data cannot be null.");
            }

            if (recipientPrivateKey == null)
            {
                return CryptoResult<byte[]>.Failure("Recipient private key cannot be null.");
            }

            try
            {
                // Decrypt the AES key with RSA
                byte[] aesKey;
                using (RSA rsa = RSA.Create())
                {
                    rsa.ImportPkcs8PrivateKey(recipientPrivateKey, out _);
                    aesKey = rsa.Decrypt(encryptedData.EncapsulatedKey, _rsaPadding);
                }

                try
                {
                    // Decrypt the data with AES-GCM
                    using AesGcmEncryption aes = new(aesKey);
                    return aes.Decrypt(encryptedData.Ciphertext, associatedData);
                }
                finally
                {
                    // Securely clear the AES key
                    CryptoHelpers.SecureClear(aesKey);
                }
            }
            catch (CryptographicException ex)
            {
                return CryptoResult<byte[]>.Failure($"Decryption failed: {ex.Message}");
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Decryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Generates a new RSA key pair for use with this hybrid encryption scheme.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the generated key pair on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<AsymmetricKeyPair> GenerateKeyPair()
        {
            ThrowIfDisposed();

            try
            {
                using RSA rsa = RSA.Create(_rsaKeySizeInBits);
                byte[] publicKey = rsa.ExportSubjectPublicKeyInfo();
                byte[] privateKey = rsa.ExportPkcs8PrivateKey();

                return CryptoResult<AsymmetricKeyPair>.Success(
                    new AsymmetricKeyPair(publicKey, privateKey));
            }
            catch (Exception ex)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure($"Key pair generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _disposed = true;
        }

        private static void ValidateRsaKeySize(int keySizeInBits)
        {
            if (keySizeInBits < 2048)
            {
                throw new ArgumentException(
                    "RSA key size must be at least 2048 bits for security reasons.",
                    nameof(keySizeInBits));
            }
        }

        private static void ValidateAesKeySize(int keySizeInBits)
        {
            if (keySizeInBits is not 128 and not 192 and not 256)
            {
                throw new ArgumentException(
                    "AES key size must be 128, 192, or 256 bits.",
                    nameof(keySizeInBits));
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(RsaAesHybridEncryption));
            }
        }
    }
}
#endif
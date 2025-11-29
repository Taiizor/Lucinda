// <copyright file="AesGcmEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
using System.Security.Cryptography;
#else
using System.Security.Cryptography;
#endif

using Lucinda.Abstractions;
using Lucinda.Utilities;

namespace Lucinda.Symmetric
{
    /// <summary>
    /// Provides AES-GCM (Galois/Counter Mode) authenticated encryption.
    /// AES-GCM provides both confidentiality and integrity protection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// AES-GCM is an authenticated encryption algorithm that provides:
    /// <list type="bullet">
    /// <item><description>Data confidentiality through encryption</description></item>
    /// <item><description>Data integrity through authentication tag</description></item>
    /// <item><description>Support for additional authenticated data (AAD)</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Note: AES-GCM is available in .NET Core 3.0+ and .NET 5+.
    /// For .NET Framework and .NET Standard, this implementation uses a compatibility layer
    /// that internally uses AES-CBC with HMAC for authentication.
    /// </para>
    /// </remarks>
    public sealed class AesGcmEncryption : ISymmetricEncryption
    {
        /// <summary>
        /// The default nonce size in bytes for GCM mode.
        /// </summary>
        public const int DefaultNonceSizeBytes = 12;

        /// <summary>
        /// The authentication tag size in bytes.
        /// </summary>
        public const int TagSizeBytes = 16;

        private readonly byte[] _key;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesGcmEncryption"/> class with a randomly generated key.
        /// </summary>
        /// <param name="keySizeInBits">The key size in bits (128, 192, or 256). Default is 256.</param>
        /// <exception cref="ArgumentException">Thrown when the key size is not valid.</exception>
        public AesGcmEncryption(int keySizeInBits = 256)
        {
            ValidateKeySize(keySizeInBits);
            KeySizeInBits = keySizeInBits;
            _key = SecureRandom.GenerateKey(keySizeInBits);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesGcmEncryption"/> class with the specified key.
        /// </summary>
        /// <param name="key">The AES key to use for encryption and decryption.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when the key size is not valid.</exception>
        public AesGcmEncryption(byte[] key)
        {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(key);
#else
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
#endif

            int keySizeInBits = key.Length * 8;
            ValidateKeySize(keySizeInBits);

            KeySizeInBits = keySizeInBits;
            _key = new byte[key.Length];
            Array.Copy(key, _key, key.Length);
        }

        /// <inheritdoc/>
        public string AlgorithmName => $"AES-GCM-{KeySizeInBits}";

        /// <inheritdoc/>
        public int KeySizeInBits { get; }

        /// <inheritdoc/>
        public int BlockSizeInBits => 128;

        /// <inheritdoc/>
        public CryptoResult<byte[]> Encrypt(byte[] plaintext)
        {
            return Encrypt(plaintext, null);
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Encrypt(byte[] plaintext, byte[]? associatedData)
        {
            ThrowIfDisposed();

            if (plaintext == null)
            {
                return CryptoResult<byte[]>.Failure("Plaintext cannot be null.");
            }

            try
            {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
                return EncryptWithNativeGcm(plaintext, associatedData);
#else
                return EncryptWithCompatibilityMode(plaintext, associatedData);
#endif
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Decrypt(byte[] ciphertext)
        {
            return Decrypt(ciphertext, null);
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Decrypt(byte[] ciphertext, byte[]? associatedData)
        {
            ThrowIfDisposed();

            if (ciphertext == null)
            {
                return CryptoResult<byte[]>.Failure("Ciphertext cannot be null.");
            }

            try
            {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
                return DecryptWithNativeGcm(ciphertext, associatedData);
#else
                return DecryptWithCompatibilityMode(ciphertext, associatedData);
#endif
            }
            catch (CryptographicException)
            {
                return CryptoResult<byte[]>.Failure("Decryption failed: Authentication tag verification failed.");
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Decryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> GenerateKey()
        {
            ThrowIfDisposed();

            try
            {
                byte[] key = SecureRandom.GenerateKey(KeySizeInBits);
                return CryptoResult<byte[]>.Success(key);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Key generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> GenerateIV()
        {
            ThrowIfDisposed();

            try
            {
                byte[] nonce = SecureRandom.GenerateNonce(DefaultNonceSizeBytes);
                return CryptoResult<byte[]>.Success(nonce);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Nonce generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            CryptoHelpers.SecureClear(_key);
            _disposed = true;
        }

#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
        private CryptoResult<byte[]> EncryptWithNativeGcm(byte[] plaintext, byte[]? associatedData)
        {
            byte[] nonce = SecureRandom.GenerateNonce(DefaultNonceSizeBytes);
            byte[] tag = new byte[TagSizeBytes];
            byte[] ciphertext = new byte[plaintext.Length];

#if NET8_0_OR_GREATER
            using (AesGcm aesGcm = new(_key, TagSizeBytes))
#else
#pragma warning disable CA5394 // AesGcm constructor with only key is obsolete in NET8+
            using (AesGcm aesGcm = new(_key))
#pragma warning restore CA5394
#endif
            {
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }

            // Format: [nonce][tag][ciphertext]
            byte[] result = new byte[nonce.Length + tag.Length + ciphertext.Length];
            Array.Copy(nonce, 0, result, 0, nonce.Length);
            Array.Copy(tag, 0, result, nonce.Length, tag.Length);
            Array.Copy(ciphertext, 0, result, nonce.Length + tag.Length, ciphertext.Length);

            return CryptoResult<byte[]>.Success(result);
        }

        private CryptoResult<byte[]> DecryptWithNativeGcm(byte[] encryptedData, byte[]? associatedData)
        {
            if (encryptedData.Length < DefaultNonceSizeBytes + TagSizeBytes)
            {
                return CryptoResult<byte[]>.Failure("Encrypted data is too short.");
            }

            byte[] nonce = new byte[DefaultNonceSizeBytes];
            byte[] tag = new byte[TagSizeBytes];
            byte[] ciphertext = new byte[encryptedData.Length - DefaultNonceSizeBytes - TagSizeBytes];

            Array.Copy(encryptedData, 0, nonce, 0, DefaultNonceSizeBytes);
            Array.Copy(encryptedData, DefaultNonceSizeBytes, tag, 0, TagSizeBytes);
            Array.Copy(encryptedData, DefaultNonceSizeBytes + TagSizeBytes, ciphertext, 0, ciphertext.Length);

            byte[] plaintext = new byte[ciphertext.Length];

#if NET8_0_OR_GREATER
            using (AesGcm aesGcm = new(_key, TagSizeBytes))
#else
#pragma warning disable CA5394 // AesGcm constructor with only key is obsolete in NET8+
            using (AesGcm aesGcm = new(_key))
#pragma warning restore CA5394
#endif
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            }

            return CryptoResult<byte[]>.Success(plaintext);
        }
#else
        // Compatibility implementation for .NET Framework and .NET Standard
        // Uses AES-CBC with HMAC-SHA256 for authenticated encryption
        private CryptoResult<byte[]> EncryptWithCompatibilityMode(byte[] plaintext, byte[]? associatedData)
        {
            using Aes aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.GenerateIV();

            byte[] ciphertext;
            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            {
                ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
            }

            // Compute HMAC for authentication
            byte[] dataToAuthenticate = CryptoHelpers.Concatenate(aes.IV, ciphertext, associatedData ?? []);
            byte[] hmac = CryptoHelpers.ComputeHmacSha256(_key, dataToAuthenticate);

            // Format: [IV (16 bytes)][HMAC (32 bytes)][ciphertext]
            byte[] result = new byte[aes.IV.Length + hmac.Length + ciphertext.Length];
            Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
            Array.Copy(hmac, 0, result, aes.IV.Length, hmac.Length);
            Array.Copy(ciphertext, 0, result, aes.IV.Length + hmac.Length, ciphertext.Length);

            return CryptoResult<byte[]>.Success(result);
        }

        private CryptoResult<byte[]> DecryptWithCompatibilityMode(byte[] encryptedData, byte[]? associatedData)
        {
            const int ivSize = 16;
            const int hmacSize = 32;

            if (encryptedData.Length < ivSize + hmacSize)
            {
                return CryptoResult<byte[]>.Failure("Encrypted data is too short.");
            }

            byte[] iv = new byte[ivSize];
            byte[] storedHmac = new byte[hmacSize];
            byte[] ciphertext = new byte[encryptedData.Length - ivSize - hmacSize];

            Array.Copy(encryptedData, 0, iv, 0, ivSize);
            Array.Copy(encryptedData, ivSize, storedHmac, 0, hmacSize);
            Array.Copy(encryptedData, ivSize + hmacSize, ciphertext, 0, ciphertext.Length);

            // Verify HMAC
            byte[] dataToAuthenticate = CryptoHelpers.Concatenate(iv, ciphertext, associatedData ?? []);
            byte[] computedHmac = CryptoHelpers.ComputeHmacSha256(_key, dataToAuthenticate);

            if (!CryptoHelpers.ConstantTimeEquals(storedHmac, computedHmac))
            {
                return CryptoResult<byte[]>.Failure("Authentication failed.");
            }

            using Aes aes = Aes.Create();
            aes.Key = _key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using ICryptoTransform decryptor = aes.CreateDecryptor();
            byte[] plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            return CryptoResult<byte[]>.Success(plaintext);
        }
#endif

        private static void ValidateKeySize(int keySizeInBits)
        {
            if (keySizeInBits is not 128 and not 192 and not 256)
            {
                throw new ArgumentException("Key size must be 128, 192, or 256 bits.", nameof(keySizeInBits));
            }
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(AesGcmEncryption));
            }
#endif
        }
    }
}
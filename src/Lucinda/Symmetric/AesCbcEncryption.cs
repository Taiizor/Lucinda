// <copyright file="AesCbcEncryption.cs" company="Lucinda">
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
    /// Provides AES-CBC (Cipher Block Chaining) encryption with optional HMAC authentication.
    /// </summary>
    /// <remarks>
    /// <para>
    /// AES-CBC provides confidentiality but not integrity protection on its own.
    /// This implementation includes optional HMAC-SHA256 authentication when using
    /// the <see cref="Encrypt(byte[], byte[])"/> method with associated data.
    /// </para>
    /// <para>
    /// For authenticated encryption, prefer <see cref="AesGcmEncryption"/> when available.
    /// </para>
    /// </remarks>
    public sealed class AesCbcEncryption : ISymmetricEncryption
    {
        /// <summary>
        /// The IV size in bytes for CBC mode (16 bytes = 128 bits).
        /// </summary>
        public const int IvSizeBytes = 16;

        private readonly byte[] _key;
        private readonly bool _useHmac;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcEncryption"/> class with a randomly generated key.
        /// </summary>
        /// <param name="keySizeInBits">The key size in bits (128, 192, or 256). Default is 256.</param>
        /// <param name="useHmac">Whether to use HMAC authentication. Default is true.</param>
        /// <exception cref="ArgumentException">Thrown when the key size is not valid.</exception>
        public AesCbcEncryption(int keySizeInBits = 256, bool useHmac = true)
        {
            ValidateKeySize(keySizeInBits);
            KeySizeInBits = keySizeInBits;
            _useHmac = useHmac;
            _key = SecureRandom.GenerateKey(keySizeInBits);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcEncryption"/> class with the specified key.
        /// </summary>
        /// <param name="key">The AES key to use for encryption and decryption.</param>
        /// <param name="useHmac">Whether to use HMAC authentication. Default is true.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when the key size is not valid.</exception>
        public AesCbcEncryption(byte[] key, bool useHmac = true)
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
            _useHmac = useHmac;
            _key = new byte[key.Length];
            Array.Copy(key, _key, key.Length);
        }

        /// <inheritdoc/>
        public string AlgorithmName => _useHmac ? $"AES-CBC-HMAC-{KeySizeInBits}" : $"AES-CBC-{KeySizeInBits}";

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

                if (_useHmac)
                {
                    // Compute HMAC for authentication (Encrypt-then-MAC)
                    byte[] dataToAuthenticate = CryptoHelpers.Concatenate(
                        aes.IV,
                        ciphertext,
                        associatedData ?? []
                    );
                    byte[] hmac = CryptoHelpers.ComputeHmacSha256(_key, dataToAuthenticate);

                    // Format: [IV (16 bytes)][HMAC (32 bytes)][ciphertext]
                    byte[] result = new byte[aes.IV.Length + hmac.Length + ciphertext.Length];
                    Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
                    Array.Copy(hmac, 0, result, aes.IV.Length, hmac.Length);
                    Array.Copy(ciphertext, 0, result, aes.IV.Length + hmac.Length, ciphertext.Length);

                    return CryptoResult<byte[]>.Success(result);
                }
                else
                {
                    // Format: [IV (16 bytes)][ciphertext]
                    byte[] result = new byte[aes.IV.Length + ciphertext.Length];
                    Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
                    Array.Copy(ciphertext, 0, result, aes.IV.Length, ciphertext.Length);

                    return CryptoResult<byte[]>.Success(result);
                }
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
        public CryptoResult<byte[]> Decrypt(byte[] encryptedData, byte[]? associatedData)
        {
            ThrowIfDisposed();

            if (encryptedData == null)
            {
                return CryptoResult<byte[]>.Failure("Encrypted data cannot be null.");
            }

            try
            {
                const int hmacSize = 32;
                int minLength = _useHmac ? IvSizeBytes + hmacSize : IvSizeBytes;

                if (encryptedData.Length < minLength)
                {
                    return CryptoResult<byte[]>.Failure("Encrypted data is too short.");
                }

                byte[] iv = new byte[IvSizeBytes];
                Array.Copy(encryptedData, 0, iv, 0, IvSizeBytes);

                byte[] ciphertext;
                if (_useHmac)
                {
                    byte[] storedHmac = new byte[hmacSize];
                    ciphertext = new byte[encryptedData.Length - IvSizeBytes - hmacSize];

                    Array.Copy(encryptedData, IvSizeBytes, storedHmac, 0, hmacSize);
                    Array.Copy(encryptedData, IvSizeBytes + hmacSize, ciphertext, 0, ciphertext.Length);

                    // Verify HMAC before decryption
                    byte[] dataToAuthenticate = CryptoHelpers.Concatenate(
                        iv,
                        ciphertext,
                        associatedData ?? []
                    );
                    byte[] computedHmac = CryptoHelpers.ComputeHmacSha256(_key, dataToAuthenticate);

                    if (!CryptoHelpers.ConstantTimeEquals(storedHmac, computedHmac))
                    {
                        return CryptoResult<byte[]>.Failure("Authentication failed: HMAC verification failed.");
                    }
                }
                else
                {
                    ciphertext = new byte[encryptedData.Length - IvSizeBytes];
                    Array.Copy(encryptedData, IvSizeBytes, ciphertext, 0, ciphertext.Length);
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
            catch (CryptographicException ex)
            {
                return CryptoResult<byte[]>.Failure($"Decryption failed: {ex.Message}");
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
                byte[] iv = SecureRandom.GenerateNonce(IvSizeBytes);
                return CryptoResult<byte[]>.Success(iv);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"IV generation failed: {ex.Message}");
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
                throw new ObjectDisposedException(nameof(AesCbcEncryption));
            }
#endif
        }
    }
}
// <copyright file="RsaEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
using Lucinda.Abstractions;
using Lucinda.Utilities;
using System.Security.Cryptography;

namespace Lucinda.Asymmetric
{
    /// <summary>
    /// Provides RSA asymmetric encryption and decryption operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RSA encryption is suitable for encrypting small amounts of data,
    /// typically symmetric keys in hybrid encryption schemes.
    /// </para>
    /// <para>
    /// The maximum data size that can be encrypted depends on the key size:
    /// <list type="bullet">
    /// <item><description>2048-bit key with OAEP-SHA256: 190 bytes</description></item>
    /// <item><description>3072-bit key with OAEP-SHA256: 318 bytes</description></item>
    /// <item><description>4096-bit key with OAEP-SHA256: 446 bytes</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Note: This class is only available on .NET Core 3.0+ and .NET 5.0+.
    /// </para>
    /// </remarks>
    public sealed class RsaEncryption : IAsymmetricEncryption
    {
        private readonly RSA _rsa;
        private readonly RSAEncryptionPadding _padding;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaEncryption"/> class with a new key pair.
        /// </summary>
        /// <param name="keySizeInBits">The key size in bits (2048, 3072, or 4096). Default is 2048.</param>
        /// <param name="padding">The padding mode to use. Default is OAEP with SHA-256.</param>
        /// <exception cref="ArgumentException">Thrown when the key size is not valid.</exception>
        public RsaEncryption(int keySizeInBits = 2048, RSAEncryptionPadding? padding = null)
        {
            ValidateKeySize(keySizeInBits);
            KeySizeInBits = keySizeInBits;
            _padding = padding ?? RSAEncryptionPadding.OaepSHA256;
            _rsa = RSA.Create(keySizeInBits);
            HasPrivateKey = true;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaEncryption"/> class with an existing RSA instance.
        /// </summary>
        /// <param name="rsa">The RSA instance to use.</param>
        /// <param name="padding">The padding mode to use. Default is OAEP with SHA-256.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="rsa"/> is null.</exception>
        public RsaEncryption(RSA rsa, RSAEncryptionPadding? padding = null)
        {
            _rsa = rsa ?? throw new ArgumentNullException(nameof(rsa));
            KeySizeInBits = rsa.KeySize;
            _padding = padding ?? RSAEncryptionPadding.OaepSHA256;
            HasPrivateKey = CanExportPrivateKey();
        }

        /// <inheritdoc/>
        public string AlgorithmName => $"RSA-{KeySizeInBits}";

        /// <inheritdoc/>
        public int KeySizeInBits { get; }

        /// <inheritdoc/>
        public bool HasPrivateKey { get; private set; }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Encrypt(byte[] plaintext)
        {
            ThrowIfDisposed();

            if (plaintext == null)
            {
                return CryptoResult<byte[]>.Failure("Plaintext cannot be null.");
            }

            try
            {
                int maxSize = GetMaxPlaintextSize();
                if (plaintext.Length > maxSize)
                {
                    return CryptoResult<byte[]>.Failure(
                        $"Plaintext is too large for RSA encryption. Maximum size: {maxSize} bytes.");
                }

                byte[] encrypted = _rsa.Encrypt(plaintext, _padding);
                return CryptoResult<byte[]>.Success(encrypted);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Decrypt(byte[] ciphertext)
        {
            ThrowIfDisposed();

            if (ciphertext == null)
            {
                return CryptoResult<byte[]>.Failure("Ciphertext cannot be null.");
            }

            if (!HasPrivateKey)
            {
                return CryptoResult<byte[]>.Failure("Private key is not available for decryption.");
            }

            try
            {
                byte[] decrypted = _rsa.Decrypt(ciphertext, _padding);
                return CryptoResult<byte[]>.Success(decrypted);
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
        public CryptoResult<AsymmetricKeyPair> GenerateKeyPair()
        {
            ThrowIfDisposed();

            try
            {
                using RSA newRsa = RSA.Create(KeySizeInBits);
                byte[] publicKey = newRsa.ExportSubjectPublicKeyInfo();
                byte[] privateKey = newRsa.ExportPkcs8PrivateKey();

                return CryptoResult<AsymmetricKeyPair>.Success(
                    new AsymmetricKeyPair(publicKey, privateKey));
            }
            catch (Exception ex)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure($"Key pair generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ExportPublicKey(KeyFormat format)
        {
            ThrowIfDisposed();

            try
            {
                byte[] keyData;
                switch (format)
                {
                    case KeyFormat.SubjectPublicKeyInfo:
                        keyData = _rsa.ExportSubjectPublicKeyInfo();
                        break;
                    case KeyFormat.RsaParameters:
                        RSAParameters parameters = _rsa.ExportParameters(false);
                        keyData = SerializeRsaParameters(parameters);
                        break;
                    default:
                        return CryptoResult<byte[]>.Failure($"Unsupported key format: {format}");
                }

                return CryptoResult<byte[]>.Success(keyData);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Public key export failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ExportPrivateKey(KeyFormat format)
        {
            ThrowIfDisposed();

            if (!HasPrivateKey)
            {
                return CryptoResult<byte[]>.Failure("Private key is not available for export.");
            }

            try
            {
                byte[] keyData;
                switch (format)
                {
                    case KeyFormat.Pkcs8:
                        keyData = _rsa.ExportPkcs8PrivateKey();
                        break;
                    case KeyFormat.RsaParameters:
                        RSAParameters parameters = _rsa.ExportParameters(true);
                        keyData = SerializeRsaParameters(parameters);
                        break;
                    default:
                        return CryptoResult<byte[]>.Failure($"Unsupported key format: {format}");
                }

                return CryptoResult<byte[]>.Success(keyData);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Private key export failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> ImportPublicKey(byte[] keyData, KeyFormat format)
        {
            ThrowIfDisposed();

            if (keyData == null)
            {
                return CryptoResult<bool>.Failure("Key data cannot be null.");
            }

            try
            {
                switch (format)
                {
                    case KeyFormat.SubjectPublicKeyInfo:
                        _rsa.ImportSubjectPublicKeyInfo(keyData, out _);
                        break;
                    case KeyFormat.RsaParameters:
                        RSAParameters parameters = DeserializeRsaParameters(keyData);
                        _rsa.ImportParameters(parameters);
                        break;
                    default:
                        return CryptoResult<bool>.Failure($"Unsupported key format: {format}");
                }

                HasPrivateKey = false;
                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Public key import failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> ImportPrivateKey(byte[] keyData, KeyFormat format)
        {
            ThrowIfDisposed();

            if (keyData == null)
            {
                return CryptoResult<bool>.Failure("Key data cannot be null.");
            }

            try
            {
                switch (format)
                {
                    case KeyFormat.Pkcs8:
                        _rsa.ImportPkcs8PrivateKey(keyData, out _);
                        break;
                    case KeyFormat.RsaParameters:
                        RSAParameters parameters = DeserializeRsaParameters(keyData);
                        _rsa.ImportParameters(parameters);
                        break;
                    default:
                        return CryptoResult<bool>.Failure($"Unsupported key format: {format}");
                }

                HasPrivateKey = true;
                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Private key import failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _rsa.Dispose();
            _disposed = true;
        }

        /// <summary>
        /// Gets the maximum plaintext size that can be encrypted with the current key and padding.
        /// </summary>
        /// <returns>The maximum plaintext size in bytes.</returns>
        public int GetMaxPlaintextSize()
        {
            // OAEP with SHA-256 has 66 bytes of overhead
            // OAEP with SHA-1 has 42 bytes of overhead
            // PKCS#1 v1.5 has 11 bytes of overhead
            int keyBytes = KeySizeInBits / 8;

            if (_padding == RSAEncryptionPadding.OaepSHA256)
            {
                return keyBytes - 66;
            }
            else if (_padding == RSAEncryptionPadding.OaepSHA1)
            {
                return keyBytes - 42;
            }
            else if (_padding == RSAEncryptionPadding.Pkcs1)
            {
                return keyBytes - 11;
            }

            return keyBytes - 66; // Default conservative estimate
        }

        private bool CanExportPrivateKey()
        {
            try
            {
                _rsa.ExportParameters(true);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void ValidateKeySize(int keySizeInBits)
        {
            if (keySizeInBits < 2048)
            {
                throw new ArgumentException(
                    "Key size must be at least 2048 bits for security reasons.",
                    nameof(keySizeInBits));
            }

            if (keySizeInBits % 8 != 0)
            {
                throw new ArgumentException("Key size must be a multiple of 8.", nameof(keySizeInBits));
            }
        }

        private static byte[] SerializeRsaParameters(RSAParameters parameters)
        {
            // Simple serialization: concat all parameters with length prefixes
            byte[][] components =
            [
                parameters.Modulus ?? [],
                parameters.Exponent ?? [],
                parameters.D ?? [],
                parameters.P ?? [],
                parameters.Q ?? [],
                parameters.DP ?? [],
                parameters.DQ ?? [],
                parameters.InverseQ ?? []
            ];

            int totalLength = 4; // Version
            foreach (byte[]? component in components)
            {
                totalLength += 4 + component.Length;
            }

            byte[] result = new byte[totalLength];
            int offset = 0;

            // Version
            WriteInt32(result, offset, 1);
            offset += 4;

            // Write each component with length prefix
            foreach (byte[]? component in components)
            {
                WriteInt32(result, offset, component.Length);
                offset += 4;
                if (component.Length > 0)
                {
                    Array.Copy(component, 0, result, offset, component.Length);
                    offset += component.Length;
                }
            }

            return result;
        }

        private static RSAParameters DeserializeRsaParameters(byte[] data)
        {
            int offset = 0;

            // Version
            int version = ReadInt32(data, offset);
            offset += 4;

            if (version != 1)
            {
                throw new ArgumentException("Unsupported RSA parameters format version.");
            }

            byte[][] components = new byte[8][];
            for (int i = 0; i < 8; i++)
            {
                int length = ReadInt32(data, offset);
                offset += 4;
                components[i] = new byte[length];
                if (length > 0)
                {
                    Array.Copy(data, offset, components[i], 0, length);
                    offset += length;
                }
            }

            return new RSAParameters
            {
                Modulus = components[0].Length > 0 ? components[0] : null,
                Exponent = components[1].Length > 0 ? components[1] : null,
                D = components[2].Length > 0 ? components[2] : null,
                P = components[3].Length > 0 ? components[3] : null,
                Q = components[4].Length > 0 ? components[4] : null,
                DP = components[5].Length > 0 ? components[5] : null,
                DQ = components[6].Length > 0 ? components[6] : null,
                InverseQ = components[7].Length > 0 ? components[7] : null
            };
        }

        private static void WriteInt32(byte[] buffer, int offset, int value)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }

        private static int ReadInt32(byte[] buffer, int offset)
        {
            return (buffer[offset] << 24) |
                   (buffer[offset + 1] << 16) |
                   (buffer[offset + 2] << 8) |
                   buffer[offset + 3];
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(RsaEncryption));
            }
#endif
        }
    }
}
#endif
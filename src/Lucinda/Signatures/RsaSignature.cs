// <copyright file="RsaSignature.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
using Lucinda.Abstractions;
using Lucinda.Utilities;
using System.Security.Cryptography;

namespace Lucinda.Signatures
{
    /// <summary>
    /// Provides RSA digital signature operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RSA signatures provide authentication, non-repudiation, and integrity verification.
    /// </para>
    /// <para>
    /// Supported padding schemes:
    /// <list type="bullet">
    /// <item><description>PSS (RSASSA-PSS) - Recommended, provides probabilistic signatures</description></item>
    /// <item><description>PKCS#1 v1.5 - Legacy, deterministic signatures</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public sealed class RsaSignature : IDigitalSignature
    {
        private readonly RSA _rsa;
        private readonly RSASignaturePadding _padding;
        private readonly HashAlgorithmName _hashAlgorithm;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaSignature"/> class with a new key pair.
        /// </summary>
        /// <param name="keySizeInBits">The key size in bits (2048, 3072, or 4096). Default is 2048.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use. Default is SHA-256.</param>
        /// <param name="padding">The padding mode to use. Default is PSS.</param>
        /// <exception cref="ArgumentException">Thrown when the key size is not valid.</exception>
        public RsaSignature(
            int keySizeInBits = 2048,
            HashAlgorithmName? hashAlgorithm = null,
            RSASignaturePadding? padding = null)
        {
            ValidateKeySize(keySizeInBits);
            KeySizeInBits = keySizeInBits;
            _hashAlgorithm = hashAlgorithm ?? HashAlgorithmName.SHA256;
            _padding = padding ?? RSASignaturePadding.Pss;
            _rsa = RSA.Create(keySizeInBits);
            HasPrivateKey = true;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaSignature"/> class with an existing RSA instance.
        /// </summary>
        /// <param name="rsa">The RSA instance to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use. Default is SHA-256.</param>
        /// <param name="padding">The padding mode to use. Default is PSS.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="rsa"/> is null.</exception>
        public RsaSignature(
            RSA rsa,
            HashAlgorithmName? hashAlgorithm = null,
            RSASignaturePadding? padding = null)
        {
            _rsa = rsa ?? throw new ArgumentNullException(nameof(rsa));
            KeySizeInBits = rsa.KeySize;
            _hashAlgorithm = hashAlgorithm ?? HashAlgorithmName.SHA256;
            _padding = padding ?? RSASignaturePadding.Pss;
            HasPrivateKey = CanExportPrivateKey();
        }

        /// <inheritdoc/>
        public string AlgorithmName => $"RSA-{_hashAlgorithm.Name}-{_padding}";

        /// <inheritdoc/>
        public int KeySizeInBits { get; }

        /// <inheritdoc/>
        public bool HasPrivateKey { get; private set; }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Sign(byte[] data)
        {
            ThrowIfDisposed();

            if (data == null)
            {
                return CryptoResult<byte[]>.Failure("Data cannot be null.");
            }

            if (!HasPrivateKey)
            {
                return CryptoResult<byte[]>.Failure("Private key is not available for signing.");
            }

            try
            {
                byte[] signature = _rsa.SignData(data, _hashAlgorithm, _padding);
                return CryptoResult<byte[]>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Signing failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> SignHash(byte[] hash)
        {
            ThrowIfDisposed();

            if (hash == null)
            {
                return CryptoResult<byte[]>.Failure("Hash cannot be null.");
            }

            if (!HasPrivateKey)
            {
                return CryptoResult<byte[]>.Failure("Private key is not available for signing.");
            }

            try
            {
                byte[] signature = _rsa.SignHash(hash, _hashAlgorithm, _padding);
                return CryptoResult<byte[]>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Signing failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> Verify(byte[] data, byte[] signature)
        {
            ThrowIfDisposed();

            if (data == null)
            {
                return CryptoResult<bool>.Failure("Data cannot be null.");
            }

            if (signature == null)
            {
                return CryptoResult<bool>.Failure("Signature cannot be null.");
            }

            try
            {
                bool isValid = _rsa.VerifyData(data, signature, _hashAlgorithm, _padding);
                return CryptoResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Verification failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> VerifyHash(byte[] hash, byte[] signature)
        {
            ThrowIfDisposed();

            if (hash == null)
            {
                return CryptoResult<bool>.Failure("Hash cannot be null.");
            }

            if (signature == null)
            {
                return CryptoResult<bool>.Failure("Signature cannot be null.");
            }

            try
            {
                bool isValid = _rsa.VerifyHash(hash, signature, _hashAlgorithm, _padding);
                return CryptoResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Verification failed: {ex.Message}");
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

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(RsaSignature));
            }
        }
    }
}
#endif
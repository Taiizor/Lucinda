// <copyright file="EcdsaSignature.cs" company="Lucinda">
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
    /// Provides ECDSA (Elliptic Curve Digital Signature Algorithm) signature operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// ECDSA provides strong security with smaller key sizes compared to RSA,
    /// resulting in faster signing and verification, and smaller signature sizes.
    /// </para>
    /// <para>
    /// Supported curves:
    /// <list type="bullet">
    /// <item><description>P-256 (NIST P-256, secp256r1)</description></item>
    /// <item><description>P-384 (NIST P-384, secp384r1)</description></item>
    /// <item><description>P-521 (NIST P-521, secp521r1)</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public sealed class EcdsaSignature : IDigitalSignature
    {
        private readonly ECDsa _ecdsa;
        private readonly ECCurve _curve;
        private readonly HashAlgorithmName _hashAlgorithm;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdsaSignature"/> class with a new key pair.
        /// </summary>
        /// <param name="curve">The elliptic curve to use. Default is P-256.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use. If null, selects based on curve.</param>
        public EcdsaSignature(ECCurve? curve = null, HashAlgorithmName? hashAlgorithm = null)
        {
            _curve = curve ?? ECCurve.NamedCurves.nistP256;
            KeySizeInBits = GetKeySizeForCurve(_curve);
            _hashAlgorithm = hashAlgorithm ?? GetHashAlgorithmForCurve(KeySizeInBits);
            _ecdsa = ECDsa.Create(_curve);
            HasPrivateKey = true;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdsaSignature"/> class with an existing ECDSA instance.
        /// </summary>
        /// <param name="ecdsa">The ECDSA instance to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use. If null, selects based on key size.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="ecdsa"/> is null.</exception>
        public EcdsaSignature(ECDsa ecdsa, HashAlgorithmName? hashAlgorithm = null)
        {
            _ecdsa = ecdsa ?? throw new ArgumentNullException(nameof(ecdsa));
            KeySizeInBits = ecdsa.KeySize;
            _curve = GetCurveForKeySize(KeySizeInBits);
            _hashAlgorithm = hashAlgorithm ?? GetHashAlgorithmForCurve(KeySizeInBits);
            HasPrivateKey = CanExportPrivateKey();
        }

        /// <inheritdoc/>
        public string AlgorithmName => $"ECDSA-P{KeySizeInBits}-{_hashAlgorithm.Name}";

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
                byte[] signature = _ecdsa.SignData(data, _hashAlgorithm);
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
                byte[] signature = _ecdsa.SignHash(hash);
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
                bool isValid = _ecdsa.VerifyData(data, signature, _hashAlgorithm);
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
                bool isValid = _ecdsa.VerifyHash(hash, signature);
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
                using ECDsa newEcdsa = ECDsa.Create(_curve);
                byte[] publicKey = newEcdsa.ExportSubjectPublicKeyInfo();
                byte[] privateKey = newEcdsa.ExportPkcs8PrivateKey();

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
                        keyData = _ecdsa.ExportSubjectPublicKeyInfo();
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
                        keyData = _ecdsa.ExportPkcs8PrivateKey();
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
                        _ecdsa.ImportSubjectPublicKeyInfo(keyData, out _);
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
                        _ecdsa.ImportPkcs8PrivateKey(keyData, out _);
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

            _ecdsa.Dispose();
            _disposed = true;
        }

        private bool CanExportPrivateKey()
        {
            try
            {
                _ecdsa.ExportPkcs8PrivateKey();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static int GetKeySizeForCurve(ECCurve curve)
        {
            if (curve.Oid?.Value == ECCurve.NamedCurves.nistP256.Oid?.Value)
            {
                return 256;
            }
            else if (curve.Oid?.Value == ECCurve.NamedCurves.nistP384.Oid?.Value)
            {
                return 384;
            }
            else if (curve.Oid?.Value == ECCurve.NamedCurves.nistP521.Oid?.Value)
            {
                return 521;
            }

            return 256;
        }

        private static ECCurve GetCurveForKeySize(int keySizeInBits)
        {
            return keySizeInBits switch
            {
                256 => ECCurve.NamedCurves.nistP256,
                384 => ECCurve.NamedCurves.nistP384,
                521 => ECCurve.NamedCurves.nistP521,
                _ => ECCurve.NamedCurves.nistP256,
            };
        }

        private static HashAlgorithmName GetHashAlgorithmForCurve(int keySizeInBits)
        {
            // Select hash algorithm to match curve security level
            return keySizeInBits switch
            {
                256 => HashAlgorithmName.SHA256,
                384 => HashAlgorithmName.SHA384,
                521 => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256,
            };
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(EcdsaSignature));
            }
#endif
        }
    }
}
#endif
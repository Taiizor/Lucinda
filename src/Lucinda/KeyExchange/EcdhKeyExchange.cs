// <copyright file="EcdhKeyExchange.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using Lucinda.Abstractions;
using Lucinda.KeyDerivation;
using Lucinda.Utilities;
using System.Security.Cryptography;

namespace Lucinda.KeyExchange
{
    /// <summary>
    /// Provides Elliptic Curve Diffie-Hellman (ECDH) key exchange operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// ECDH allows two parties to establish a shared secret over an insecure channel.
    /// The shared secret should be processed through a key derivation function (KDF)
    /// before being used as an encryption key.
    /// </para>
    /// <para>
    /// Supported curves:
    /// <list type="bullet">
    /// <item><description>P-256 (NIST P-256, secp256r1)</description></item>
    /// <item><description>P-384 (NIST P-384, secp384r1)</description></item>
    /// <item><description>P-521 (NIST P-521, secp521r1)</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Note: This class is only available on .NET 6.0 and later.
    /// </para>
    /// </remarks>
    public sealed class EcdhKeyExchange : IKeyExchange
    {
        private readonly ECDiffieHellman _ecdh;
        private readonly ECCurve _curve;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdhKeyExchange"/> class with a new key pair.
        /// </summary>
        /// <param name="curve">The elliptic curve to use. Default is P-256.</param>
        public EcdhKeyExchange(ECCurve? curve = null)
        {
            _curve = curve ?? ECCurve.NamedCurves.nistP256;
            KeySizeInBits = GetKeySizeForCurve(_curve);
            _ecdh = ECDiffieHellman.Create(_curve);
            HasPrivateKey = true;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdhKeyExchange"/> class with an existing ECDH instance.
        /// </summary>
        /// <param name="ecdh">The ECDH instance to use.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="ecdh"/> is null.</exception>
        public EcdhKeyExchange(ECDiffieHellman ecdh)
        {
            _ecdh = ecdh ?? throw new ArgumentNullException(nameof(ecdh));
            KeySizeInBits = ecdh.KeySize;
            _curve = GetCurveForKeySize(KeySizeInBits);
            HasPrivateKey = CanExportPrivateKey();
        }

        /// <inheritdoc/>
        public string AlgorithmName => $"ECDH-P{KeySizeInBits}";

        /// <inheritdoc/>
        public int KeySizeInBits { get; }

        /// <inheritdoc/>
        public bool HasPrivateKey { get; private set; }

        /// <inheritdoc/>
        public CryptoResult<AsymmetricKeyPair> GenerateKeyPair()
        {
            ThrowIfDisposed();

            try
            {
                using ECDiffieHellman newEcdh = ECDiffieHellman.Create(_curve);
                byte[] publicKey = newEcdh.ExportSubjectPublicKeyInfo();
                byte[] privateKey = newEcdh.ExportPkcs8PrivateKey();

                return CryptoResult<AsymmetricKeyPair>.Success(
                    new AsymmetricKeyPair(publicKey, privateKey));
            }
            catch (Exception ex)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure($"Key pair generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> DeriveSharedSecret(byte[] remotePublicKey)
        {
            ThrowIfDisposed();

            if (remotePublicKey == null)
            {
                return CryptoResult<byte[]>.Failure("Remote public key cannot be null.");
            }

            if (!HasPrivateKey)
            {
                return CryptoResult<byte[]>.Failure("Private key is not available for key derivation.");
            }

            try
            {
                using ECDiffieHellman remoteEcdh = ECDiffieHellman.Create();
                remoteEcdh.ImportSubjectPublicKeyInfo(remotePublicKey, out _);

                byte[] sharedSecret = _ecdh.DeriveKeyMaterial(remoteEcdh.PublicKey);
                return CryptoResult<byte[]>.Success(sharedSecret);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Key derivation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> GetPublicKey()
        {
            ThrowIfDisposed();

            try
            {
                byte[] publicKey = _ecdh.ExportSubjectPublicKeyInfo();
                return CryptoResult<byte[]>.Success(publicKey);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Public key export failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> ImportPrivateKey(byte[] privateKeyData, KeyFormat format)
        {
            ThrowIfDisposed();

            if (privateKeyData == null)
            {
                return CryptoResult<bool>.Failure("Private key data cannot be null.");
            }

            try
            {
                switch (format)
                {
                    case KeyFormat.Pkcs8:
                        _ecdh.ImportPkcs8PrivateKey(privateKeyData, out _);
                        break;
                    case KeyFormat.EcParameters:
                        // For EC parameters, we need to deserialize and import
                        return CryptoResult<bool>.Failure("EC parameters format is not yet supported.");
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
        public CryptoResult<byte[]> ExportPublicKey(KeyFormat format)
        {
            ThrowIfDisposed();

            try
            {
                byte[] keyData;
                switch (format)
                {
                    case KeyFormat.SubjectPublicKeyInfo:
                        keyData = _ecdh.ExportSubjectPublicKeyInfo();
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

        /// <summary>
        /// Derives a shared secret and applies HKDF to produce a key of the specified length.
        /// </summary>
        /// <param name="remotePublicKey">The remote party's public key.</param>
        /// <param name="salt">Optional salt for HKDF.</param>
        /// <param name="info">Optional context information for HKDF.</param>
        /// <param name="derivedKeyLength">The desired length of the derived key in bytes.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the derived key on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<byte[]> DeriveKey(
            byte[] remotePublicKey,
            byte[]? salt = null,
            byte[]? info = null,
            int derivedKeyLength = 32)
        {
            ThrowIfDisposed();

            CryptoResult<byte[]> sharedSecretResult = DeriveSharedSecret(remotePublicKey);
            if (sharedSecretResult.IsFailure)
            {
                return CryptoResult<byte[]>.Failure(sharedSecretResult.Error);
            }

            try
            {
                using HkdfKeyDerivation hkdf = new();
                return hkdf.DeriveKey(sharedSecretResult.Value, salt, info, derivedKeyLength);
            }
            finally
            {
                // Clear the shared secret from memory
                CryptoHelpers.SecureClear(sharedSecretResult.Value);
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _ecdh.Dispose();
            _disposed = true;
        }

        private bool CanExportPrivateKey()
        {
            try
            {
                _ecdh.ExportPkcs8PrivateKey();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static int GetKeySizeForCurve(ECCurve curve)
        {
            // Compare by OID since ECCurve doesn't have a direct equality check
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

            // Default fallback
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

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(EcdhKeyExchange));
            }
        }
    }
}
#endif
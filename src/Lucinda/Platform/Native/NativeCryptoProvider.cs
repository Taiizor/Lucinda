// <copyright file="NativeCryptoProvider.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using System.Security.Cryptography;
using Lucinda.Abstractions;
using Lucinda.Symmetric;
using Lucinda.KeyDerivation;

#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
using Lucinda.Asymmetric;
using Lucinda.KeyExchange;
using Lucinda.Signatures;
#endif

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Platform.Native
{
    /// <summary>
    /// Native .NET cryptography provider that uses System.Security.Cryptography APIs.
    /// This provider is used on all non-browser platforms where full crypto APIs are available.
    /// </summary>
    public sealed class NativeCryptoProvider : ICryptoProvider
    {
        private bool _disposed;

        /// <inheritdoc/>
        public CryptoPlatformType PlatformType => CryptoPlatformType.Native;

        /// <inheritdoc/>
        public bool IsAvailable => CryptoPlatform.IsNativeCryptoSupported;

        /// <inheritdoc/>
        public CryptoResult<ISymmetricEncryption> CreateAesGcm(byte[] key)
        {
            try
            {
                ThrowIfDisposed();
                ValidateKey(key, "AES key");

                AesGcmEncryption encryption = new(key);
                return CryptoResult<ISymmetricEncryption>.Success(encryption);
            }
            catch (Exception ex)
            {
                return CryptoResult<ISymmetricEncryption>.Failure($"Failed to create AES-GCM: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<ISymmetricEncryption> CreateAesCbc(byte[] key)
        {
            try
            {
                ThrowIfDisposed();
                ValidateKey(key, "AES key");

                AesCbcEncryption encryption = new(key);
                return CryptoResult<ISymmetricEncryption>.Success(encryption);
            }
            catch (Exception ex)
            {
                return CryptoResult<ISymmetricEncryption>.Failure($"Failed to create AES-CBC: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IAsymmetricEncryption> CreateRsa(int keySizeInBits = 2048)
        {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            try
            {
                ThrowIfDisposed();
                ValidateRsaKeySize(keySizeInBits);

                RsaEncryption encryption = new(keySizeInBits);
                return CryptoResult<IAsymmetricEncryption>.Success(encryption);
            }
            catch (Exception ex)
            {
                return CryptoResult<IAsymmetricEncryption>.Failure($"Failed to create RSA: {ex.Message}");
            }
#else
            return CryptoResult<IAsymmetricEncryption>.Failure("RSA encryption is not available on this framework. Upgrade to .NET Core 3.0 or later.");
#endif
        }

        /// <inheritdoc/>
        public CryptoResult<IAsymmetricEncryption> CreateRsa(byte[] keyData, KeyFormat format, bool isPrivateKey)
        {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            try
            {
                ThrowIfDisposed();
                if (keyData == null || keyData.Length == 0)
                {
                    return CryptoResult<IAsymmetricEncryption>.Failure("Key data cannot be null or empty.");
                }

                RSA rsa = RSA.Create();

                if (isPrivateKey)
                {
                    if (format == KeyFormat.Pkcs8)
                    {
                        rsa.ImportPkcs8PrivateKey(keyData, out _);
                    }
                    else
                    {
                        return CryptoResult<IAsymmetricEncryption>.Failure($"Unsupported private key format: {format}");
                    }
                }
                else
                {
                    if (format == KeyFormat.SubjectPublicKeyInfo)
                    {
                        rsa.ImportSubjectPublicKeyInfo(keyData, out _);
                    }
                    else
                    {
                        return CryptoResult<IAsymmetricEncryption>.Failure($"Unsupported public key format: {format}");
                    }
                }

                RsaEncryption encryption = new(rsa);
                return CryptoResult<IAsymmetricEncryption>.Success(encryption);
            }
            catch (Exception ex)
            {
                return CryptoResult<IAsymmetricEncryption>.Failure($"Failed to create RSA from key data: {ex.Message}");
            }
#else
            return CryptoResult<IAsymmetricEncryption>.Failure("RSA encryption is not available on this framework. Upgrade to .NET Core 3.0 or later.");
#endif
        }

        /// <inheritdoc/>
        public CryptoResult<IKeyExchange> CreateEcdh(string curveName = "P-256")
        {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            try
            {
                ThrowIfDisposed();
                ECCurve curve = GetECCurve(curveName);

                EcdhKeyExchange keyExchange = new(curve);
                return CryptoResult<IKeyExchange>.Success(keyExchange);
            }
            catch (Exception ex)
            {
                return CryptoResult<IKeyExchange>.Failure($"Failed to create ECDH: {ex.Message}");
            }
#else
            return CryptoResult<IKeyExchange>.Failure("ECDH key exchange is not available on this framework. Upgrade to .NET Core 3.0 or later.");
#endif
        }

        /// <inheritdoc/>
        public CryptoResult<IKeyExchange> CreateEcdh(byte[] keyData, KeyFormat format, string curveName = "P-256")
        {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            try
            {
                ThrowIfDisposed();
                if (keyData == null || keyData.Length == 0)
                {
                    return CryptoResult<IKeyExchange>.Failure("Key data cannot be null or empty.");
                }

                ECCurve curve = GetECCurve(curveName);
                ECDiffieHellman ecdh = ECDiffieHellman.Create();

                if (format == KeyFormat.Pkcs8)
                {
                    ecdh.ImportPkcs8PrivateKey(keyData, out _);
                }
                else if (format == KeyFormat.SubjectPublicKeyInfo)
                {
                    ecdh.ImportSubjectPublicKeyInfo(keyData, out _);
                }
                else
                {
                    return CryptoResult<IKeyExchange>.Failure($"Unsupported key format: {format}");
                }

                EcdhKeyExchange keyExchange = new(ecdh);
                return CryptoResult<IKeyExchange>.Success(keyExchange);
            }
            catch (Exception ex)
            {
                return CryptoResult<IKeyExchange>.Failure($"Failed to create ECDH from key data: {ex.Message}");
            }
#else
            return CryptoResult<IKeyExchange>.Failure("ECDH key exchange is not available on this framework. Upgrade to .NET Core 3.0 or later.");
#endif
        }

        /// <inheritdoc/>
        public CryptoResult<IDigitalSignature> CreateEcdsa(string curveName = "P-256")
        {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            try
            {
                ThrowIfDisposed();
                ECCurve curve = GetECCurve(curveName);

                EcdsaSignature signature = new(curve);
                return CryptoResult<IDigitalSignature>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<IDigitalSignature>.Failure($"Failed to create ECDSA: {ex.Message}");
            }
#else
            return CryptoResult<IDigitalSignature>.Failure("ECDSA signatures are not available on this framework. Upgrade to .NET Core 3.0 or later.");
#endif
        }

        /// <inheritdoc/>
        public CryptoResult<IDigitalSignature> CreateEcdsa(byte[] keyData, KeyFormat format, bool isPrivateKey, string curveName = "P-256")
        {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            try
            {
                ThrowIfDisposed();
                if (keyData == null || keyData.Length == 0)
                {
                    return CryptoResult<IDigitalSignature>.Failure("Key data cannot be null or empty.");
                }

                ECDsa ecdsa = ECDsa.Create();

                if (isPrivateKey)
                {
                    if (format == KeyFormat.Pkcs8)
                    {
                        ecdsa.ImportPkcs8PrivateKey(keyData, out _);
                    }
                    else
                    {
                        return CryptoResult<IDigitalSignature>.Failure($"Unsupported private key format: {format}");
                    }
                }
                else
                {
                    if (format == KeyFormat.SubjectPublicKeyInfo)
                    {
                        ecdsa.ImportSubjectPublicKeyInfo(keyData, out _);
                    }
                    else
                    {
                        return CryptoResult<IDigitalSignature>.Failure($"Unsupported public key format: {format}");
                    }
                }

                EcdsaSignature signature = new(ecdsa);
                return CryptoResult<IDigitalSignature>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<IDigitalSignature>.Failure($"Failed to create ECDSA from key data: {ex.Message}");
            }
#else
            return CryptoResult<IDigitalSignature>.Failure("ECDSA signatures are not available on this framework. Upgrade to .NET Core 3.0 or later.");
#endif
        }

        /// <inheritdoc/>
        public CryptoResult<IDigitalSignature> CreateRsaSignature(int keySizeInBits = 2048)
        {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            try
            {
                ThrowIfDisposed();
                ValidateRsaKeySize(keySizeInBits);

                RsaSignature signature = new(keySizeInBits);
                return CryptoResult<IDigitalSignature>.Success(signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<IDigitalSignature>.Failure($"Failed to create RSA signature: {ex.Message}");
            }
#else
            return CryptoResult<IDigitalSignature>.Failure("RSA signatures are not available on this framework. Upgrade to .NET Core 3.0 or later.");
#endif
        }

        /// <inheritdoc/>
        public CryptoResult<IKeyDerivation> CreateHkdf(string hashAlgorithm = "SHA256")
        {
            try
            {
                ThrowIfDisposed();
                HashAlgorithmName hashName = GetHashAlgorithmName(hashAlgorithm);

                HkdfKeyDerivation kdf = new(hashName);
                return CryptoResult<IKeyDerivation>.Success(kdf);
            }
            catch (Exception ex)
            {
                return CryptoResult<IKeyDerivation>.Failure($"Failed to create HKDF: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<IKeyDerivation> CreatePbkdf2(string hashAlgorithm = "SHA256")
        {
            try
            {
                ThrowIfDisposed();
                HashAlgorithmName hashName = GetHashAlgorithmName(hashAlgorithm);

                Pbkdf2KeyDerivation kdf = new(hashName);
                return CryptoResult<IKeyDerivation>.Success(kdf);
            }
            catch (Exception ex)
            {
                return CryptoResult<IKeyDerivation>.Failure($"Failed to create PBKDF2: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> GenerateRandomBytes(int length)
        {
            try
            {
                ThrowIfDisposed();
                if (length <= 0)
                {
                    return CryptoResult<byte[]>.Failure("Length must be greater than zero.");
                }

                byte[] bytes = new byte[length];
#if NET6_0_OR_GREATER
                RandomNumberGenerator.Fill(bytes);
#else
                using RandomNumberGenerator rng = RandomNumberGenerator.Create();
                rng.GetBytes(bytes);
#endif
                return CryptoResult<byte[]>.Success(bytes);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to generate random bytes: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ComputeSha256(byte[] data)
        {
            try
            {
                ThrowIfDisposed();
                if (data == null)
                {
                    return CryptoResult<byte[]>.Failure("Data cannot be null.");
                }

#if NET5_0_OR_GREATER
                byte[] hash = SHA256.HashData(data);
#else
                using SHA256 sha256 = SHA256.Create();
                byte[] hash = sha256.ComputeHash(data);
#endif
                return CryptoResult<byte[]>.Success(hash);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to compute SHA-256: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ComputeSha384(byte[] data)
        {
            try
            {
                ThrowIfDisposed();
                if (data == null)
                {
                    return CryptoResult<byte[]>.Failure("Data cannot be null.");
                }

#if NET5_0_OR_GREATER
                byte[] hash = SHA384.HashData(data);
#else
                using SHA384 sha384 = SHA384.Create();
                byte[] hash = sha384.ComputeHash(data);
#endif
                return CryptoResult<byte[]>.Success(hash);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to compute SHA-384: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ComputeSha512(byte[] data)
        {
            try
            {
                ThrowIfDisposed();
                if (data == null)
                {
                    return CryptoResult<byte[]>.Failure("Data cannot be null.");
                }

#if NET5_0_OR_GREATER
                byte[] hash = SHA512.HashData(data);
#else
                using SHA512 sha512 = SHA512.Create();
                byte[] hash = sha512.ComputeHash(data);
#endif
                return CryptoResult<byte[]>.Success(hash);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to compute SHA-512: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ComputeHmac(byte[] key, byte[] data, string hashAlgorithm = "SHA256")
        {
            try
            {
                ThrowIfDisposed();
                if (key == null || key.Length == 0)
                {
                    return CryptoResult<byte[]>.Failure("Key cannot be null or empty.");
                }
                if (data == null)
                {
                    return CryptoResult<byte[]>.Failure("Data cannot be null.");
                }

                byte[] hash;
                switch (hashAlgorithm.ToUpperInvariant())
                {
                    case "SHA256":
#if NET5_0_OR_GREATER
                        hash = HMACSHA256.HashData(key, data);
#else
                        using (HMACSHA256 hmac = new(key))
                        {
                            hash = hmac.ComputeHash(data);
                        }
#endif
                        break;
                    case "SHA384":
#if NET5_0_OR_GREATER
                        hash = HMACSHA384.HashData(key, data);
#else
                        using (HMACSHA384 hmac = new(key))
                        {
                            hash = hmac.ComputeHash(data);
                        }
#endif
                        break;
                    case "SHA512":
#if NET5_0_OR_GREATER
                        hash = HMACSHA512.HashData(key, data);
#else
                        using (HMACSHA512 hmac = new(key))
                        {
                            hash = hmac.ComputeHash(data);
                        }
#endif
                        break;
                    default:
                        return CryptoResult<byte[]>.Failure($"Unsupported hash algorithm: {hashAlgorithm}");
                }

                return CryptoResult<byte[]>.Success(hash);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to compute HMAC: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(NativeCryptoProvider));
            }
#endif
        }

        private static void ValidateKey(byte[] key, string keyName)
        {
            if (key == null || key.Length == 0)
            {
                throw new ArgumentException($"{keyName} cannot be null or empty.", keyName);
            }

            if (key.Length is not 16 and not 24 and not 32)
            {
                throw new ArgumentException($"{keyName} must be 16, 24, or 32 bytes.", keyName);
            }
        }

        private static void ValidateRsaKeySize(int keySizeInBits)
        {
            if (keySizeInBits is not 2048 and not 3072 and not 4096)
            {
                throw new ArgumentException("RSA key size must be 2048, 3072, or 4096 bits.", nameof(keySizeInBits));
            }
        }

        private static ECCurve GetECCurve(string curveName)
        {
            return curveName.ToUpperInvariant() switch
            {
                "P-256" or "P256" or "SECP256R1" or "NIST P-256" => ECCurve.NamedCurves.nistP256,
                "P-384" or "P384" or "SECP384R1" or "NIST P-384" => ECCurve.NamedCurves.nistP384,
                "P-521" or "P521" or "SECP521R1" or "NIST P-521" => ECCurve.NamedCurves.nistP521,
                _ => throw new ArgumentException($"Unsupported curve: {curveName}", nameof(curveName))
            };
        }

        private static HashAlgorithmName GetHashAlgorithmName(string algorithm)
        {
            return algorithm.ToUpperInvariant() switch
            {
                "SHA256" or "SHA-256" => HashAlgorithmName.SHA256,
                "SHA384" or "SHA-384" => HashAlgorithmName.SHA384,
                "SHA512" or "SHA-512" => HashAlgorithmName.SHA512,
                _ => throw new ArgumentException($"Unsupported hash algorithm: {algorithm}", nameof(algorithm))
            };
        }
    }
}
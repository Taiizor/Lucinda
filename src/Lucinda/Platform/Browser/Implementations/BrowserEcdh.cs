// <copyright file="BrowserEcdh.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET7_0_OR_GREATER

using Lucinda.Abstractions;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Lucinda.Platform.Browser.Implementations
{
    /// <summary>
    /// Browser-based ECDH key exchange implementation using the Web Crypto API.
    /// </summary>
    [SupportedOSPlatform("browser")]
    internal sealed class BrowserEcdh : IKeyExchange
    {
        private readonly string _curveName;
        private byte[]? _publicKey;
        private byte[]? _privateKey;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="BrowserEcdh"/> class.
        /// </summary>
        /// <param name="curveName">The elliptic curve name (P-256, P-384, P-521).</param>
        public BrowserEcdh(string curveName)
        {
            _curveName = BrowserCryptoInterop.NormalizeCurveName(curveName);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BrowserEcdh"/> class from existing key data.
        /// </summary>
        /// <param name="curveName">The elliptic curve name.</param>
        /// <param name="keyData">The key data.</param>
        /// <param name="format">The key format.</param>
        public BrowserEcdh(string curveName, byte[] keyData, KeyFormat format)
        {
            _curveName = BrowserCryptoInterop.NormalizeCurveName(curveName);

            if (keyData == null || keyData.Length == 0)
            {
                throw new ArgumentNullException(nameof(keyData));
            }

            // Determine if it's a public or private key based on format and length
            if (format == KeyFormat.Raw || IsPublicKeySize(keyData.Length))
            {
                _publicKey = new byte[keyData.Length];
                Array.Copy(keyData, _publicKey, keyData.Length);
            }
            else
            {
                _privateKey = new byte[keyData.Length];
                Array.Copy(keyData, _privateKey, keyData.Length);
            }
        }

        /// <inheritdoc/>
        public string AlgorithmName => $"ECDH-{_curveName}";

        /// <inheritdoc/>
        public int KeySizeInBits => _curveName switch
        {
            "P-256" => 256,
            "P-384" => 384,
            "P-521" => 521,
            _ => 256
        };

        /// <inheritdoc/>
        public bool HasPrivateKey => _privateKey != null;

        /// <inheritdoc/>
        public CryptoResult<AsymmetricKeyPair> GenerateKeyPair()
        {
            try
            {
                ThrowIfDisposed();

                BrowserCryptoInterop.EnsureInitialized();
                (byte[]? publicKey, byte[]? privateKey) = BrowserCryptoInterop.EcdhGenerateKeyPair(_curveName);

                _publicKey = publicKey;
                _privateKey = privateKey;

                AsymmetricKeyPair keyPair = new(_publicKey, _privateKey);
                return CryptoResult<AsymmetricKeyPair>.Success(keyPair);
            }
            catch (Exception ex)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure($"Key generation failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> DeriveSharedSecret(byte[] remotePublicKey)
        {
            try
            {
                ThrowIfDisposed();

                if (remotePublicKey == null || remotePublicKey.Length == 0)
                {
                    return CryptoResult<byte[]>.Failure("Remote public key cannot be null or empty.");
                }

                if (_privateKey == null)
                {
                    return CryptoResult<byte[]>.Failure("No private key available. Generate a key pair first.");
                }

                BrowserCryptoInterop.EnsureInitialized();
                byte[] sharedSecret = BrowserCryptoInterop.EcdhDeriveSharedSecret(_privateKey, remotePublicKey, _curveName);

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
            try
            {
                ThrowIfDisposed();

                if (_publicKey == null)
                {
                    return CryptoResult<byte[]>.Failure("No public key available. Generate a key pair first.");
                }

                byte[] result = new byte[_publicKey.Length];
                Array.Copy(_publicKey, result, _publicKey.Length);

                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Failed to get public key: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<bool> ImportPrivateKey(byte[] privateKeyData, KeyFormat format)
        {
            try
            {
                ThrowIfDisposed();

                if (privateKeyData == null || privateKeyData.Length == 0)
                {
                    return CryptoResult<bool>.Failure("Private key data cannot be null or empty.");
                }

                _privateKey = new byte[privateKeyData.Length];
                Array.Copy(privateKeyData, _privateKey, privateKeyData.Length);

                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Import failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> ExportPublicKey(KeyFormat format)
        {
            try
            {
                ThrowIfDisposed();

                if (_publicKey == null)
                {
                    return CryptoResult<byte[]>.Failure("No public key available.");
                }

                // Web Crypto API exports EC public keys in raw format
                if (format is not KeyFormat.Raw and not KeyFormat.SubjectPublicKeyInfo)
                {
                    return CryptoResult<byte[]>.Failure($"Unsupported key format: {format}. Browser supports Raw format.");
                }

                byte[] result = new byte[_publicKey.Length];
                Array.Copy(_publicKey, result, _publicKey.Length);

                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Export failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            if (_privateKey != null)
            {
                CryptographicOperations.ZeroMemory(_privateKey);
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
                throw new ObjectDisposedException(nameof(BrowserEcdh));
            }
#endif
        }

        private bool IsPublicKeySize(int length)
        {
            // Uncompressed EC public key sizes (1 + 2*coordinate_size)
            return _curveName switch
            {
                "P-256" => length == 65,  // 1 + 32 + 32
                "P-384" => length == 97,  // 1 + 48 + 48
                "P-521" => length == 133, // 1 + 66 + 66
                _ => length < 100
            };
        }
    }
}

#endif
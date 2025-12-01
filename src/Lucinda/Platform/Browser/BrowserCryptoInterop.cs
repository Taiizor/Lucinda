// <copyright file="BrowserCryptoInterop.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET7_0_OR_GREATER

using Lucinda.Abstractions;
using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;

namespace Lucinda.Platform.Browser
{
    /// <summary>
    /// Provides JavaScript interop methods for accessing the Web Crypto API.
    /// This class is only available in browser environments (Blazor WebAssembly).
    /// </summary>
    [SupportedOSPlatform("browser")]
    internal static partial class BrowserCryptoInterop
    {
        private static bool _initialized;
#if NET9_0_OR_GREATER
        private static readonly Lock _initLock = new();
#else
        private static readonly object _initLock = new();
#endif

        /// <summary>
        /// Ensures the JavaScript module is loaded.
        /// </summary>
        internal static void EnsureInitialized()
        {
            if (_initialized)
            {
                return;
            }

            lock (_initLock)
            {
                if (_initialized)
                {
                    return;
                }

                // The JavaScript module should be loaded via JSHost.ImportAsync
                // This happens automatically when the Blazor app starts
                _initialized = true;
            }
        }

        #region AES-GCM Operations

        /// <summary>
        /// Encrypts data using AES-GCM via Web Crypto API.
        /// </summary>
        [JSImport("aesGcmEncrypt", "LucindaCrypto")]
        internal static partial byte[] AesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[]? associatedData);

        /// <summary>
        /// Decrypts data using AES-GCM via Web Crypto API.
        /// </summary>
        [JSImport("aesGcmDecrypt", "LucindaCrypto")]
        internal static partial byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[]? associatedData);

        #endregion

        #region AES-CBC Operations

        /// <summary>
        /// Encrypts data using AES-CBC via Web Crypto API.
        /// </summary>
        [JSImport("aesCbcEncrypt", "LucindaCrypto")]
        internal static partial byte[] AesCbcEncrypt(byte[] key, byte[] iv, byte[] plaintext);

        /// <summary>
        /// Decrypts data using AES-CBC via Web Crypto API.
        /// </summary>
        [JSImport("aesCbcDecrypt", "LucindaCrypto")]
        internal static partial byte[] AesCbcDecrypt(byte[] key, byte[] iv, byte[] ciphertext);

        #endregion

        #region RSA Operations

        /// <summary>
        /// Generates an RSA key pair via Web Crypto API.
        /// Returns Base64-encoded JSON with publicKey and privateKey properties.
        /// </summary>
        [JSImport("rsaGenerateKeyPairJson", "LucindaCrypto")]
        internal static partial string RsaGenerateKeyPairJson(int keySizeInBits);

        /// <summary>
        /// Generates RSA key pair and returns as separate byte arrays.
        /// </summary>
        internal static (byte[] publicKey, byte[] privateKey) RsaGenerateKeyPair(int keySizeInBits)
        {
            string json = RsaGenerateKeyPairJson(keySizeInBits);
            string[] parts = json.Split('|');
            return (Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]));
        }

        /// <summary>
        /// Encrypts data using RSA-OAEP via Web Crypto API.
        /// </summary>
        [JSImport("rsaEncrypt", "LucindaCrypto")]
        internal static partial byte[] RsaEncrypt(byte[] publicKey, byte[] plaintext);

        /// <summary>
        /// Decrypts data using RSA-OAEP via Web Crypto API.
        /// </summary>
        [JSImport("rsaDecrypt", "LucindaCrypto")]
        internal static partial byte[] RsaDecrypt(byte[] privateKey, byte[] ciphertext);

        /// <summary>
        /// Signs data using RSA-PSS via Web Crypto API.
        /// </summary>
        [JSImport("rsaSign", "LucindaCrypto")]
        internal static partial byte[] RsaSign(byte[] privateKey, byte[] data, string hashAlgorithm);

        /// <summary>
        /// Verifies an RSA-PSS signature via Web Crypto API.
        /// </summary>
        [JSImport("rsaVerify", "LucindaCrypto")]
        internal static partial bool RsaVerify(byte[] publicKey, byte[] data, byte[] signature, string hashAlgorithm);

        #endregion

        #region ECDH Operations

        /// <summary>
        /// Generates an ECDH key pair via Web Crypto API.
        /// Returns pipe-separated Base64-encoded keys.
        /// </summary>
        [JSImport("ecdhGenerateKeyPairJson", "LucindaCrypto")]
        internal static partial string EcdhGenerateKeyPairJson(string curveName);

        /// <summary>
        /// Generates ECDH key pair and returns as separate byte arrays.
        /// </summary>
        internal static (byte[] publicKey, byte[] privateKey) EcdhGenerateKeyPair(string curveName)
        {
            string json = EcdhGenerateKeyPairJson(curveName);
            string[] parts = json.Split('|');
            return (Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]));
        }

        /// <summary>
        /// Derives a shared secret using ECDH via Web Crypto API.
        /// </summary>
        [JSImport("ecdhDeriveSharedSecret", "LucindaCrypto")]
        internal static partial byte[] EcdhDeriveSharedSecret(byte[] privateKey, byte[] publicKey, string curveName);

        #endregion

        #region ECDSA Operations

        /// <summary>
        /// Generates an ECDSA key pair via Web Crypto API.
        /// Returns pipe-separated Base64-encoded keys.
        /// </summary>
        [JSImport("ecdsaGenerateKeyPairJson", "LucindaCrypto")]
        internal static partial string EcdsaGenerateKeyPairJson(string curveName);

        /// <summary>
        /// Generates ECDSA key pair and returns as separate byte arrays.
        /// </summary>
        internal static (byte[] publicKey, byte[] privateKey) EcdsaGenerateKeyPair(string curveName)
        {
            string json = EcdsaGenerateKeyPairJson(curveName);
            string[] parts = json.Split('|');
            return (Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]));
        }

        /// <summary>
        /// Signs data using ECDSA via Web Crypto API.
        /// </summary>
        [JSImport("ecdsaSign", "LucindaCrypto")]
        internal static partial byte[] EcdsaSign(byte[] privateKey, byte[] data, string curveName, string hashAlgorithm);

        /// <summary>
        /// Verifies an ECDSA signature via Web Crypto API.
        /// </summary>
        [JSImport("ecdsaVerify", "LucindaCrypto")]
        internal static partial bool EcdsaVerify(byte[] publicKey, byte[] data, byte[] signature, string curveName, string hashAlgorithm);

        #endregion

        #region Key Derivation Operations

        /// <summary>
        /// Derives a key using HKDF via Web Crypto API.
        /// </summary>
        [JSImport("hkdfDerive", "LucindaCrypto")]
        internal static partial byte[] HkdfDerive(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int outputLength, string hashAlgorithm);

        /// <summary>
        /// Derives a key using PBKDF2 via Web Crypto API.
        /// </summary>
        [JSImport("pbkdf2Derive", "LucindaCrypto")]
        internal static partial byte[] Pbkdf2Derive(byte[] password, byte[] salt, int iterations, int outputLength, string hashAlgorithm);

        #endregion

        #region HMAC Operations

        /// <summary>
        /// Computes HMAC via Web Crypto API.
        /// </summary>
        [JSImport("hmacCompute", "LucindaCrypto")]
        internal static partial byte[] HmacComputeInternal(byte[] key, byte[] data, string hashAlgorithm);

        /// <summary>
        /// Computes HMAC with result pattern.
        /// </summary>
        internal static CryptoResult<byte[]> ComputeHmac(byte[] key, byte[] data, string hashAlgorithm)
        {
            try
            {
                EnsureInitialized();
                byte[] result = HmacComputeInternal(key, data, NormalizeHashAlgorithm(hashAlgorithm));
                return CryptoResult<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"HMAC computation failed: {ex.Message}");
            }
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Normalizes the hash algorithm name for Web Crypto API.
        /// </summary>
        internal static string NormalizeHashAlgorithm(string algorithm)
        {
            return algorithm.ToUpperInvariant().Replace("-", "") switch
            {
                "SHA256" => "SHA-256",
                "SHA384" => "SHA-384",
                "SHA512" => "SHA-512",
                _ => algorithm
            };
        }

        /// <summary>
        /// Normalizes the curve name for Web Crypto API.
        /// </summary>
        internal static string NormalizeCurveName(string curveName)
        {
            return curveName.ToUpperInvariant() switch
            {
                "P256" or "P-256" or "SECP256R1" or "NIST P-256" => "P-256",
                "P384" or "P-384" or "SECP384R1" or "NIST P-384" => "P-384",
                "P521" or "P-521" or "SECP521R1" or "NIST P-521" => "P-521",
                _ => curveName
            };
        }

        #endregion
    }
}

#endif
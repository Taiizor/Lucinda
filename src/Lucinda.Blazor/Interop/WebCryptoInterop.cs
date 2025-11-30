// -----------------------------------------------------------------------
// <copyright file="WebCryptoInterop.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Microsoft.JSInterop;

namespace Lucinda.Blazor.Interop
{
    /// <summary>
    /// Provides JavaScript interop for Web Crypto API operations.
    /// </summary>
    /// <remarks>
    /// This class serves as the bridge between .NET and the browser's native Web Crypto API.
    /// All cryptographic operations are performed in JavaScript using the secure, hardware-accelerated
    /// implementations provided by the browser.
    /// </remarks>
    /// <remarks>
    /// Initializes a new instance of the <see cref="WebCryptoInterop"/> class.
    /// </remarks>
    /// <param name="jsRuntime">The JavaScript runtime.</param>
    public sealed class WebCryptoInterop(IJSRuntime jsRuntime) : IAsyncDisposable
    {
        private readonly IJSRuntime _jsRuntime = jsRuntime ?? throw new ArgumentNullException(nameof(jsRuntime));
        private IJSObjectReference? _module;
        private bool _disposed;

        /// <summary>
        /// Gets a value indicating whether the module has been initialized.
        /// </summary>
        public bool IsInitialized => _module != null;

        /// <summary>
        /// Initializes the JavaScript module.
        /// </summary>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task InitializeAsync()
        {
            _module ??= await _jsRuntime.InvokeAsync<IJSObjectReference>(
                    "import", "./_content/Lucinda.Blazor/lucinda.crypto.js");
        }

        /// <summary>
        /// Ensures the module is initialized before use.
        /// </summary>
        private async Task EnsureInitializedAsync()
        {
            if (_module == null)
            {
                await InitializeAsync();
            }
        }

        // ============================================================================
        // Secure Random
        // ============================================================================

        /// <summary>
        /// Generates cryptographically secure random bytes.
        /// </summary>
        /// <param name="length">The number of bytes to generate.</param>
        /// <returns>The random bytes.</returns>
        public async Task<byte[]> GetRandomBytesAsync(int length)
        {
            await EnsureInitializedAsync();
            string base64 = await _module!.InvokeAsync<string>("getRandomBytes", length);
            return Convert.FromBase64String(base64);
        }

        /// <summary>
        /// Generates a random 32-bit integer.
        /// </summary>
        /// <returns>A random integer.</returns>
        public async Task<int> GetRandomInt32Async()
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<int>("getRandomInt32");
        }

        // ============================================================================
        // AES-GCM Encryption
        // ============================================================================

        /// <summary>
        /// Encrypts data using AES-GCM.
        /// </summary>
        /// <param name="key">The encryption key (16, 24, or 32 bytes).</param>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="associatedData">Optional additional authenticated data.</param>
        /// <returns>The encrypted data with IV prepended.</returns>
        public async Task<byte[]> AesGcmEncryptAsync(byte[] key, byte[] plaintext, byte[]? associatedData = null)
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "aesGcmEncrypt",
                Convert.ToBase64String(key),
                Convert.ToBase64String(plaintext),
                associatedData != null ? Convert.ToBase64String(associatedData) : null);
            return Convert.FromBase64String(result);
        }

        /// <summary>
        /// Decrypts data using AES-GCM.
        /// </summary>
        /// <param name="key">The decryption key.</param>
        /// <param name="ciphertext">The encrypted data with IV prepended.</param>
        /// <param name="associatedData">Optional additional authenticated data.</param>
        /// <returns>The decrypted data.</returns>
        public async Task<byte[]> AesGcmDecryptAsync(byte[] key, byte[] ciphertext, byte[]? associatedData = null)
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "aesGcmDecrypt",
                Convert.ToBase64String(key),
                Convert.ToBase64String(ciphertext),
                associatedData != null ? Convert.ToBase64String(associatedData) : null);
            return Convert.FromBase64String(result);
        }

        /// <summary>
        /// Generates an AES key.
        /// </summary>
        /// <param name="keySizeBits">The key size in bits (128, 192, or 256).</param>
        /// <returns>The generated key.</returns>
        public async Task<byte[]> GenerateAesKeyAsync(int keySizeBits = 256)
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>("generateAesKey", keySizeBits);
            return Convert.FromBase64String(result);
        }

        // ============================================================================
        // AES-CBC Encryption
        // ============================================================================

        /// <summary>
        /// Encrypts data using AES-CBC.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <returns>The encrypted data with IV prepended.</returns>
        public async Task<byte[]> AesCbcEncryptAsync(byte[] key, byte[] plaintext)
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "aesCbcEncrypt",
                Convert.ToBase64String(key),
                Convert.ToBase64String(plaintext));
            return Convert.FromBase64String(result);
        }

        /// <summary>
        /// Decrypts data using AES-CBC.
        /// </summary>
        /// <param name="key">The decryption key.</param>
        /// <param name="ciphertext">The encrypted data with IV prepended.</param>
        /// <returns>The decrypted data.</returns>
        public async Task<byte[]> AesCbcDecryptAsync(byte[] key, byte[] ciphertext)
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "aesCbcDecrypt",
                Convert.ToBase64String(key),
                Convert.ToBase64String(ciphertext));
            return Convert.FromBase64String(result);
        }

        // ============================================================================
        // RSA Encryption
        // ============================================================================

        /// <summary>
        /// Generates an RSA key pair.
        /// </summary>
        /// <param name="modulusLength">The key size in bits (2048, 3072, or 4096).</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>The public and private keys.</returns>
        public async Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateRsaKeyPairAsync(
            int modulusLength = 2048,
            string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            RsaKeyPairResult result = await _module!.InvokeAsync<RsaKeyPairResult>(
                "generateRsaKeyPair", modulusLength, hashName);
            return (
                Convert.FromBase64String(result.PublicKey),
                Convert.FromBase64String(result.PrivateKey));
        }

        /// <summary>
        /// Encrypts data using RSA-OAEP.
        /// </summary>
        /// <param name="publicKey">The SPKI-encoded public key.</param>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>The encrypted data.</returns>
        public async Task<byte[]> RsaEncryptAsync(byte[] publicKey, byte[] plaintext, string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "rsaEncrypt",
                Convert.ToBase64String(publicKey),
                Convert.ToBase64String(plaintext),
                hashName);
            return Convert.FromBase64String(result);
        }

        /// <summary>
        /// Decrypts data using RSA-OAEP.
        /// </summary>
        /// <param name="privateKey">The PKCS8-encoded private key.</param>
        /// <param name="ciphertext">The data to decrypt.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>The decrypted data.</returns>
        public async Task<byte[]> RsaDecryptAsync(byte[] privateKey, byte[] ciphertext, string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "rsaDecrypt",
                Convert.ToBase64String(privateKey),
                Convert.ToBase64String(ciphertext),
                hashName);
            return Convert.FromBase64String(result);
        }

        // ============================================================================
        // ECDH Key Exchange
        // ============================================================================

        /// <summary>
        /// Generates an ECDH key pair.
        /// </summary>
        /// <param name="namedCurve">The curve name (P-256, P-384, or P-521).</param>
        /// <returns>The public and private keys.</returns>
        public async Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateEcdhKeyPairAsync(string namedCurve = "P-256")
        {
            await EnsureInitializedAsync();
            EcKeyPairResult result = await _module!.InvokeAsync<EcKeyPairResult>(
                "generateEcdhKeyPair", namedCurve);
            return (
                Convert.FromBase64String(result.PublicKey),
                Convert.FromBase64String(result.PrivateKey));
        }

        /// <summary>
        /// Derives a shared secret using ECDH.
        /// </summary>
        /// <param name="privateKey">The local private key.</param>
        /// <param name="publicKey">The remote public key.</param>
        /// <param name="namedCurve">The curve name.</param>
        /// <param name="lengthBits">The output length in bits.</param>
        /// <returns>The shared secret.</returns>
        public async Task<byte[]> EcdhDeriveBitsAsync(
            byte[] privateKey,
            byte[] publicKey,
            string namedCurve = "P-256",
            int lengthBits = 256)
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "ecdhDeriveBits",
                Convert.ToBase64String(privateKey),
                Convert.ToBase64String(publicKey),
                namedCurve,
                lengthBits);
            return Convert.FromBase64String(result);
        }

        // ============================================================================
        // ECDSA Signatures
        // ============================================================================

        /// <summary>
        /// Generates an ECDSA key pair.
        /// </summary>
        /// <param name="namedCurve">The curve name.</param>
        /// <returns>The public and private keys.</returns>
        public async Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateEcdsaKeyPairAsync(string namedCurve = "P-256")
        {
            await EnsureInitializedAsync();
            EcKeyPairResult result = await _module!.InvokeAsync<EcKeyPairResult>(
                "generateEcdsaKeyPair", namedCurve);
            return (
                Convert.FromBase64String(result.PublicKey),
                Convert.FromBase64String(result.PrivateKey));
        }

        /// <summary>
        /// Signs data using ECDSA.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="data">The data to sign.</param>
        /// <param name="namedCurve">The curve name.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>The signature.</returns>
        public async Task<byte[]> EcdsaSignAsync(
            byte[] privateKey,
            byte[] data,
            string namedCurve = "P-256",
            string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "ecdsaSign",
                Convert.ToBase64String(privateKey),
                Convert.ToBase64String(data),
                namedCurve,
                hashName);
            return Convert.FromBase64String(result);
        }

        /// <summary>
        /// Verifies an ECDSA signature.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="data">The original data.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="namedCurve">The curve name.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>True if the signature is valid.</returns>
        public async Task<bool> EcdsaVerifyAsync(
            byte[] publicKey,
            byte[] data,
            byte[] signature,
            string namedCurve = "P-256",
            string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>(
                "ecdsaVerify",
                Convert.ToBase64String(publicKey),
                Convert.ToBase64String(data),
                Convert.ToBase64String(signature),
                namedCurve,
                hashName);
        }

        // ============================================================================
        // RSA Signatures
        // ============================================================================

        /// <summary>
        /// Generates an RSA-PSS key pair for signing.
        /// </summary>
        /// <param name="modulusLength">The key size in bits.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>The public and private keys.</returns>
        public async Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateRsaSignatureKeyPairAsync(
            int modulusLength = 2048,
            string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            RsaKeyPairResult result = await _module!.InvokeAsync<RsaKeyPairResult>(
                "generateRsaSignatureKeyPair", modulusLength, hashName);
            return (
                Convert.FromBase64String(result.PublicKey),
                Convert.FromBase64String(result.PrivateKey));
        }

        /// <summary>
        /// Signs data using RSA-PSS.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="data">The data to sign.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <param name="saltLength">The salt length in bytes.</param>
        /// <returns>The signature.</returns>
        public async Task<byte[]> RsaPssSignAsync(
            byte[] privateKey,
            byte[] data,
            string hashName = "SHA-256",
            int saltLength = 32)
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "rsaPssSign",
                Convert.ToBase64String(privateKey),
                Convert.ToBase64String(data),
                hashName,
                saltLength);
            return Convert.FromBase64String(result);
        }

        /// <summary>
        /// Verifies an RSA-PSS signature.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="data">The original data.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <param name="saltLength">The salt length in bytes.</param>
        /// <returns>True if the signature is valid.</returns>
        public async Task<bool> RsaPssVerifyAsync(
            byte[] publicKey,
            byte[] data,
            byte[] signature,
            string hashName = "SHA-256",
            int saltLength = 32)
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>(
                "rsaPssVerify",
                Convert.ToBase64String(publicKey),
                Convert.ToBase64String(data),
                Convert.ToBase64String(signature),
                hashName,
                saltLength);
        }

        // ============================================================================
        // Key Derivation Functions
        // ============================================================================

        /// <summary>
        /// Derives a key using HKDF.
        /// </summary>
        /// <param name="inputKeyMaterial">The input key material.</param>
        /// <param name="salt">The salt (can be null or empty).</param>
        /// <param name="info">The info/context (can be null or empty).</param>
        /// <param name="lengthBytes">The output length in bytes.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>The derived key.</returns>
        public async Task<byte[]> HkdfDeriveKeyAsync(
            byte[] inputKeyMaterial,
            byte[]? salt,
            byte[]? info,
            int lengthBytes,
            string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "hkdfDeriveKey",
                Convert.ToBase64String(inputKeyMaterial),
                salt != null && salt.Length > 0 ? Convert.ToBase64String(salt) : null,
                info != null && info.Length > 0 ? Convert.ToBase64String(info) : null,
                lengthBytes,
                hashName);
            return Convert.FromBase64String(result);
        }

        /// <summary>
        /// Derives a key using PBKDF2.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The number of iterations.</param>
        /// <param name="lengthBytes">The output length in bytes.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>The derived key.</returns>
        public async Task<byte[]> Pbkdf2DeriveKeyAsync(
            byte[] password,
            byte[] salt,
            int iterations,
            int lengthBytes,
            string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "pbkdf2DeriveKey",
                Convert.ToBase64String(password),
                Convert.ToBase64String(salt),
                iterations,
                lengthBytes,
                hashName);
            return Convert.FromBase64String(result);
        }

        // ============================================================================
        // Hash Functions
        // ============================================================================

        /// <summary>
        /// Computes a SHA hash.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>The hash.</returns>
        public async Task<byte[]> ComputeHashAsync(byte[] data, string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "computeHash",
                Convert.ToBase64String(data),
                hashName);
            return Convert.FromBase64String(result);
        }

        // ============================================================================
        // HMAC Functions
        // ============================================================================

        /// <summary>
        /// Computes an HMAC.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="data">The data.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>The HMAC.</returns>
        public async Task<byte[]> ComputeHmacAsync(byte[] key, byte[] data, string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            string result = await _module!.InvokeAsync<string>(
                "computeHmac",
                Convert.ToBase64String(key),
                Convert.ToBase64String(data),
                hashName);
            return Convert.FromBase64String(result);
        }

        /// <summary>
        /// Verifies an HMAC.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="data">The data.</param>
        /// <param name="hmac">The HMAC to verify.</param>
        /// <param name="hashName">The hash algorithm name.</param>
        /// <returns>True if the HMAC is valid.</returns>
        public async Task<bool> VerifyHmacAsync(byte[] key, byte[] data, byte[] hmac, string hashName = "SHA-256")
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>(
                "verifyHmac",
                Convert.ToBase64String(key),
                Convert.ToBase64String(data),
                Convert.ToBase64String(hmac),
                hashName);
        }

        // ============================================================================
        // Feature Detection
        // ============================================================================

        /// <summary>
        /// Checks if Web Crypto API is available.
        /// </summary>
        /// <returns>True if Web Crypto API is available.</returns>
        public async Task<bool> IsWebCryptoAvailableAsync()
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>("isWebCryptoAvailable");
        }

        /// <summary>
        /// Gets supported algorithms.
        /// </summary>
        /// <returns>An object describing supported algorithms.</returns>
        public async Task<SupportedAlgorithms> GetSupportedAlgorithmsAsync()
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<SupportedAlgorithms>("getSupportedAlgorithms");
        }

        // ============================================================================
        // IndexedDB Key Storage
        // ============================================================================

        /// <summary>
        /// Stores a key in IndexedDB.
        /// </summary>
        /// <param name="keyId">The unique key identifier.</param>
        /// <param name="keyData">The key data.</param>
        /// <param name="metadata">The key metadata.</param>
        /// <returns>True if stored successfully.</returns>
        public async Task<bool> StoreKeyAsync(string keyId, byte[] keyData, KeyStorageMetadata metadata)
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>(
                "storeKey",
                keyId,
                Convert.ToBase64String(keyData),
                metadata);
        }

        /// <summary>
        /// Retrieves a key from IndexedDB.
        /// </summary>
        /// <param name="keyId">The unique key identifier.</param>
        /// <returns>The key data, or null if not found.</returns>
        public async Task<byte[]?> RetrieveKeyAsync(string keyId)
        {
            await EnsureInitializedAsync();
            string? result = await _module!.InvokeAsync<string?>("retrieveKey", keyId);
            return result != null ? Convert.FromBase64String(result) : null;
        }

        /// <summary>
        /// Deletes a key from IndexedDB.
        /// </summary>
        /// <param name="keyId">The unique key identifier.</param>
        /// <returns>True if deleted successfully.</returns>
        public async Task<bool> DeleteKeyAsync(string keyId)
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>("deleteKey", keyId);
        }

        /// <summary>
        /// Checks if a key exists in IndexedDB.
        /// </summary>
        /// <param name="keyId">The unique key identifier.</param>
        /// <returns>True if the key exists.</returns>
        public async Task<bool> KeyExistsAsync(string keyId)
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>("keyExists", keyId);
        }

        /// <summary>
        /// Gets key metadata from IndexedDB.
        /// </summary>
        /// <param name="keyId">The unique key identifier.</param>
        /// <returns>The key metadata, or null if not found.</returns>
        public async Task<KeyStorageMetadata?> GetKeyMetadataAsync(string keyId)
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<KeyStorageMetadata?>("getKeyMetadata", keyId);
        }

        /// <summary>
        /// Lists all key IDs in IndexedDB.
        /// </summary>
        /// <returns>Array of key IDs.</returns>
        public async Task<string[]> ListKeyIdsAsync()
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<string[]>("listKeyIds");
        }

        /// <summary>
        /// Lists key IDs by type.
        /// </summary>
        /// <param name="keyType">The key type to filter by.</param>
        /// <returns>Array of key IDs.</returns>
        public async Task<string[]> ListKeyIdsByTypeAsync(int keyType)
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<string[]>("listKeyIdsByType", keyType);
        }

        /// <summary>
        /// Clears expired keys from IndexedDB.
        /// </summary>
        /// <returns>Number of deleted keys.</returns>
        public async Task<int> ClearExpiredKeysAsync()
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<int>("clearExpiredKeys");
        }

        /// <summary>
        /// Clears all keys from IndexedDB.
        /// </summary>
        public async Task ClearAllKeysAsync()
        {
            await EnsureInitializedAsync();
            await _module!.InvokeVoidAsync("clearAllKeys");
        }

        // ============================================================================
        // IndexedDB Session Storage
        // ============================================================================

        /// <summary>
        /// Stores session data in IndexedDB.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <param name="sessionData">The session data.</param>
        /// <returns>True if stored successfully.</returns>
        public async Task<bool> StoreSessionAsync(string sessionId, byte[] sessionData)
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>(
                "storeSession",
                sessionId,
                Convert.ToBase64String(sessionData));
        }

        /// <summary>
        /// Loads session data from IndexedDB.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <returns>The session data, or null if not found.</returns>
        public async Task<byte[]?> LoadSessionAsync(string sessionId)
        {
            await EnsureInitializedAsync();
            string? result = await _module!.InvokeAsync<string?>("loadSession", sessionId);
            return result != null ? Convert.FromBase64String(result) : null;
        }

        /// <summary>
        /// Deletes session data from IndexedDB.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <returns>True if deleted successfully.</returns>
        public async Task<bool> DeleteSessionAsync(string sessionId)
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>("deleteSession", sessionId);
        }

        /// <summary>
        /// Checks if a session exists in IndexedDB.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <returns>True if the session exists.</returns>
        public async Task<bool> SessionExistsAsync(string sessionId)
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>("sessionExists", sessionId);
        }

        /// <summary>
        /// Gets all session IDs from IndexedDB.
        /// </summary>
        /// <returns>Array of session IDs.</returns>
        public async Task<string[]> GetAllSessionIdsAsync()
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<string[]>("getAllSessionIds");
        }

        /// <summary>
        /// Clears all sessions from IndexedDB.
        /// </summary>
        public async Task ClearAllSessionsAsync()
        {
            await EnsureInitializedAsync();
            await _module!.InvokeVoidAsync("clearAllSessions");
        }

        /// <summary>
        /// Checks if IndexedDB is available.
        /// </summary>
        /// <returns>True if available.</returns>
        public async Task<bool> IsIndexedDBAvailableAsync()
        {
            await EnsureInitializedAsync();
            return await _module!.InvokeAsync<bool>("isIndexedDBAvailable");
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (!_disposed)
            {
                if (_module != null)
                {
                    await _module.DisposeAsync();
                    _module = null;
                }
                _disposed = true;
            }
        }

        // ============================================================================
        // Helper Types for JS Interop
        // ============================================================================

        /// <summary>
        /// Represents an RSA key pair result from JavaScript.
        /// </summary>
        private sealed class RsaKeyPairResult
        {
            /// <summary>
            /// Gets or sets the public key.
            /// </summary>
            public string PublicKey { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets the private key.
            /// </summary>
            public string PrivateKey { get; set; } = string.Empty;
        }

        /// <summary>
        /// Represents an EC key pair result from JavaScript.
        /// </summary>
        private sealed class EcKeyPairResult
        {
            /// <summary>
            /// Gets or sets the public key.
            /// </summary>
            public string PublicKey { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets the private key.
            /// </summary>
            public string PrivateKey { get; set; } = string.Empty;
        }
    }

    /// <summary>
    /// Represents the supported algorithms from Web Crypto API.
    /// </summary>
    public sealed class SupportedAlgorithms
    {
        /// <summary>
        /// Gets or sets the supported symmetric algorithms.
        /// </summary>
        public string[] Symmetric { get; set; } = [];

        /// <summary>
        /// Gets or sets the supported asymmetric algorithms.
        /// </summary>
        public string[] Asymmetric { get; set; } = [];

        /// <summary>
        /// Gets or sets the supported signature algorithms.
        /// </summary>
        public string[] Signatures { get; set; } = [];

        /// <summary>
        /// Gets or sets the supported key exchange algorithms.
        /// </summary>
        public string[] KeyExchange { get; set; } = [];

        /// <summary>
        /// Gets or sets the supported key derivation algorithms.
        /// </summary>
        public string[] KeyDerivation { get; set; } = [];

        /// <summary>
        /// Gets or sets the supported hash algorithms.
        /// </summary>
        public string[] Hashes { get; set; } = [];

        /// <summary>
        /// Gets or sets the supported elliptic curves.
        /// </summary>
        public string[] Curves { get; set; } = [];
    }

    /// <summary>
    /// Represents key storage metadata for IndexedDB.
    /// </summary>
    public sealed class KeyStorageMetadata
    {
        /// <summary>
        /// Gets or sets the key type.
        /// </summary>
        public int KeyType { get; set; }

        /// <summary>
        /// Gets or sets the key size in bits.
        /// </summary>
        public int KeySizeInBits { get; set; }

        /// <summary>
        /// Gets or sets the algorithm.
        /// </summary>
        public string Algorithm { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the creation timestamp.
        /// </summary>
        public string? CreatedAt { get; set; }

        /// <summary>
        /// Gets or sets the expiration timestamp.
        /// </summary>
        public string? ExpiresAt { get; set; }

        /// <summary>
        /// Gets or sets whether the key is active.
        /// </summary>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// Gets or sets whether the key is exportable.
        /// </summary>
        public bool IsExportable { get; set; } = true;

        /// <summary>
        /// Gets or sets custom tags.
        /// </summary>
        public Dictionary<string, string> Tags { get; set; } = [];
    }
}
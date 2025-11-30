// <copyright file="BlazorHeaderEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.Protocol.DoubleRatchet
{
    /// <summary>
    /// Implements header encryption for the Double Ratchet algorithm using Web Crypto API.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Header encryption provides an additional layer of privacy by encrypting
    /// the message header that contains metadata such as:
    /// <list type="bullet">
    /// <item><description>DH ratchet public key</description></item>
    /// <item><description>Message number in the sending chain</description></item>
    /// <item><description>Previous chain length</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Uses AES-GCM for authenticated encryption, which is supported by the Web Crypto API.
    /// </para>
    /// </remarks>
    public class BlazorHeaderEncryption : IBlazorHeaderEncryption
    {
        private readonly WebCryptoInterop _cryptoInterop;
        private byte[] _headerKey;
        private byte[] _nextHeaderKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorHeaderEncryption"/> class.
        /// </summary>
        /// <param name="cryptoInterop">The Web Crypto interop service.</param>
        /// <param name="initialKey">The initial header encryption key (32 bytes).</param>
        /// <exception cref="ArgumentNullException">Thrown when cryptoInterop or initialKey is null.</exception>
        public BlazorHeaderEncryption(WebCryptoInterop cryptoInterop, byte[] initialKey)
        {
            _cryptoInterop = cryptoInterop ?? throw new ArgumentNullException(nameof(cryptoInterop));
            _headerKey = initialKey ?? throw new ArgumentNullException(nameof(initialKey));
            _nextHeaderKey = new byte[32];
        }

        /// <inheritdoc/>
        public async Task<BlazorCryptoResult<byte[]>> EncryptAsync(byte[] headerBytes)
        {
            try
            {
                if (headerBytes == null || headerBytes.Length == 0)
                {
                    return BlazorCryptoResult<byte[]>.Failure("Header bytes cannot be empty.");
                }

                if (_headerKey == null || _headerKey.Length != 32)
                {
                    return BlazorCryptoResult<byte[]>.Failure("Header key is not initialized.");
                }

                // Encrypt using AES-GCM (IV is generated internally and prepended to result)
                byte[] ciphertext = await _cryptoInterop.AesGcmEncryptAsync(_headerKey, headerBytes, null);

                if (ciphertext == null)
                {
                    return BlazorCryptoResult<byte[]>.Failure("Header encryption failed.");
                }

                return BlazorCryptoResult<byte[]>.Success(ciphertext);
            }
            catch (Exception ex)
            {
                return BlazorCryptoResult<byte[]>.Failure($"Header encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<BlazorCryptoResult<byte[]>> DecryptAsync(byte[] encryptedData)
        {
            try
            {
                // Minimum size: 12 bytes IV + 16 bytes auth tag + at least 1 byte data
                if (encryptedData == null || encryptedData.Length < 29)
                {
                    return BlazorCryptoResult<byte[]>.Failure("Encrypted data is too short.");
                }

                if (_headerKey == null || _headerKey.Length != 32)
                {
                    return BlazorCryptoResult<byte[]>.Failure("Header key is not initialized.");
                }

                // Try decryption with current header key (IV is prepended in ciphertext)
                byte[]? plaintext = null;
                try
                {
                    plaintext = await _cryptoInterop.AesGcmDecryptAsync(_headerKey, encryptedData, null);
                }
                catch
                {
                    // Try with next header key if current fails
                    if (_nextHeaderKey != null && _nextHeaderKey.Length == 32)
                    {
                        plaintext = await _cryptoInterop.AesGcmDecryptAsync(_nextHeaderKey, encryptedData, null);
                    }
                }

                if (plaintext == null)
                {
                    return BlazorCryptoResult<byte[]>.Failure("Header decryption failed.");
                }

                return BlazorCryptoResult<byte[]>.Success(plaintext);
            }
            catch (Exception ex)
            {
                return BlazorCryptoResult<byte[]>.Failure($"Header decryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<BlazorCryptoResult<bool>> RatchetKeysAsync(byte[] newRootKey)
        {
            try
            {
                if (newRootKey == null || newRootKey.Length != 32)
                {
                    return BlazorCryptoResult<bool>.Failure("New root key must be 32 bytes.");
                }

                // Derive new header keys from root key using HKDF
                byte[] derivedKeys = await _cryptoInterop.HkdfDeriveKeyAsync(
                    newRootKey,
                    [],
                    System.Text.Encoding.UTF8.GetBytes("LucindaHeaderKeys"),
                    64);

                if (derivedKeys == null || derivedKeys.Length != 64)
                {
                    return BlazorCryptoResult<bool>.Failure("Failed to derive header keys.");
                }

                // Move next header key to current
                _headerKey = new byte[32];
                _nextHeaderKey = new byte[32];
                Array.Copy(derivedKeys, 0, _headerKey, 0, 32);
                Array.Copy(derivedKeys, 32, _nextHeaderKey, 0, 32);

                return BlazorCryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return BlazorCryptoResult<bool>.Failure($"Header key ratchet failed: {ex.Message}");
            }
        }
    }
}

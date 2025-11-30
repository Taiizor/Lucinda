// <copyright file="BlazorKdfChain.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor.Protocol.DoubleRatchet
{
    /// <summary>
    /// Implements KDF chain operations for the Double Ratchet algorithm using Web Crypto API.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class provides the key derivation functions required by the Double Ratchet algorithm:
    /// <list type="bullet">
    /// <item><description>Root KDF: Derives new root key and chain key from DH output</description></item>
    /// <item><description>Chain KDF: Derives message key and advances the chain key</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Uses HKDF-SHA256 as the underlying key derivation function, which is supported
    /// by the Web Crypto API in modern browsers.
    /// </para>
    /// </remarks>
    public class BlazorKdfChain : IBlazorKdfChain
    {
        private readonly WebCryptoInterop _cryptoInterop;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorKdfChain"/> class.
        /// </summary>
        /// <param name="cryptoInterop">The Web Crypto interop service.</param>
        /// <exception cref="ArgumentNullException">Thrown when cryptoInterop is null.</exception>
        public BlazorKdfChain(WebCryptoInterop cryptoInterop)
        {
            _cryptoInterop = cryptoInterop ?? throw new ArgumentNullException(nameof(cryptoInterop));
        }

        /// <inheritdoc/>
        public string AlgorithmName => "HKDF-SHA256";

        /// <inheritdoc/>
        public async Task<BlazorCryptoResult<(byte[] RootKey, byte[] ChainKey)>> RootKdfAsync(byte[] rootKey, byte[] dhOutput)
        {
            try
            {
                if (rootKey == null || rootKey.Length != 32)
                {
                    return BlazorCryptoResult<(byte[], byte[])>.Failure("Root key must be 32 bytes.");
                }

                if (dhOutput == null || dhOutput.Length == 0)
                {
                    return BlazorCryptoResult<(byte[], byte[])>.Failure("DH output is required.");
                }

                // Use HKDF to derive root key and chain key
                // Input: rootKey as salt, dhOutput as IKM
                // Output: 64 bytes (32 for new root key, 32 for chain key)
                byte[] derivedKey = await _cryptoInterop.HkdfDeriveKeyAsync(
                    dhOutput,
                    rootKey,
                    System.Text.Encoding.UTF8.GetBytes("LucindaRootKDF"),
                    64);

                if (derivedKey == null || derivedKey.Length != 64)
                {
                    return BlazorCryptoResult<(byte[], byte[])>.Failure("Failed to derive keys.");
                }

                byte[] newRootKey = new byte[32];
                byte[] chainKey = new byte[32];
                Array.Copy(derivedKey, 0, newRootKey, 0, 32);
                Array.Copy(derivedKey, 32, chainKey, 0, 32);

                return BlazorCryptoResult<(byte[], byte[])>.Success((newRootKey, chainKey));
            }
            catch (Exception ex)
            {
                return BlazorCryptoResult<(byte[], byte[])>.Failure($"Root KDF failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public async Task<BlazorCryptoResult<(byte[] MessageKey, byte[] NextChainKey)>> ChainKdfAsync(byte[] chainKey)
        {
            try
            {
                if (chainKey == null || chainKey.Length != 32)
                {
                    return BlazorCryptoResult<(byte[], byte[])>.Failure("Chain key must be 32 bytes.");
                }

                // Derive message key using constant 0x01
                byte[] messageKeyInput = new byte[33];
                Array.Copy(chainKey, messageKeyInput, 32);
                messageKeyInput[32] = 0x01;

                byte[] messageKey = await _cryptoInterop.HkdfDeriveKeyAsync(
                    messageKeyInput,
                    [],
                    System.Text.Encoding.UTF8.GetBytes("LucindaMessageKey"),
                    32);

                // Derive next chain key using constant 0x02
                byte[] nextChainKeyInput = new byte[33];
                Array.Copy(chainKey, nextChainKeyInput, 32);
                nextChainKeyInput[32] = 0x02;

                byte[] nextChainKey = await _cryptoInterop.HkdfDeriveKeyAsync(
                    nextChainKeyInput,
                    [],
                    System.Text.Encoding.UTF8.GetBytes("LucindaChainKey"),
                    32);

                if (messageKey == null || nextChainKey == null)
                {
                    return BlazorCryptoResult<(byte[], byte[])>.Failure("Failed to derive keys.");
                }

                return BlazorCryptoResult<(byte[], byte[])>.Success((messageKey, nextChainKey));
            }
            catch (Exception ex)
            {
                return BlazorCryptoResult<(byte[], byte[])>.Failure($"Chain KDF failed: {ex.Message}");
            }
        }
    }
}

// <copyright file="KdfChain.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using System.Security.Cryptography;

using Lucinda.Abstractions;
using Lucinda.KeyDerivation;

namespace Lucinda.Protocol.DoubleRatchet
{
    /// <summary>
    /// Provides KDF chain operations for the Double Ratchet algorithm.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This implementation uses HKDF for key derivation as specified in the Signal Protocol.
    /// <list type="bullet">
    /// <item><description>Root KDF: HKDF with root key as salt and DH output as input</description></item>
    /// <item><description>Chain KDF: HKDF with chain key as input, deriving message and next chain keys</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public sealed class KdfChain : IKdfChain, IDisposable
    {
        private readonly HkdfKeyDerivation _hkdf;
        private bool _disposed;

        /// <summary>
        /// Info bytes for root key derivation.
        /// </summary>
        private static readonly byte[] RootKdfInfo = "RootRatchet"u8.ToArray();

        /// <summary>
        /// Constant for message key derivation.
        /// </summary>
        private static readonly byte[] MessageKeyConstant = new byte[] { 0x01 };

        /// <summary>
        /// Constant for chain key derivation.
        /// </summary>
        private static readonly byte[] ChainKeyConstant = new byte[] { 0x02 };

        /// <summary>
        /// Initializes a new instance of the <see cref="KdfChain"/> class.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm to use. Default is SHA-256.</param>
        public KdfChain(HashAlgorithmName? hashAlgorithm = null)
        {
            _hkdf = new HkdfKeyDerivation(hashAlgorithm ?? HashAlgorithmName.SHA256);
        }

        /// <inheritdoc/>
        public string AlgorithmName => _hkdf.AlgorithmName;

        /// <inheritdoc/>
        public CryptoResult<(byte[] RootKey, byte[] ChainKey)> RootKdf(byte[] rootKey, byte[] dhOutput)
        {
            ThrowIfDisposed();

            if (rootKey == null || rootKey.Length == 0)
            {
                return CryptoResult<(byte[] RootKey, byte[] ChainKey)>.Failure("Root key cannot be null or empty.");
            }

            if (dhOutput == null || dhOutput.Length == 0)
            {
                return CryptoResult<(byte[] RootKey, byte[] ChainKey)>.Failure("DH output cannot be null or empty.");
            }

            try
            {
                // Use HKDF to derive 64 bytes (32 for new root key + 32 for chain key)
                // Extract phase: PRK = HKDF-Extract(salt=rootKey, IKM=dhOutput)
                CryptoResult<byte[]> extractResult = _hkdf.Extract(rootKey, dhOutput);
                if (extractResult.IsFailure)
                {
                    return CryptoResult<(byte[] RootKey, byte[] ChainKey)>.Failure(
                        $"Root KDF extract failed: {extractResult.Error}");
                }

                // Expand phase: output = HKDF-Expand(PRK, info, 64)
                CryptoResult<byte[]> expandResult = _hkdf.Expand(extractResult.Value, RootKdfInfo, 64);
                if (expandResult.IsFailure)
                {
                    return CryptoResult<(byte[] RootKey, byte[] ChainKey)>.Failure(
                        $"Root KDF expand failed: {expandResult.Error}");
                }

                byte[] output = expandResult.Value;
                byte[] newRootKey = new byte[32];
                byte[] chainKey = new byte[32];

                Buffer.BlockCopy(output, 0, newRootKey, 0, 32);
                Buffer.BlockCopy(output, 32, chainKey, 0, 32);

                // Clear intermediate value
                Utilities.CryptoHelpers.SecureClear(output);

                return CryptoResult<(byte[] RootKey, byte[] ChainKey)>.Success((newRootKey, chainKey));
            }
            catch (Exception ex)
            {
                return CryptoResult<(byte[] RootKey, byte[] ChainKey)>.Failure(
                    $"Root KDF failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<(byte[] MessageKey, byte[] NextChainKey)> ChainKdf(byte[] chainKey)
        {
            ThrowIfDisposed();

            if (chainKey == null || chainKey.Length == 0)
            {
                return CryptoResult<(byte[] MessageKey, byte[] NextChainKey)>.Failure(
                    "Chain key cannot be null or empty.");
            }

            try
            {
                // Message Key = HMAC-SHA256(chain_key, 0x01)
                byte[] messageKey;
                using (HMACSHA256 hmac = new(chainKey))
                {
                    messageKey = hmac.ComputeHash(MessageKeyConstant);
                }

                // Next Chain Key = HMAC-SHA256(chain_key, 0x02)
                byte[] nextChainKey;
                using (HMACSHA256 hmac = new(chainKey))
                {
                    nextChainKey = hmac.ComputeHash(ChainKeyConstant);
                }

                return CryptoResult<(byte[] MessageKey, byte[] NextChainKey)>.Success((messageKey, nextChainKey));
            }
            catch (Exception ex)
            {
                return CryptoResult<(byte[] MessageKey, byte[] NextChainKey)>.Failure(
                    $"Chain KDF failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Derives an encryption key and authentication key from a message key.
        /// </summary>
        /// <param name="messageKey">The message key (32 bytes).</param>
        /// <returns>
        /// A tuple of (encryptionKey, authKey, iv) for AEAD encryption.
        /// </returns>
        public CryptoResult<(byte[] EncryptionKey, byte[] AuthKey, byte[] IV)> DeriveMessageKeys(byte[] messageKey)
        {
            ThrowIfDisposed();

            if (messageKey == null || messageKey.Length < 32)
            {
                return CryptoResult<(byte[] EncryptionKey, byte[] AuthKey, byte[] IV)>.Failure(
                    "Message key must be at least 32 bytes.");
            }

            try
            {
                // Derive 80 bytes: 32 (encryption key) + 32 (auth key) + 16 (IV)
                CryptoResult<byte[]> deriveResult = _hkdf.DeriveKey(messageKey, null, "MessageKeys"u8.ToArray(), 80);
                if (deriveResult.IsFailure)
                {
                    return CryptoResult<(byte[] EncryptionKey, byte[] AuthKey, byte[] IV)>.Failure(
                        $"Message key derivation failed: {deriveResult.Error}");
                }

                byte[] output = deriveResult.Value;
                byte[] encryptionKey = new byte[32];
                byte[] authKey = new byte[32];
                byte[] iv = new byte[16];

                Buffer.BlockCopy(output, 0, encryptionKey, 0, 32);
                Buffer.BlockCopy(output, 32, authKey, 0, 32);
                Buffer.BlockCopy(output, 64, iv, 0, 16);

                // Clear intermediate value
                Utilities.CryptoHelpers.SecureClear(output);

                return CryptoResult<(byte[] EncryptionKey, byte[] AuthKey, byte[] IV)>.Success(
                    (encryptionKey, authKey, iv));
            }
            catch (Exception ex)
            {
                return CryptoResult<(byte[] EncryptionKey, byte[] AuthKey, byte[] IV)>.Failure(
                    $"Message key derivation failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Throws an <see cref="ObjectDisposedException"/> if this instance has been disposed.
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(KdfChain));
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (!_disposed)
            {
                _hkdf.Dispose();
                _disposed = true;
            }
        }
    }
}
#endif

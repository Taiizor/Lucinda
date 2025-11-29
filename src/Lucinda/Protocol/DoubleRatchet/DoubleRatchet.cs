// <copyright file="DoubleRatchet.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using System.Security.Cryptography;

using Lucinda.Abstractions;
using Lucinda.KeyExchange;
using Lucinda.Symmetric;
using Lucinda.Utilities;

namespace Lucinda.Protocol.DoubleRatchet
{
    /// <summary>
    /// Provides Double Ratchet algorithm implementation for forward-secure messaging.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Double Ratchet algorithm combines:
    /// <list type="bullet">
    /// <item><description>DH Ratchet: Provides break-in recovery through periodic key agreement</description></item>
    /// <item><description>Symmetric Ratchet: Provides forward secrecy for each message</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Key properties:
    /// <list type="bullet">
    /// <item><description>Forward Secrecy: Compromise of current keys doesn't reveal past messages</description></item>
    /// <item><description>Break-in Recovery: Future messages become secure after a compromise</description></item>
    /// <item><description>Out-of-order Delivery: Supports decrypting messages received out of order</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    /// <remarks>
    /// Initializes a new instance of the <see cref="DoubleRatchet"/> class.
    /// </remarks>
    /// <param name="curve">The elliptic curve to use. Default is P-256.</param>
    /// <param name="maxSkip">Maximum number of message keys to skip. Default is 100.</param>
    public sealed class DoubleRatchet(ECCurve? curve = null, int maxSkip = 100) : IDoubleRatchet, IDisposable
    {
        private readonly ECCurve _curve = curve ?? ECCurve.NamedCurves.nistP256;
        private readonly KdfChain _kdfChain = new(HashAlgorithmName.SHA256);
        private bool _disposed;

        /// <inheritdoc/>
        public string AlgorithmName => $"DoubleRatchet-{GetCurveName(_curve)}-{_kdfChain.AlgorithmName}";

        /// <inheritdoc/>
        public CryptoResult<RatchetState> InitializeAsInitiator(byte[] sharedSecret, byte[] remotePublicKey)
        {
            ThrowIfDisposed();

            if (sharedSecret == null || sharedSecret.Length < 32)
            {
                return CryptoResult<RatchetState>.Failure("Shared secret must be at least 32 bytes.");
            }

            if (remotePublicKey == null || remotePublicKey.Length == 0)
            {
                return CryptoResult<RatchetState>.Failure("Remote public key cannot be null or empty.");
            }

            try
            {
                // Generate our sending key pair
                using EcdhKeyExchange ecdh = new(_curve);
                CryptoResult<AsymmetricKeyPair> keyPairResult = ecdh.GenerateKeyPair();
                if (keyPairResult.IsFailure)
                {
                    return CryptoResult<RatchetState>.Failure($"Failed to generate key pair: {keyPairResult.Error}");
                }

                RatchetState state = new()
                {
                    DHSendingPrivateKey = keyPairResult.Value.PrivateKey,
                    DHSendingPublicKey = keyPairResult.Value.PublicKey,
                    DHReceivingPublicKey = [.. remotePublicKey],
                    RootKey = [.. sharedSecret],
                    SendingMessageNumber = 0,
                    ReceivingMessageNumber = 0,
                    PreviousSendingChainLength = 0
                };

                // Perform initial DH ratchet to derive sending chain key
                CryptoResult<byte[]> dhResult = PerformDH(state.DHSendingPrivateKey, state.DHReceivingPublicKey);
                if (dhResult.IsFailure)
                {
                    state.Dispose();
                    return CryptoResult<RatchetState>.Failure($"Initial DH failed: {dhResult.Error}");
                }

                CryptoResult<(byte[] RootKey, byte[] ChainKey)> kdfResult = _kdfChain.RootKdf(state.RootKey, dhResult.Value);
                if (kdfResult.IsFailure)
                {
                    state.Dispose();
                    return CryptoResult<RatchetState>.Failure($"Root KDF failed: {kdfResult.Error}");
                }

                CryptoHelpers.SecureClear(state.RootKey);
                state.RootKey = kdfResult.Value.RootKey;
                state.SendingChainKey = kdfResult.Value.ChainKey;

                // Clear sensitive data
                CryptoHelpers.SecureClear(dhResult.Value);

                return CryptoResult<RatchetState>.Success(state);
            }
            catch (Exception ex)
            {
                return CryptoResult<RatchetState>.Failure($"Initiator initialization failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<RatchetState> InitializeAsResponder(byte[] sharedSecret, AsymmetricKeyPair localKeyPair)
        {
            ThrowIfDisposed();

            if (sharedSecret == null || sharedSecret.Length < 32)
            {
                return CryptoResult<RatchetState>.Failure("Shared secret must be at least 32 bytes.");
            }

            if (localKeyPair == null)
            {
                return CryptoResult<RatchetState>.Failure("Local key pair cannot be null.");
            }

            try
            {
                RatchetState state = new()
                {
                    DHSendingPrivateKey = [.. localKeyPair.PrivateKey],
                    DHSendingPublicKey = [.. localKeyPair.PublicKey],
                    DHReceivingPublicKey = null, // Will be set when first message is received
                    RootKey = [.. sharedSecret],
                    SendingChainKey = null, // Will be set after first DH ratchet
                    ReceivingChainKey = null,
                    SendingMessageNumber = 0,
                    ReceivingMessageNumber = 0,
                    PreviousSendingChainLength = 0
                };

                return CryptoResult<RatchetState>.Success(state);
            }
            catch (Exception ex)
            {
                return CryptoResult<RatchetState>.Failure($"Responder initialization failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<RatchetMessage> Encrypt(RatchetState state, byte[] plaintext, byte[]? associatedData = null)
        {
            ThrowIfDisposed();

            if (state == null)
            {
                return CryptoResult<RatchetMessage>.Failure("State cannot be null.");
            }

            if (plaintext == null)
            {
                return CryptoResult<RatchetMessage>.Failure("Plaintext cannot be null.");
            }

            if (state.SendingChainKey == null)
            {
                return CryptoResult<RatchetMessage>.Failure("Sending chain key not initialized.");
            }

            if (state.DHSendingPublicKey == null)
            {
                return CryptoResult<RatchetMessage>.Failure("DH sending public key not initialized.");
            }

            try
            {
                // Derive message key and advance chain
                CryptoResult<(byte[] MessageKey, byte[] NextChainKey)> chainResult =
                    _kdfChain.ChainKdf(state.SendingChainKey);
                if (chainResult.IsFailure)
                {
                    return CryptoResult<RatchetMessage>.Failure($"Chain KDF failed: {chainResult.Error}");
                }

                byte[] messageKey = chainResult.Value.MessageKey;

                // Update sending chain key
                CryptoHelpers.SecureClear(state.SendingChainKey);
                state.SendingChainKey = chainResult.Value.NextChainKey;

                // Create header
                RatchetHeader header = new(
                    state.DHSendingPublicKey,
                    state.PreviousSendingChainLength,
                    state.SendingMessageNumber);

                // Encrypt the message using AES-GCM
                CryptoResult<byte[]> encryptResult = EncryptWithMessageKey(
                    messageKey,
                    plaintext,
                    header.ToBytes(),
                    associatedData);

                // Clear message key
                CryptoHelpers.SecureClear(messageKey);

                if (encryptResult.IsFailure)
                {
                    return CryptoResult<RatchetMessage>.Failure($"Encryption failed: {encryptResult.Error}");
                }

                // Increment message counter
                state.SendingMessageNumber++;

                return CryptoResult<RatchetMessage>.Success(new RatchetMessage(header, encryptResult.Value));
            }
            catch (Exception ex)
            {
                return CryptoResult<RatchetMessage>.Failure($"Encryption failed: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public CryptoResult<byte[]> Decrypt(RatchetState state, RatchetMessage message, byte[]? associatedData = null)
        {
            ThrowIfDisposed();

            if (state == null)
            {
                return CryptoResult<byte[]>.Failure("State cannot be null.");
            }

            if (message == null)
            {
                return CryptoResult<byte[]>.Failure("Message cannot be null.");
            }

            try
            {
                // Try to use a skipped message key first
                if (state.TryConsumeSkippedMessageKey(
                    message.Header.DHPublicKey,
                    message.Header.MessageNumber,
                    out byte[]? skippedKey) && skippedKey != null)
                {
                    CryptoResult<byte[]> skippedDecryptResult = DecryptWithMessageKey(
                        skippedKey,
                        message.Ciphertext,
                        message.Header.ToBytes(),
                        associatedData);

                    CryptoHelpers.SecureClear(skippedKey);
                    return skippedDecryptResult;
                }

                // Check if we need to perform a DH ratchet
                bool needsDHRatchet = state.DHReceivingPublicKey == null ||
                    !CryptoHelpers.ConstantTimeEquals(message.Header.DHPublicKey, state.DHReceivingPublicKey);

                if (needsDHRatchet)
                {
                    // Skip any remaining messages in current receiving chain
                    if (state.ReceivingChainKey != null)
                    {
                        CryptoResult<bool> skipResult = SkipMessageKeys(
                            state,
                            state.DHReceivingPublicKey!,
                            message.Header.PreviousChainLength);

                        if (skipResult.IsFailure)
                        {
                            return CryptoResult<byte[]>.Failure($"Failed to skip message keys: {skipResult.Error}");
                        }
                    }

                    // Perform DH ratchet
                    CryptoResult<bool> ratchetResult = PerformDHRatchet(state, message.Header.DHPublicKey);
                    if (ratchetResult.IsFailure)
                    {
                        return CryptoResult<byte[]>.Failure($"DH ratchet failed: {ratchetResult.Error}");
                    }
                }

                // Skip messages in current chain if needed
                if (message.Header.MessageNumber > state.ReceivingMessageNumber)
                {
                    CryptoResult<bool> skipResult = SkipMessageKeys(
                        state,
                        message.Header.DHPublicKey,
                        message.Header.MessageNumber);

                    if (skipResult.IsFailure)
                    {
                        return CryptoResult<byte[]>.Failure($"Failed to skip message keys: {skipResult.Error}");
                    }
                }

                // Derive message key
                if (state.ReceivingChainKey == null)
                {
                    return CryptoResult<byte[]>.Failure("Receiving chain key not initialized.");
                }

                CryptoResult<(byte[] MessageKey, byte[] NextChainKey)> chainResult =
                    _kdfChain.ChainKdf(state.ReceivingChainKey);
                if (chainResult.IsFailure)
                {
                    return CryptoResult<byte[]>.Failure($"Chain KDF failed: {chainResult.Error}");
                }

                byte[] messageKey = chainResult.Value.MessageKey;

                // Update receiving chain key
                CryptoHelpers.SecureClear(state.ReceivingChainKey);
                state.ReceivingChainKey = chainResult.Value.NextChainKey;
                state.ReceivingMessageNumber++;

                // Decrypt
                CryptoResult<byte[]> decryptResult = DecryptWithMessageKey(
                    messageKey,
                    message.Ciphertext,
                    message.Header.ToBytes(),
                    associatedData);

                CryptoHelpers.SecureClear(messageKey);

                return decryptResult;
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Decryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Performs a DH ratchet step.
        /// </summary>
        private CryptoResult<bool> PerformDHRatchet(RatchetState state, byte[] remotePublicKey)
        {
            try
            {
                // Store previous chain length
                state.PreviousSendingChainLength = state.SendingMessageNumber;
                state.SendingMessageNumber = 0;
                state.ReceivingMessageNumber = 0;

                // Update receiving public key
                state.DHReceivingPublicKey = [.. remotePublicKey];

                // Derive receiving chain key
                CryptoResult<byte[]> dhResult = PerformDH(state.DHSendingPrivateKey!, state.DHReceivingPublicKey);
                if (dhResult.IsFailure)
                {
                    return CryptoResult<bool>.Failure($"DH failed: {dhResult.Error}");
                }

                CryptoResult<(byte[] RootKey, byte[] ChainKey)> kdfResult =
                    _kdfChain.RootKdf(state.RootKey!, dhResult.Value);
                CryptoHelpers.SecureClear(dhResult.Value);

                if (kdfResult.IsFailure)
                {
                    return CryptoResult<bool>.Failure($"Root KDF failed: {kdfResult.Error}");
                }

                if (state.RootKey != null)
                {
                    CryptoHelpers.SecureClear(state.RootKey);
                }
                state.RootKey = kdfResult.Value.RootKey;
                state.ReceivingChainKey = kdfResult.Value.ChainKey;

                // Generate new sending key pair
                using EcdhKeyExchange ecdh = new(_curve);
                CryptoResult<AsymmetricKeyPair> keyPairResult = ecdh.GenerateKeyPair();
                if (keyPairResult.IsFailure)
                {
                    return CryptoResult<bool>.Failure($"Key pair generation failed: {keyPairResult.Error}");
                }

                if (state.DHSendingPrivateKey != null)
                {
                    CryptoHelpers.SecureClear(state.DHSendingPrivateKey);
                }
                state.DHSendingPrivateKey = keyPairResult.Value.PrivateKey;
                state.DHSendingPublicKey = keyPairResult.Value.PublicKey;

                // Derive sending chain key
                dhResult = PerformDH(state.DHSendingPrivateKey, state.DHReceivingPublicKey);
                if (dhResult.IsFailure)
                {
                    return CryptoResult<bool>.Failure($"DH failed: {dhResult.Error}");
                }

                kdfResult = _kdfChain.RootKdf(state.RootKey, dhResult.Value);
                CryptoHelpers.SecureClear(dhResult.Value);

                if (kdfResult.IsFailure)
                {
                    return CryptoResult<bool>.Failure($"Root KDF failed: {kdfResult.Error}");
                }

                CryptoHelpers.SecureClear(state.RootKey);
                state.RootKey = kdfResult.Value.RootKey;
                state.SendingChainKey = kdfResult.Value.ChainKey;

                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"DH ratchet failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Skips message keys up to a certain message number and stores them.
        /// </summary>
        private CryptoResult<bool> SkipMessageKeys(RatchetState state, byte[] publicKey, int until)
        {
            if (state.ReceivingChainKey == null)
            {
                return CryptoResult<bool>.Success(true);
            }

            if (until - state.ReceivingMessageNumber > maxSkip)
            {
                return CryptoResult<bool>.Failure($"Too many skipped messages: {until - state.ReceivingMessageNumber}");
            }

            while (state.ReceivingMessageNumber < until)
            {
                CryptoResult<(byte[] MessageKey, byte[] NextChainKey)> chainResult =
                    _kdfChain.ChainKdf(state.ReceivingChainKey);
                if (chainResult.IsFailure)
                {
                    return CryptoResult<bool>.Failure($"Chain KDF failed: {chainResult.Error}");
                }

                if (!state.StoreSkippedMessageKey(publicKey, state.ReceivingMessageNumber, chainResult.Value.MessageKey))
                {
                    CryptoHelpers.SecureClear(chainResult.Value.MessageKey);
                    return CryptoResult<bool>.Failure("Too many skipped message keys stored.");
                }

                CryptoHelpers.SecureClear(state.ReceivingChainKey);
                state.ReceivingChainKey = chainResult.Value.NextChainKey;
                state.ReceivingMessageNumber++;
            }

            return CryptoResult<bool>.Success(true);
        }

        /// <summary>
        /// Performs a Diffie-Hellman key agreement.
        /// </summary>
        private CryptoResult<byte[]> PerformDH(byte[] privateKey, byte[] publicKey)
        {
            try
            {
                using ECDiffieHellman ecdh = ECDiffieHellman.Create();
                ecdh.ImportPkcs8PrivateKey(privateKey, out _);

                using ECDiffieHellman remoteEcdh = ECDiffieHellman.Create();
                remoteEcdh.ImportSubjectPublicKeyInfo(publicKey, out _);

                byte[] sharedSecret = ecdh.DeriveKeyMaterial(remoteEcdh.PublicKey);
                return CryptoResult<byte[]>.Success(sharedSecret);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"DH operation failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Encrypts data using a message key.
        /// </summary>
        private CryptoResult<byte[]> EncryptWithMessageKey(
            byte[] messageKey,
            byte[] plaintext,
            byte[] header,
            byte[]? additionalData)
        {
            try
            {
                // Derive encryption keys from message key
                CryptoResult<(byte[] EncryptionKey, byte[] AuthKey, byte[] IV)> keysResult =
                    _kdfChain.DeriveMessageKeys(messageKey);
                if (keysResult.IsFailure)
                {
                    return CryptoResult<byte[]>.Failure($"Key derivation failed: {keysResult.Error}");
                }

                // Combine header and additional data for AAD
                byte[] aad = CombineAad(header, additionalData);

                // Encrypt with AES-GCM
                using AesGcmEncryption aes = new(keysResult.Value.EncryptionKey);
                CryptoResult<byte[]> encryptResult = aes.Encrypt(plaintext, aad);

                // Clear keys
                CryptoHelpers.SecureClear(keysResult.Value.EncryptionKey);
                CryptoHelpers.SecureClear(keysResult.Value.AuthKey);
                CryptoHelpers.SecureClear(keysResult.Value.IV);

                return encryptResult;
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Encryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Decrypts data using a message key.
        /// </summary>
        private CryptoResult<byte[]> DecryptWithMessageKey(
            byte[] messageKey,
            byte[] ciphertext,
            byte[] header,
            byte[]? additionalData)
        {
            try
            {
                // Derive encryption keys from message key
                CryptoResult<(byte[] EncryptionKey, byte[] AuthKey, byte[] IV)> keysResult =
                    _kdfChain.DeriveMessageKeys(messageKey);
                if (keysResult.IsFailure)
                {
                    return CryptoResult<byte[]>.Failure($"Key derivation failed: {keysResult.Error}");
                }

                // Combine header and additional data for AAD
                byte[] aad = CombineAad(header, additionalData);

                // Decrypt with AES-GCM
                using AesGcmEncryption aes = new(keysResult.Value.EncryptionKey);
                CryptoResult<byte[]> decryptResult = aes.Decrypt(ciphertext, aad);

                // Clear keys
                CryptoHelpers.SecureClear(keysResult.Value.EncryptionKey);
                CryptoHelpers.SecureClear(keysResult.Value.AuthKey);
                CryptoHelpers.SecureClear(keysResult.Value.IV);

                return decryptResult;
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Decryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Combines header and additional data for use as AAD.
        /// </summary>
        private static byte[] CombineAad(byte[] header, byte[]? additionalData)
        {
            if (additionalData == null || additionalData.Length == 0)
            {
                return header;
            }

            byte[] combined = new byte[header.Length + additionalData.Length];
            Buffer.BlockCopy(header, 0, combined, 0, header.Length);
            Buffer.BlockCopy(additionalData, 0, combined, header.Length, additionalData.Length);
            return combined;
        }

        /// <summary>
        /// Gets the curve name for display.
        /// </summary>
        private static string GetCurveName(ECCurve curve)
        {
            if (curve.Oid?.FriendlyName != null)
            {
                return curve.Oid.FriendlyName;
            }
            return "Unknown";
        }

        /// <summary>
        /// Throws if disposed.
        /// </summary>
        private void ThrowIfDisposed()
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(DoubleRatchet));
            }
#endif
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (!_disposed)
            {
                _kdfChain.Dispose();
                _disposed = true;
            }
        }
    }
}
#endif
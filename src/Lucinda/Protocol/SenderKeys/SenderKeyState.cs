// -----------------------------------------------------------------------
// <copyright file="SenderKeyState.cs" company="Taiizor">
// Copyright (c) Taiizor. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.
// </copyright>
// -----------------------------------------------------------------------

#if NET6_0_OR_GREATER
using System;
using System.Security.Cryptography;
using System.Text;

namespace Lucinda.Protocol.SenderKeys
{
    /// <summary>
    /// Represents the state of a Sender Key for group messaging.
    /// Each sender in a group has their own Sender Key state that they use to encrypt messages.
    /// </summary>
    public class SenderKeyState : IDisposable
    {
        private const int KeySize = 32;
        private const int MaxChainLength = 2000; // Maximum messages before re-keying required

        private byte[]? _chainKey;
        private byte[]? _signaturePrivateKey;
        private bool _disposed;

        /// <summary>
        /// Gets the key ID that identifies this sender key generation.
        /// </summary>
        public int KeyId { get; }

        /// <summary>
        /// Gets the current chain index (message counter).
        /// </summary>
        public int ChainIndex { get; private set; }

        /// <summary>
        /// Gets the signature public key for verifying messages from this sender.
        /// </summary>
        public byte[]? SignaturePublicKey { get; }

        /// <summary>
        /// Gets whether the state has a private key (i.e., is the owner).
        /// </summary>
        public bool IsOwner => _signaturePrivateKey != null;

        /// <summary>
        /// Initializes a new SenderKeyState for the sender (owner).
        /// </summary>
        /// <param name="keyId">The key ID for this generation.</param>
        /// <param name="chainKey">The initial chain key (32 bytes).</param>
        /// <param name="signaturePrivateKey">The signature private key.</param>
        /// <param name="signaturePublicKey">The signature public key.</param>
        private SenderKeyState(int keyId, byte[] chainKey, byte[]? signaturePrivateKey, byte[] signaturePublicKey)
        {
            KeyId = keyId;
            _chainKey = (byte[])chainKey.Clone();
            _signaturePrivateKey = signaturePrivateKey != null ? (byte[])signaturePrivateKey.Clone() : null;
            SignaturePublicKey = (byte[])signaturePublicKey.Clone();
            ChainIndex = 0;
        }

        /// <summary>
        /// Creates a new SenderKeyState as the owner (can sign and encrypt).
        /// </summary>
        /// <param name="keyId">The key ID.</param>
        /// <returns>A new SenderKeyState.</returns>
        public static SenderKeyState CreateAsOwner(int keyId)
        {
            byte[] chainKey = RandomNumberGenerator.GetBytes(KeySize);

            // Generate ECDSA key pair for signing (using P-256 as native)
            using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] signaturePrivateKey = ecdsa.ExportECPrivateKey();
            byte[] signaturePublicKey = ecdsa.ExportSubjectPublicKeyInfo();

            return new SenderKeyState(keyId, chainKey, signaturePrivateKey, signaturePublicKey);
        }

        /// <summary>
        /// Creates a SenderKeyState from a received distribution message (can only decrypt).
        /// </summary>
        /// <param name="keyId">The key ID.</param>
        /// <param name="chainKey">The chain key from the distribution message.</param>
        /// <param name="signaturePublicKey">The signature public key from the distribution message.</param>
        /// <param name="chainIndex">The starting chain index.</param>
        /// <returns>A new SenderKeyState.</returns>
        public static SenderKeyState CreateFromDistribution(int keyId, byte[] chainKey, byte[] signaturePublicKey, int chainIndex)
        {
            SenderKeyState state = new(keyId, chainKey, null, signaturePublicKey)
            {
                ChainIndex = chainIndex
            };
            return state;
        }

        /// <summary>
        /// Gets the current message key and advances the chain.
        /// </summary>
        /// <returns>The message key, or null if max chain length exceeded.</returns>
        public byte[]? GetMessageKeyAndAdvance()
        {
            if (_disposed || _chainKey == null)
            {
                return null;
            }

            if (ChainIndex >= MaxChainLength)
            {
                return null; // Re-keying required
            }

            // Derive message key from chain key
            byte[] messageKeyInfo = Encoding.UTF8.GetBytes("SenderKey_MessageKey");
            byte[] messageKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, _chainKey, KeySize, null, messageKeyInfo);

            // Advance chain key
            byte[] chainKeyInfo = Encoding.UTF8.GetBytes("SenderKey_ChainKey");
            byte[] newChainKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, _chainKey, KeySize, null, chainKeyInfo);

            CryptographicOperations.ZeroMemory(_chainKey);
            _chainKey = newChainKey;
            ChainIndex++;

            return messageKey;
        }

        /// <summary>
        /// Gets the message key for a specific chain index (for decryption of out-of-order messages).
        /// This does NOT advance the state.
        /// </summary>
        /// <param name="targetIndex">The target chain index.</param>
        /// <returns>The message key at that index, or null if not reachable.</returns>
        public byte[]? GetMessageKeyAtIndex(int targetIndex)
        {
            if (_disposed || _chainKey == null)
            {
                return null;
            }

            if (targetIndex < ChainIndex || targetIndex >= MaxChainLength)
            {
                return null;
            }

            // Clone current chain key to iterate forward
            byte[] tempChainKey = (byte[])_chainKey.Clone();
            int currentIndex = ChainIndex;

            try
            {
                // Advance to target index
                while (currentIndex < targetIndex)
                {
                    byte[] chainKeyInfo = Encoding.UTF8.GetBytes("SenderKey_ChainKey");
                    byte[] newChainKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, tempChainKey, KeySize, null, chainKeyInfo);
                    CryptographicOperations.ZeroMemory(tempChainKey);
                    tempChainKey = newChainKey;
                    currentIndex++;
                }

                // Derive message key at target
                byte[] messageKeyInfo = Encoding.UTF8.GetBytes("SenderKey_MessageKey");
                return HKDF.DeriveKey(HashAlgorithmName.SHA256, tempChainKey, KeySize, null, messageKeyInfo);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(tempChainKey);
            }
        }

        /// <summary>
        /// Signs data using the sender's signature key.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <returns>The signature, or null if not the owner.</returns>
        public byte[]? Sign(byte[] data)
        {
            if (_disposed || _signaturePrivateKey == null)
            {
                return null;
            }

            using ECDsa ecdsa = ECDsa.Create();
            ecdsa.ImportECPrivateKey(_signaturePrivateKey, out _);
            return ecdsa.SignData(data, HashAlgorithmName.SHA256);
        }

        /// <summary>
        /// Verifies a signature using the sender's public key.
        /// </summary>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>True if valid, false otherwise.</returns>
        public bool Verify(byte[] data, byte[] signature)
        {
            if (_disposed || SignaturePublicKey == null)
            {
                return false;
            }

            try
            {
                using ECDsa ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(SignaturePublicKey, out _);
                return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Exports the state for distribution to other group members.
        /// </summary>
        /// <returns>The distribution data.</returns>
        public SenderKeyDistributionData? ExportForDistribution()
        {
            if (_disposed || _chainKey == null || SignaturePublicKey == null)
            {
                return null;
            }

            return new SenderKeyDistributionData(
                KeyId,
                (byte[])_chainKey.Clone(),
                (byte[])SignaturePublicKey.Clone(),
                ChainIndex);
        }

        /// <summary>
        /// Disposes the state and clears sensitive data.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes managed resources.
        /// </summary>
        /// <param name="disposing">True if disposing managed resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    if (_chainKey != null)
                    {
                        CryptographicOperations.ZeroMemory(_chainKey);
                        _chainKey = null;
                    }
                    if (_signaturePrivateKey != null)
                    {
                        CryptographicOperations.ZeroMemory(_signaturePrivateKey);
                        _signaturePrivateKey = null;
                    }
                }
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Data for distributing a sender key to group members.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of SenderKeyDistributionData.
    /// </remarks>
    public class SenderKeyDistributionData(int keyId, byte[] chainKey, byte[] signaturePublicKey, int chainIndex)
    {
        /// <summary>
        /// Gets the key ID.
        /// </summary>
        public int KeyId { get; } = keyId;

        /// <summary>
        /// Gets the chain key.
        /// </summary>
        public byte[] ChainKey { get; } = chainKey;

        /// <summary>
        /// Gets the signature public key.
        /// </summary>
        public byte[] SignaturePublicKey { get; } = signaturePublicKey;

        /// <summary>
        /// Gets the current chain index.
        /// </summary>
        public int ChainIndex { get; } = chainIndex;

        /// <summary>
        /// Serializes the distribution data to a byte array.
        /// </summary>
        public byte[] Serialize()
        {
            // Format: [KeyId:4][ChainIndex:4][ChainKeyLength:4][ChainKey][PublicKeyLength:4][PublicKey]
            byte[] result = new byte[4 + 4 + 4 + ChainKey.Length + 4 + SignaturePublicKey.Length];
            int offset = 0;

            BitConverter.GetBytes(KeyId).CopyTo(result, offset);
            offset += 4;

            BitConverter.GetBytes(ChainIndex).CopyTo(result, offset);
            offset += 4;

            BitConverter.GetBytes(ChainKey.Length).CopyTo(result, offset);
            offset += 4;
            ChainKey.CopyTo(result, offset);
            offset += ChainKey.Length;

            BitConverter.GetBytes(SignaturePublicKey.Length).CopyTo(result, offset);
            offset += 4;
            SignaturePublicKey.CopyTo(result, offset);

            return result;
        }

        /// <summary>
        /// Deserializes distribution data from a byte array.
        /// </summary>
        public static SenderKeyDistributionData? Deserialize(byte[] data)
        {
            if (data == null || data.Length < 16)
            {
                return null;
            }

            try
            {
                int offset = 0;

                int keyId = BitConverter.ToInt32(data, offset);
                offset += 4;

                int chainIndex = BitConverter.ToInt32(data, offset);
                offset += 4;

                int chainKeyLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                if (offset + chainKeyLength > data.Length)
                {
                    return null;
                }
                byte[] chainKey = new byte[chainKeyLength];
                Array.Copy(data, offset, chainKey, 0, chainKeyLength);
                offset += chainKeyLength;

                int publicKeyLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                if (offset + publicKeyLength > data.Length)
                {
                    return null;
                }
                byte[] publicKey = new byte[publicKeyLength];
                Array.Copy(data, offset, publicKey, 0, publicKeyLength);

                return new SenderKeyDistributionData(keyId, chainKey, publicKey, chainIndex);
            }
            catch
            {
                return null;
            }
        }
    }
}
#endif
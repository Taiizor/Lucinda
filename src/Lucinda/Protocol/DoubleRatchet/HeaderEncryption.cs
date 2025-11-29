// -----------------------------------------------------------------------
// <copyright file="HeaderEncryption.cs" company="Taiizor">
// Copyright (c) Taiizor. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.
// </copyright>
// -----------------------------------------------------------------------

#if NET6_0_OR_GREATER
using Lucinda.Abstractions;
using Lucinda.Utilities;
using System;
using System.Security.Cryptography;

namespace Lucinda.Protocol.DoubleRatchet
{
    /// <summary>
    /// Provides header encryption for Double Ratchet messages.
    /// Header encryption protects metadata such as message number and ratchet public key.
    /// </summary>
    public class HeaderEncryption : IDisposable
    {
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32;
        private const string HeaderKeyInfo = "Lucinda_HeaderKey";
        private const string NextHeaderKeyInfo = "Lucinda_NextHeaderKey";

        private byte[]? _headerKey;
        private byte[]? _nextHeaderKey;
        private bool _disposed;

        /// <summary>
        /// Initializes header encryption with derived keys.
        /// </summary>
        /// <param name="rootKey">The root key to derive header keys from.</param>
        /// <returns>A CryptoResult containing the HeaderEncryption instance.</returns>
        public static CryptoResult<HeaderEncryption> Initialize(byte[] rootKey)
        {
            if (rootKey == null || rootKey.Length == 0)
            {
                return CryptoResult<HeaderEncryption>.Failure("Root key cannot be null or empty");
            }

            try
            {
                HeaderEncryption instance = new()
                {
                    _headerKey = DeriveHeaderKey(rootKey, HeaderKeyInfo),
                    _nextHeaderKey = DeriveHeaderKey(rootKey, NextHeaderKeyInfo)
                };
                return CryptoResult<HeaderEncryption>.Success(instance);
            }
            catch (Exception ex)
            {
                return CryptoResult<HeaderEncryption>.Failure($"Failed to initialize header encryption: {ex.Message}");
            }
        }

        /// <summary>
        /// Updates the header keys during a DH ratchet step.
        /// </summary>
        /// <param name="newRootKey">The new root key after ratchet.</param>
        /// <returns>A CryptoResult indicating success or failure.</returns>
        public CryptoResult<bool> RatchetHeaderKeys(byte[] newRootKey)
        {
            if (_disposed)
            {
                return CryptoResult<bool>.Failure("HeaderEncryption has been disposed");
            }

            if (newRootKey == null || newRootKey.Length == 0)
            {
                return CryptoResult<bool>.Failure("New root key cannot be null or empty");
            }

            try
            {
                // Move next header key to current header key
                if (_headerKey != null)
                {
                    CryptographicOperations.ZeroMemory(_headerKey);
                }
                _headerKey = _nextHeaderKey;

                // Derive new next header key
                _nextHeaderKey = DeriveHeaderKey(newRootKey, NextHeaderKeyInfo);

                return CryptoResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Failed to ratchet header keys: {ex.Message}");
            }
        }

        /// <summary>
        /// Encrypts a ratchet header.
        /// </summary>
        /// <param name="header">The header to encrypt.</param>
        /// <returns>A CryptoResult containing the encrypted header.</returns>
        public CryptoResult<EncryptedHeader> EncryptHeader(RatchetHeader header)
        {
            if (_disposed)
            {
                return CryptoResult<EncryptedHeader>.Failure("HeaderEncryption has been disposed");
            }

            if (header == null)
            {
                return CryptoResult<EncryptedHeader>.Failure("Header cannot be null");
            }

            if (_headerKey == null)
            {
                return CryptoResult<EncryptedHeader>.Failure("Header key not initialized");
            }

            try
            {
                byte[] headerBytes = header.ToBytes();
                byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
                byte[] ciphertext = new byte[headerBytes.Length];
                byte[] tag = new byte[TagSize];

#if NET8_0_OR_GREATER
                using var aesGcm = new AesGcm(_headerKey, TagSize);
#else
                using AesGcm aesGcm = new(_headerKey);
#endif
                aesGcm.Encrypt(nonce, headerBytes, ciphertext, tag);

                CryptographicOperations.ZeroMemory(headerBytes);

                return CryptoResult<EncryptedHeader>.Success(new EncryptedHeader(nonce, ciphertext, tag));
            }
            catch (Exception ex)
            {
                return CryptoResult<EncryptedHeader>.Failure($"Failed to encrypt header: {ex.Message}");
            }
        }

        /// <summary>
        /// Decrypts an encrypted header using the current header key.
        /// </summary>
        /// <param name="encryptedHeader">The encrypted header.</param>
        /// <returns>A CryptoResult containing the decrypted header.</returns>
        public CryptoResult<RatchetHeader> DecryptHeader(EncryptedHeader encryptedHeader)
        {
            if (_disposed)
            {
                return CryptoResult<RatchetHeader>.Failure("HeaderEncryption has been disposed");
            }

            if (encryptedHeader == null)
            {
                return CryptoResult<RatchetHeader>.Failure("Encrypted header cannot be null");
            }

            // Try current header key first
            if (_headerKey != null)
            {
                CryptoResult<RatchetHeader> result = TryDecryptWithKey(_headerKey, encryptedHeader);
                if (result.IsSuccess)
                {
                    return result;
                }
            }

            // Try next header key (for out-of-order messages after ratchet)
            if (_nextHeaderKey != null)
            {
                CryptoResult<RatchetHeader> result = TryDecryptWithKey(_nextHeaderKey, encryptedHeader);
                if (result.IsSuccess)
                {
                    return result;
                }
            }

            return CryptoResult<RatchetHeader>.Failure("Failed to decrypt header with any available key");
        }

        /// <summary>
        /// Attempts to decrypt a header with a specific key.
        /// </summary>
        /// <param name="key">The key to use for decryption.</param>
        /// <param name="encryptedHeader">The encrypted header.</param>
        /// <returns>A CryptoResult containing the decrypted header.</returns>
        public static CryptoResult<RatchetHeader> TryDecryptWithKey(byte[] key, EncryptedHeader encryptedHeader)
        {
            if (key == null || key.Length != KeySize)
            {
                return CryptoResult<RatchetHeader>.Failure("Invalid key");
            }

            try
            {
                byte[] plaintext = new byte[encryptedHeader.Ciphertext.Length];

#if NET8_0_OR_GREATER
                using var aesGcm = new AesGcm(key, TagSize);
#else
                using AesGcm aesGcm = new(key);
#endif
                aesGcm.Decrypt(encryptedHeader.Nonce, encryptedHeader.Ciphertext, encryptedHeader.Tag, plaintext);

                RatchetHeader header = RatchetHeader.FromBytes(plaintext);
                CryptographicOperations.ZeroMemory(plaintext);

                return CryptoResult<RatchetHeader>.Success(header);
            }
            catch (CryptographicException)
            {
                return CryptoResult<RatchetHeader>.Failure("Authentication failed - wrong key or corrupted data");
            }
            catch (Exception ex)
            {
                return CryptoResult<RatchetHeader>.Failure($"Decryption failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Derives a header key from a root key using HKDF.
        /// </summary>
        /// <param name="rootKey">The root key.</param>
        /// <param name="info">The info string for HKDF.</param>
        /// <returns>The derived header key.</returns>
        private static byte[] DeriveHeaderKey(byte[] rootKey, string info)
        {
            byte[] infoBytes = System.Text.Encoding.UTF8.GetBytes(info);
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, rootKey, KeySize, null, infoBytes);
        }

        /// <summary>
        /// Gets the current header key (for testing purposes only).
        /// </summary>
        internal byte[]? GetCurrentHeaderKey()
        {
            return _headerKey;
        }

        /// <summary>
        /// Gets the next header key (for testing purposes only).
        /// </summary>
        internal byte[]? GetNextHeaderKey()
        {
            return _nextHeaderKey;
        }

        /// <summary>
        /// Disposes the header encryption and securely clears keys.
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
                    if (_headerKey != null)
                    {
                        CryptographicOperations.ZeroMemory(_headerKey);
                        _headerKey = null;
                    }
                    if (_nextHeaderKey != null)
                    {
                        CryptographicOperations.ZeroMemory(_nextHeaderKey);
                        _nextHeaderKey = null;
                    }
                }
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Represents an encrypted header with its authentication data.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the EncryptedHeader class.
    /// </remarks>
    /// <param name="nonce">The nonce.</param>
    /// <param name="ciphertext">The ciphertext.</param>
    /// <param name="tag">The authentication tag.</param>
    public class EncryptedHeader(byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        /// <summary>
        /// Gets the nonce used for encryption.
        /// </summary>
        public byte[] Nonce { get; } = nonce ?? throw new ArgumentNullException(nameof(nonce));

        /// <summary>
        /// Gets the encrypted header ciphertext.
        /// </summary>
        public byte[] Ciphertext { get; } = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));

        /// <summary>
        /// Gets the authentication tag.
        /// </summary>
        public byte[] Tag { get; } = tag ?? throw new ArgumentNullException(nameof(tag));

        /// <summary>
        /// Serializes the encrypted header to a byte array.
        /// </summary>
        /// <returns>The serialized encrypted header.</returns>
        public byte[] Serialize()
        {
            // Format: [NonceLength:4][Nonce][CiphertextLength:4][Ciphertext][TagLength:4][Tag]
            byte[] result = new byte[4 + Nonce.Length + 4 + Ciphertext.Length + 4 + Tag.Length];
            int offset = 0;

            // Write nonce
            BitConverter.GetBytes(Nonce.Length).CopyTo(result, offset);
            offset += 4;
            Nonce.CopyTo(result, offset);
            offset += Nonce.Length;

            // Write ciphertext
            BitConverter.GetBytes(Ciphertext.Length).CopyTo(result, offset);
            offset += 4;
            Ciphertext.CopyTo(result, offset);
            offset += Ciphertext.Length;

            // Write tag
            BitConverter.GetBytes(Tag.Length).CopyTo(result, offset);
            offset += 4;
            Tag.CopyTo(result, offset);

            return result;
        }

        /// <summary>
        /// Deserializes an encrypted header from a byte array.
        /// </summary>
        /// <param name="data">The serialized data.</param>
        /// <returns>A CryptoResult containing the deserialized encrypted header.</returns>
        public static CryptoResult<EncryptedHeader> Deserialize(byte[] data)
        {
            if (data == null || data.Length < 12) // Minimum: 3 length fields
            {
                return CryptoResult<EncryptedHeader>.Failure("Invalid encrypted header data");
            }

            try
            {
                int offset = 0;

                // Read nonce
                int nonceLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                if (offset + nonceLength > data.Length)
                {
                    return CryptoResult<EncryptedHeader>.Failure("Invalid nonce length");
                }
                byte[] nonce = new byte[nonceLength];
                Array.Copy(data, offset, nonce, 0, nonceLength);
                offset += nonceLength;

                // Read ciphertext
                if (offset + 4 > data.Length)
                {
                    return CryptoResult<EncryptedHeader>.Failure("Invalid data format");
                }
                int ciphertextLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                if (offset + ciphertextLength > data.Length)
                {
                    return CryptoResult<EncryptedHeader>.Failure("Invalid ciphertext length");
                }
                byte[] ciphertext = new byte[ciphertextLength];
                Array.Copy(data, offset, ciphertext, 0, ciphertextLength);
                offset += ciphertextLength;

                // Read tag
                if (offset + 4 > data.Length)
                {
                    return CryptoResult<EncryptedHeader>.Failure("Invalid data format");
                }
                int tagLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                if (offset + tagLength > data.Length)
                {
                    return CryptoResult<EncryptedHeader>.Failure("Invalid tag length");
                }
                byte[] tag = new byte[tagLength];
                Array.Copy(data, offset, tag, 0, tagLength);

                return CryptoResult<EncryptedHeader>.Success(new EncryptedHeader(nonce, ciphertext, tag));
            }
            catch (Exception ex)
            {
                return CryptoResult<EncryptedHeader>.Failure($"Failed to deserialize encrypted header: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Represents a Double Ratchet message with an encrypted header.
    /// This provides metadata protection by hiding the ratchet public key and message numbers.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the EncryptedHeaderMessage class.
    /// </remarks>
    /// <param name="encryptedHeader">The encrypted header.</param>
    /// <param name="encryptedPayload">The encrypted payload.</param>
    /// <param name="payloadNonce">The payload nonce.</param>
    /// <param name="payloadTag">The payload tag.</param>
    public class EncryptedHeaderMessage(EncryptedHeader encryptedHeader, byte[] encryptedPayload, byte[] payloadNonce, byte[] payloadTag)
    {
        /// <summary>
        /// Gets or sets the encrypted header.
        /// </summary>
        public EncryptedHeader EncryptedHeader { get; set; } = encryptedHeader ?? throw new ArgumentNullException(nameof(encryptedHeader));

        /// <summary>
        /// Gets or sets the encrypted message payload.
        /// </summary>
        public byte[] EncryptedPayload { get; set; } = encryptedPayload ?? throw new ArgumentNullException(nameof(encryptedPayload));

        /// <summary>
        /// Gets or sets the payload nonce.
        /// </summary>
        public byte[] PayloadNonce { get; set; } = payloadNonce ?? throw new ArgumentNullException(nameof(payloadNonce));

        /// <summary>
        /// Gets or sets the payload authentication tag.
        /// </summary>
        public byte[] PayloadTag { get; set; } = payloadTag ?? throw new ArgumentNullException(nameof(payloadTag));

        /// <summary>
        /// Serializes the message to a byte array.
        /// </summary>
        /// <returns>The serialized message.</returns>
        public byte[] Serialize()
        {
            byte[] headerData = EncryptedHeader.Serialize();

            // Format: [HeaderDataLength:4][HeaderData][PayloadNonceLength:4][PayloadNonce][PayloadLength:4][Payload][TagLength:4][Tag]
            byte[] result = new byte[4 + headerData.Length + 4 + PayloadNonce.Length + 4 + EncryptedPayload.Length + 4 + PayloadTag.Length];
            int offset = 0;

            // Write header data
            BitConverter.GetBytes(headerData.Length).CopyTo(result, offset);
            offset += 4;
            headerData.CopyTo(result, offset);
            offset += headerData.Length;

            // Write payload nonce
            BitConverter.GetBytes(PayloadNonce.Length).CopyTo(result, offset);
            offset += 4;
            PayloadNonce.CopyTo(result, offset);
            offset += PayloadNonce.Length;

            // Write payload
            BitConverter.GetBytes(EncryptedPayload.Length).CopyTo(result, offset);
            offset += 4;
            EncryptedPayload.CopyTo(result, offset);
            offset += EncryptedPayload.Length;

            // Write tag
            BitConverter.GetBytes(PayloadTag.Length).CopyTo(result, offset);
            offset += 4;
            PayloadTag.CopyTo(result, offset);

            return result;
        }

        /// <summary>
        /// Deserializes a message from a byte array.
        /// </summary>
        /// <param name="data">The serialized data.</param>
        /// <returns>A CryptoResult containing the deserialized message.</returns>
        public static CryptoResult<EncryptedHeaderMessage> Deserialize(byte[] data)
        {
            if (data == null || data.Length < 16) // Minimum size
            {
                return CryptoResult<EncryptedHeaderMessage>.Failure("Invalid message data");
            }

            try
            {
                int offset = 0;

                // Read header data
                int headerLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                if (offset + headerLength > data.Length)
                {
                    return CryptoResult<EncryptedHeaderMessage>.Failure("Invalid header length");
                }
                byte[] headerData = new byte[headerLength];
                Array.Copy(data, offset, headerData, 0, headerLength);
                offset += headerLength;

                CryptoResult<EncryptedHeader> headerResult = EncryptedHeader.Deserialize(headerData);
                if (!headerResult.IsSuccess)
                {
                    return CryptoResult<EncryptedHeaderMessage>.Failure($"Failed to deserialize header: {headerResult.Error}");
                }

                // Read payload nonce
                if (offset + 4 > data.Length)
                {
                    return CryptoResult<EncryptedHeaderMessage>.Failure("Invalid data format");
                }
                int nonceLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                if (offset + nonceLength > data.Length)
                {
                    return CryptoResult<EncryptedHeaderMessage>.Failure("Invalid nonce length");
                }
                byte[] payloadNonce = new byte[nonceLength];
                Array.Copy(data, offset, payloadNonce, 0, nonceLength);
                offset += nonceLength;

                // Read payload
                if (offset + 4 > data.Length)
                {
                    return CryptoResult<EncryptedHeaderMessage>.Failure("Invalid data format");
                }
                int payloadLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                if (offset + payloadLength > data.Length)
                {
                    return CryptoResult<EncryptedHeaderMessage>.Failure("Invalid payload length");
                }
                byte[] payload = new byte[payloadLength];
                Array.Copy(data, offset, payload, 0, payloadLength);
                offset += payloadLength;

                // Read tag
                if (offset + 4 > data.Length)
                {
                    return CryptoResult<EncryptedHeaderMessage>.Failure("Invalid data format");
                }
                int tagLength = BitConverter.ToInt32(data, offset);
                offset += 4;
                if (offset + tagLength > data.Length)
                {
                    return CryptoResult<EncryptedHeaderMessage>.Failure("Invalid tag length");
                }
                byte[] tag = new byte[tagLength];
                Array.Copy(data, offset, tag, 0, tagLength);

                return CryptoResult<EncryptedHeaderMessage>.Success(
                    new EncryptedHeaderMessage(headerResult.Value!, payload, payloadNonce, tag));
            }
            catch (Exception ex)
            {
                return CryptoResult<EncryptedHeaderMessage>.Failure($"Failed to deserialize message: {ex.Message}");
            }
        }
    }
}
#endif
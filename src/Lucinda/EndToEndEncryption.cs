// <copyright file="EndToEndEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
using System.Text;

using Lucinda.Abstractions;
using Lucinda.Asymmetric;
using Lucinda.KeyDerivation;
#if NET6_0_OR_GREATER
using Lucinda.KeyExchange;
#endif
using Lucinda.Signatures;
using Lucinda.Symmetric;
using Lucinda.Utilities;

namespace Lucinda
{
    /// <summary>
    /// Provides high-level end-to-end encryption operations combining multiple cryptographic primitives.
    /// This class serves as the main entry point for E2EE functionality.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <see cref="EndToEndEncryption"/> class provides:
    /// <list type="bullet">
    /// <item><description>Simplified API for common E2EE scenarios</description></item>
    /// <item><description>Secure defaults for all cryptographic operations</description></item>
    /// <item><description>Key management integration</description></item>
    /// <item><description>Message signing and verification</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// For advanced customization, use the individual cryptographic classes directly.
    /// </para>
    /// <para>
    /// Note: This class is only available on .NET Core 3.0+ and .NET 5.0+.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Generate key pairs for Alice and Bob
    /// using var e2ee = new EndToEndEncryption();
    /// var aliceKeyPair = e2ee.GenerateKeyPair();
    /// var bobKeyPair = e2ee.GenerateKeyPair();
    /// 
    /// // Alice encrypts a message for Bob
    /// var encrypted = e2ee.EncryptMessage("Hello, Bob!", bobKeyPair.Value.PublicKey);
    /// 
    /// // Bob decrypts the message
    /// var decrypted = e2ee.DecryptMessage(encrypted.Value, bobKeyPair.Value.PrivateKey);
    /// </code>
    /// </example>
    public sealed class EndToEndEncryption : IDisposable
    {
        private readonly RsaAesHybridEncryption _hybridEncryption;
        private readonly EcdsaSignature? _signature;
        private readonly HkdfKeyDerivation _hkdf;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="EndToEndEncryption"/> class with default settings.
        /// </summary>
        public EndToEndEncryption()
            : this(new EndToEndEncryptionOptions())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EndToEndEncryption"/> class with the specified options.
        /// </summary>
        /// <param name="options">The configuration options for E2EE operations.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
        public EndToEndEncryption(EndToEndEncryptionOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _hybridEncryption = new RsaAesHybridEncryption(
                options.RsaKeySizeInBits,
                options.AesKeySizeInBits);

            if (options.EnableSignatures)
            {
                _signature = new EcdsaSignature(options.SignatureCurve);
            }

            _hkdf = new HkdfKeyDerivation(options.HashAlgorithm);
        }

        /// <summary>
        /// Generates a new key pair for encryption and decryption.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the generated key pair on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<AsymmetricKeyPair> GenerateKeyPair()
        {
            ThrowIfDisposed();
            return _hybridEncryption.GenerateKeyPair();
        }

        /// <summary>
        /// Generates a new key pair for digital signatures.
        /// </summary>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the generated key pair on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<AsymmetricKeyPair> GenerateSigningKeyPair()
        {
            ThrowIfDisposed();

            if (_signature == null)
            {
                return CryptoResult<AsymmetricKeyPair>.Failure("Signatures are not enabled.");
            }

            return _signature.GenerateKeyPair();
        }

        /// <summary>
        /// Encrypts a string message for a recipient.
        /// </summary>
        /// <param name="message">The plaintext message to encrypt.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the encrypted data on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<byte[]> EncryptMessage(string message, byte[] recipientPublicKey)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(message))
            {
                return CryptoResult<byte[]>.Failure("Message cannot be null or empty.");
            }

            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            return EncryptData(messageBytes, recipientPublicKey);
        }

        /// <summary>
        /// Encrypts binary data for a recipient.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the encrypted data on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<byte[]> EncryptData(byte[] data, byte[] recipientPublicKey)
        {
            ThrowIfDisposed();

            if (data == null)
            {
                return CryptoResult<byte[]>.Failure("Data cannot be null.");
            }

            if (recipientPublicKey == null)
            {
                return CryptoResult<byte[]>.Failure("Recipient public key cannot be null.");
            }

            CryptoResult<HybridEncryptedData> encryptResult = _hybridEncryption.Encrypt(data, recipientPublicKey);
            if (encryptResult.IsFailure)
            {
                return CryptoResult<byte[]>.Failure(encryptResult.Error);
            }

            return CryptoResult<byte[]>.Success(encryptResult.Value.ToBytes());
        }

        /// <summary>
        /// Encrypts data with additional authenticated data.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <param name="associatedData">Additional data to authenticate but not encrypt.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the encrypted data on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<byte[]> EncryptData(byte[] data, byte[] recipientPublicKey, byte[] associatedData)
        {
            ThrowIfDisposed();

            if (data == null)
            {
                return CryptoResult<byte[]>.Failure("Data cannot be null.");
            }

            if (recipientPublicKey == null)
            {
                return CryptoResult<byte[]>.Failure("Recipient public key cannot be null.");
            }

            CryptoResult<HybridEncryptedData> encryptResult = _hybridEncryption.Encrypt(data, recipientPublicKey, associatedData);
            if (encryptResult.IsFailure)
            {
                return CryptoResult<byte[]>.Failure(encryptResult.Error);
            }

            return CryptoResult<byte[]>.Success(encryptResult.Value.ToBytes());
        }

        /// <summary>
        /// Decrypts a message using the recipient's private key.
        /// </summary>
        /// <param name="encryptedData">The encrypted data.</param>
        /// <param name="recipientPrivateKey">The recipient's private key.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted message string on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<string> DecryptMessage(byte[] encryptedData, byte[] recipientPrivateKey)
        {
            ThrowIfDisposed();

            CryptoResult<byte[]> decryptResult = DecryptData(encryptedData, recipientPrivateKey);
            if (decryptResult.IsFailure)
            {
                return CryptoResult<string>.Failure(decryptResult.Error);
            }

            try
            {
                string message = Encoding.UTF8.GetString(decryptResult.Value);
                return CryptoResult<string>.Success(message);
            }
            catch (Exception ex)
            {
                return CryptoResult<string>.Failure($"Failed to decode message: {ex.Message}");
            }
        }

        /// <summary>
        /// Decrypts binary data using the recipient's private key.
        /// </summary>
        /// <param name="encryptedData">The encrypted data.</param>
        /// <param name="recipientPrivateKey">The recipient's private key.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted data on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<byte[]> DecryptData(byte[] encryptedData, byte[] recipientPrivateKey)
        {
            ThrowIfDisposed();

            if (encryptedData == null)
            {
                return CryptoResult<byte[]>.Failure("Encrypted data cannot be null.");
            }

            if (recipientPrivateKey == null)
            {
                return CryptoResult<byte[]>.Failure("Recipient private key cannot be null.");
            }

            CryptoResult<HybridEncryptedData> parseResult = HybridEncryptedData.FromBytes(encryptedData);
            if (parseResult.IsFailure)
            {
                return CryptoResult<byte[]>.Failure(parseResult.Error);
            }

            return _hybridEncryption.Decrypt(parseResult.Value, recipientPrivateKey);
        }

        /// <summary>
        /// Decrypts data with additional authenticated data verification.
        /// </summary>
        /// <param name="encryptedData">The encrypted data.</param>
        /// <param name="recipientPrivateKey">The recipient's private key.</param>
        /// <param name="associatedData">Additional data to verify.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted data on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<byte[]> DecryptData(byte[] encryptedData, byte[] recipientPrivateKey, byte[] associatedData)
        {
            ThrowIfDisposed();

            if (encryptedData == null)
            {
                return CryptoResult<byte[]>.Failure("Encrypted data cannot be null.");
            }

            if (recipientPrivateKey == null)
            {
                return CryptoResult<byte[]>.Failure("Recipient private key cannot be null.");
            }

            CryptoResult<HybridEncryptedData> parseResult = HybridEncryptedData.FromBytes(encryptedData);
            if (parseResult.IsFailure)
            {
                return CryptoResult<byte[]>.Failure(parseResult.Error);
            }

            return _hybridEncryption.Decrypt(parseResult.Value, recipientPrivateKey, associatedData);
        }

        /// <summary>
        /// Signs data using a private key.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="signingPrivateKey">The private key to use for signing.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the signature on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<byte[]> SignData(byte[] data, byte[] signingPrivateKey)
        {
            ThrowIfDisposed();

            if (_signature == null)
            {
                return CryptoResult<byte[]>.Failure("Signatures are not enabled.");
            }

            if (data == null)
            {
                return CryptoResult<byte[]>.Failure("Data cannot be null.");
            }

            if (signingPrivateKey == null)
            {
                return CryptoResult<byte[]>.Failure("Signing private key cannot be null.");
            }

            try
            {
                using EcdsaSignature signer = new();
                CryptoResult<bool> importResult = signer.ImportPrivateKey(signingPrivateKey, KeyFormat.Pkcs8);
                if (importResult.IsFailure)
                {
                    return CryptoResult<byte[]>.Failure(importResult.Error);
                }

                return signer.Sign(data);
            }
            catch (Exception ex)
            {
                return CryptoResult<byte[]>.Failure($"Signing failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Verifies a signature using a public key.
        /// </summary>
        /// <param name="data">The original data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="signingPublicKey">The public key to use for verification.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing <c>true</c> if valid, <c>false</c> if invalid,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<bool> VerifySignature(byte[] data, byte[] signature, byte[] signingPublicKey)
        {
            ThrowIfDisposed();

            if (_signature == null)
            {
                return CryptoResult<bool>.Failure("Signatures are not enabled.");
            }

            if (data == null)
            {
                return CryptoResult<bool>.Failure("Data cannot be null.");
            }

            if (signature == null)
            {
                return CryptoResult<bool>.Failure("Signature cannot be null.");
            }

            if (signingPublicKey == null)
            {
                return CryptoResult<bool>.Failure("Signing public key cannot be null.");
            }

            try
            {
                using EcdsaSignature verifier = new();
                CryptoResult<bool> importResult = verifier.ImportPublicKey(signingPublicKey, KeyFormat.SubjectPublicKeyInfo);
                if (importResult.IsFailure)
                {
                    return CryptoResult<bool>.Failure(importResult.Error);
                }

                return verifier.Verify(data, signature);
            }
            catch (Exception ex)
            {
                return CryptoResult<bool>.Failure($"Verification failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Encrypts data and signs it in a single operation.
        /// </summary>
        /// <param name="data">The data to encrypt and sign.</param>
        /// <param name="recipientPublicKey">The recipient's public key for encryption.</param>
        /// <param name="senderPrivateKey">The sender's private key for signing.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing a <see cref="SignedEncryptedData"/> on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<SignedEncryptedData> EncryptAndSign(
            byte[] data,
            byte[] recipientPublicKey,
            byte[] senderPrivateKey)
        {
            ThrowIfDisposed();

            if (_signature == null)
            {
                return CryptoResult<SignedEncryptedData>.Failure("Signatures are not enabled.");
            }

            // First encrypt the data
            CryptoResult<byte[]> encryptResult = EncryptData(data, recipientPublicKey);
            if (encryptResult.IsFailure)
            {
                return CryptoResult<SignedEncryptedData>.Failure(encryptResult.Error);
            }

            // Then sign the encrypted data
            CryptoResult<byte[]> signResult = SignData(encryptResult.Value, senderPrivateKey);
            if (signResult.IsFailure)
            {
                return CryptoResult<SignedEncryptedData>.Failure(signResult.Error);
            }

            return CryptoResult<SignedEncryptedData>.Success(new SignedEncryptedData
            {
                EncryptedData = encryptResult.Value,
                Signature = signResult.Value
            });
        }

        /// <summary>
        /// Verifies a signature and decrypts data in a single operation.
        /// </summary>
        /// <param name="signedData">The signed and encrypted data.</param>
        /// <param name="recipientPrivateKey">The recipient's private key for decryption.</param>
        /// <param name="senderPublicKey">The sender's public key for signature verification.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the decrypted data on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<byte[]> VerifyAndDecrypt(
            SignedEncryptedData signedData,
            byte[] recipientPrivateKey,
            byte[] senderPublicKey)
        {
            ThrowIfDisposed();

            if (_signature == null)
            {
                return CryptoResult<byte[]>.Failure("Signatures are not enabled.");
            }

            if (signedData == null)
            {
                return CryptoResult<byte[]>.Failure("Signed data cannot be null.");
            }

            // First verify the signature
            CryptoResult<bool> verifyResult = VerifySignature(signedData.EncryptedData, signedData.Signature, senderPublicKey);
            if (verifyResult.IsFailure)
            {
                return CryptoResult<byte[]>.Failure(verifyResult.Error);
            }

            if (!verifyResult.Value)
            {
                return CryptoResult<byte[]>.Failure("Signature verification failed.");
            }

            // Then decrypt the data
            return DecryptData(signedData.EncryptedData, recipientPrivateKey);
        }

        /// <summary>
        /// Derives a shared key from a password using PBKDF2.
        /// </summary>
        /// <param name="password">The password to derive the key from.</param>
        /// <param name="salt">The salt to use. If null, a new salt will be generated.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the derived key and salt on success,
        /// or an error message on failure.
        /// </returns>
        public CryptoResult<(byte[] Key, byte[] Salt)> DeriveKeyFromPassword(string password, byte[]? salt = null)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(password))
            {
                return CryptoResult<(byte[], byte[])>.Failure("Password cannot be null or empty.");
            }

            using Pbkdf2KeyDerivation pbkdf2 = new();
            return pbkdf2.DeriveKeyWithDefaults(password, salt);
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _hybridEncryption.Dispose();
            _signature?.Dispose();
            _hkdf.Dispose();
            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(EndToEndEncryption));
            }
        }
    }
}
#endif
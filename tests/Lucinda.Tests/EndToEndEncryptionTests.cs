// <copyright file="EndToEndEncryptionTests.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using FluentAssertions;
using Lucinda.Abstractions;
using Xunit;

namespace Lucinda.Tests
{
    public class EndToEndEncryptionTests
    {
        [Fact]
        public void GenerateKeyPair_ShouldReturnValidKeyPair()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();

            // Act
            CryptoResult<AsymmetricKeyPair> result = e2ee.GenerateKeyPair();

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.PublicKey.Should().NotBeEmpty();
            result.Value.PrivateKey.Should().NotBeEmpty();
        }

        [Fact]
        public void EncryptMessage_AndDecryptMessage_ShouldReturnOriginalMessage()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();
            CryptoResult<AsymmetricKeyPair> keyPair = e2ee.GenerateKeyPair();
            string originalMessage = "Hello, this is a secret message!";

            // Act
            CryptoResult<byte[]> encryptResult = e2ee.EncryptMessage(originalMessage, keyPair.Value.PublicKey);
            CryptoResult<string> decryptResult = e2ee.DecryptMessage(encryptResult.Value, keyPair.Value.PrivateKey);

            // Assert
            encryptResult.IsSuccess.Should().BeTrue();
            decryptResult.IsSuccess.Should().BeTrue();
            decryptResult.Value.Should().Be(originalMessage);
        }

        [Fact]
        public void EncryptData_AndDecryptData_ShouldReturnOriginalData()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();
            CryptoResult<AsymmetricKeyPair> keyPair = e2ee.GenerateKeyPair();
            byte[] originalData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

            // Act
            CryptoResult<byte[]> encryptResult = e2ee.EncryptData(originalData, keyPair.Value.PublicKey);
            CryptoResult<byte[]> decryptResult = e2ee.DecryptData(encryptResult.Value, keyPair.Value.PrivateKey);

            // Assert
            encryptResult.IsSuccess.Should().BeTrue();
            decryptResult.IsSuccess.Should().BeTrue();
            decryptResult.Value.Should().BeEquivalentTo(originalData);
        }

        [Fact]
        public void EncryptData_WithAssociatedData_ShouldDecryptSuccessfully()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();
            CryptoResult<AsymmetricKeyPair> keyPair = e2ee.GenerateKeyPair();
            byte[] originalData = "Secret data"u8.ToArray();
            byte[] associatedData = "Additional authenticated data"u8.ToArray();

            // Act
            CryptoResult<byte[]> encryptResult = e2ee.EncryptData(originalData, keyPair.Value.PublicKey, associatedData);
            CryptoResult<byte[]> decryptResult = e2ee.DecryptData(encryptResult.Value, keyPair.Value.PrivateKey, associatedData);

            // Assert
            encryptResult.IsSuccess.Should().BeTrue();
            decryptResult.IsSuccess.Should().BeTrue();
            decryptResult.Value.Should().BeEquivalentTo(originalData);
        }

        [Fact]
        public void Encrypt_WithAliceAndBob_ShouldAllowBobToDecrypt()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();

            // Generate key pairs for Alice and Bob
            CryptoResult<AsymmetricKeyPair> aliceKeyPair = e2ee.GenerateKeyPair();
            CryptoResult<AsymmetricKeyPair> bobKeyPair = e2ee.GenerateKeyPair();

            string secretMessage = "Hello Bob, this is Alice!";

            // Act - Alice encrypts for Bob
            CryptoResult<byte[]> encryptResult = e2ee.EncryptMessage(secretMessage, bobKeyPair.Value.PublicKey);

            // Bob decrypts
            CryptoResult<string> decryptResult = e2ee.DecryptMessage(encryptResult.Value, bobKeyPair.Value.PrivateKey);

            // Assert
            decryptResult.IsSuccess.Should().BeTrue();
            decryptResult.Value.Should().Be(secretMessage);
        }

        [Fact]
        public void Encrypt_WithWrongPrivateKey_ShouldFail()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();
            CryptoResult<AsymmetricKeyPair> aliceKeyPair = e2ee.GenerateKeyPair();
            CryptoResult<AsymmetricKeyPair> bobKeyPair = e2ee.GenerateKeyPair();
            string message = "Secret message";

            // Act - Encrypt for Alice
            CryptoResult<byte[]> encryptResult = e2ee.EncryptMessage(message, aliceKeyPair.Value.PublicKey);

            // Try to decrypt with Bob's key (should fail)
            CryptoResult<string> decryptResult = e2ee.DecryptMessage(encryptResult.Value, bobKeyPair.Value.PrivateKey);

            // Assert
            decryptResult.IsFailure.Should().BeTrue();
        }

        [Fact]
        public void SignData_AndVerifySignature_ShouldSucceed()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();
            CryptoResult<AsymmetricKeyPair> signingKeyPair = e2ee.GenerateSigningKeyPair();
            byte[] data = "Data to be signed"u8.ToArray();

            // Act
            CryptoResult<byte[]> signResult = e2ee.SignData(data, signingKeyPair.Value.PrivateKey);
            CryptoResult<bool> verifyResult = e2ee.VerifySignature(data, signResult.Value, signingKeyPair.Value.PublicKey);

            // Assert
            signResult.IsSuccess.Should().BeTrue();
            verifyResult.IsSuccess.Should().BeTrue();
            verifyResult.Value.Should().BeTrue();
        }

        [Fact]
        public void VerifySignature_WithTamperedData_ShouldReturnFalse()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();
            CryptoResult<AsymmetricKeyPair> signingKeyPair = e2ee.GenerateSigningKeyPair();
            byte[] originalData = "Original data"u8.ToArray();
            byte[] tamperedData = "Tampered data"u8.ToArray();

            // Act
            CryptoResult<byte[]> signResult = e2ee.SignData(originalData, signingKeyPair.Value.PrivateKey);
            CryptoResult<bool> verifyResult = e2ee.VerifySignature(tamperedData, signResult.Value, signingKeyPair.Value.PublicKey);

            // Assert
            verifyResult.IsSuccess.Should().BeTrue();
            verifyResult.Value.Should().BeFalse(); // Signature should not verify for tampered data
        }

        [Fact]
        public void EncryptAndSign_ThenVerifyAndDecrypt_ShouldSucceed()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();
            CryptoResult<AsymmetricKeyPair> senderEncryptionKeyPair = e2ee.GenerateKeyPair();
            CryptoResult<AsymmetricKeyPair> senderSigningKeyPair = e2ee.GenerateSigningKeyPair();
            CryptoResult<AsymmetricKeyPair> recipientKeyPair = e2ee.GenerateKeyPair();
            byte[] originalData = "Authenticated encrypted message"u8.ToArray();

            // Act
            CryptoResult<SignedEncryptedData> encryptAndSignResult = e2ee.EncryptAndSign(
                originalData,
                recipientKeyPair.Value.PublicKey,
                senderSigningKeyPair.Value.PrivateKey);

            CryptoResult<byte[]> verifyAndDecryptResult = e2ee.VerifyAndDecrypt(
                encryptAndSignResult.Value,
                recipientKeyPair.Value.PrivateKey,
                senderSigningKeyPair.Value.PublicKey);

            // Assert
            encryptAndSignResult.IsSuccess.Should().BeTrue();
            verifyAndDecryptResult.IsSuccess.Should().BeTrue();
            verifyAndDecryptResult.Value.Should().BeEquivalentTo(originalData);
        }

        [Fact]
        public void DeriveKeyFromPassword_ShouldReturnConsistentKey()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();
            string password = "MySecurePassword123!";
            byte[] salt = new byte[32];
            new Random(42).NextBytes(salt);

            // Act
            CryptoResult<(byte[] Key, byte[] Salt)> result1 = e2ee.DeriveKeyFromPassword(password, salt);
            CryptoResult<(byte[] Key, byte[] Salt)> result2 = e2ee.DeriveKeyFromPassword(password, salt);

            // Assert
            result1.IsSuccess.Should().BeTrue();
            result2.IsSuccess.Should().BeTrue();
            result1.Value.Key.Should().BeEquivalentTo(result2.Value.Key);
        }

        [Fact]
        public void DeriveKeyFromPassword_WithDifferentSalts_ShouldReturnDifferentKeys()
        {
            // Arrange
            using EndToEndEncryption e2ee = new();
            string password = "MySecurePassword123!";
            byte[] salt1 = new byte[32];
            byte[] salt2 = new byte[32];
            new Random(42).NextBytes(salt1);
            new Random(123).NextBytes(salt2);

            // Act
            CryptoResult<(byte[] Key, byte[] Salt)> result1 = e2ee.DeriveKeyFromPassword(password, salt1);
            CryptoResult<(byte[] Key, byte[] Salt)> result2 = e2ee.DeriveKeyFromPassword(password, salt2);

            // Assert
            result1.IsSuccess.Should().BeTrue();
            result2.IsSuccess.Should().BeTrue();
            result1.Value.Key.Should().NotBeEquivalentTo(result2.Value.Key);
        }
    }
}
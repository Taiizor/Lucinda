// <copyright file="AesGcmEncryptionTests.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using FluentAssertions;
using Lucinda.Abstractions;
using Lucinda.Symmetric;
using Xunit;

namespace Lucinda.Tests.Symmetric
{
    public class AesGcmEncryptionTests
    {
        [Fact]
        public void Encrypt_WithValidPlaintext_ShouldReturnSuccessResult()
        {
            // Arrange
            using AesGcmEncryption aes = new();
            byte[] plaintext = "Hello, World!"u8.ToArray();

            // Act
            CryptoResult<byte[]> result = aes.Encrypt(plaintext);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeEmpty();
            result.Value.Length.Should().BeGreaterThan(plaintext.Length);
        }

        [Fact]
        public void Decrypt_WithValidCiphertext_ShouldReturnOriginalPlaintext()
        {
            // Arrange
            using AesGcmEncryption aes = new();
            byte[] plaintext = "Hello, World!"u8.ToArray();

            // Act
            CryptoResult<byte[]> encryptResult = aes.Encrypt(plaintext);
            CryptoResult<byte[]> decryptResult = aes.Decrypt(encryptResult.Value);

            // Assert
            decryptResult.IsSuccess.Should().BeTrue();
            decryptResult.Value.Should().BeEquivalentTo(plaintext);
        }

        [Fact]
        public void Encrypt_WithAssociatedData_ShouldDecryptSuccessfully()
        {
            // Arrange
            using AesGcmEncryption aes = new();
            byte[] plaintext = "Sensitive data"u8.ToArray();
            byte[] associatedData = "metadata"u8.ToArray();

            // Act
            CryptoResult<byte[]> encryptResult = aes.Encrypt(plaintext, associatedData);
            CryptoResult<byte[]> decryptResult = aes.Decrypt(encryptResult.Value, associatedData);

            // Assert
            decryptResult.IsSuccess.Should().BeTrue();
            decryptResult.Value.Should().BeEquivalentTo(plaintext);
        }

        [Fact]
        public void Decrypt_WithWrongAssociatedData_ShouldFail()
        {
            // Arrange
            using AesGcmEncryption aes = new();
            byte[] plaintext = "Sensitive data"u8.ToArray();
            byte[] associatedData = "metadata"u8.ToArray();
            byte[] wrongAssociatedData = "wrong"u8.ToArray();

            // Act
            CryptoResult<byte[]> encryptResult = aes.Encrypt(plaintext, associatedData);
            CryptoResult<byte[]> decryptResult = aes.Decrypt(encryptResult.Value, wrongAssociatedData);

            // Assert
            decryptResult.IsFailure.Should().BeTrue();
        }

        [Fact]
        public void GenerateKey_ShouldReturnCorrectSizedKey()
        {
            // Arrange
            using AesGcmEncryption aes = new(256);

            // Act
            CryptoResult<byte[]> result = aes.GenerateKey();

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Length.Should().Be(32); // 256 bits = 32 bytes
        }

        [Fact]
        public void GenerateIV_ShouldReturnCorrectSizedNonce()
        {
            // Arrange
            using AesGcmEncryption aes = new();

            // Act
            CryptoResult<byte[]> result = aes.GenerateIV();

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Length.Should().Be(12); // GCM nonce size
        }

        [Theory]
        [InlineData(128)]
        [InlineData(192)]
        [InlineData(256)]
        public void Constructor_WithValidKeySize_ShouldSucceed(int keySize)
        {
            // Act
            using AesGcmEncryption aes = new(keySize);

            // Assert
            aes.KeySizeInBits.Should().Be(keySize);
            aes.AlgorithmName.Should().Contain($"AES-GCM-{keySize}");
        }

        [Fact]
        public void Constructor_WithCustomKey_ShouldUseProvidedKey()
        {
            // Arrange
            byte[] key = new byte[32]; // 256-bit key
            new Random(42).NextBytes(key);

            // Act
            using AesGcmEncryption aes1 = new(key);
            using AesGcmEncryption aes2 = new(key);
            byte[] plaintext = "Test message"u8.ToArray();

            CryptoResult<byte[]> encrypted = aes1.Encrypt(plaintext);
            CryptoResult<byte[]> decrypted = aes2.Decrypt(encrypted.Value);

            // Assert
            decrypted.IsSuccess.Should().BeTrue();
            decrypted.Value.Should().BeEquivalentTo(plaintext);
        }

        [Fact]
        public void Encrypt_WithNullPlaintext_ShouldReturnFailure()
        {
            // Arrange
            using AesGcmEncryption aes = new();

            // Act
            CryptoResult<byte[]> result = aes.Encrypt(null!);

            // Assert
            result.IsFailure.Should().BeTrue();
            result.Error.Should().Contain("null");
        }

        [Fact]
        public void Decrypt_WithTamperedCiphertext_ShouldFail()
        {
            // Arrange
            using AesGcmEncryption aes = new();
            byte[] plaintext = "Original message"u8.ToArray();

            // Act
            CryptoResult<byte[]> encryptResult = aes.Encrypt(plaintext);
            byte[] ciphertext = encryptResult.Value;
            ciphertext[^1] ^= 0xFF; // Tamper with the ciphertext

            CryptoResult<byte[]> decryptResult = aes.Decrypt(ciphertext);

            // Assert
            decryptResult.IsFailure.Should().BeTrue();
        }
    }
}
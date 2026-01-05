// <copyright file="HeaderEncryptionTests.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
using FluentAssertions;
using Lucinda.Abstractions;
using Lucinda.Protocol.DoubleRatchet;
using System.Security.Cryptography;
using Xunit;

namespace Lucinda.Tests
{
    /// <summary>
    /// Unit tests for HeaderEncryption.
    /// </summary>
    public class HeaderEncryptionTests
    {
        [Fact]
        public void Initialize_WithValidRootKey_ShouldSucceed()
        {
            // Arrange
            byte[] rootKey = RandomNumberGenerator.GetBytes(32);

            // Act
            CryptoResult<HeaderEncryption> result = HeaderEncryption.Initialize(rootKey);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNull();

            result.Value!.Dispose();
        }

        [Fact]
        public void Initialize_WithNullKey_ShouldFail()
        {
            // Act
            CryptoResult<HeaderEncryption> result = HeaderEncryption.Initialize(null!);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Error.Should().Contain("null or empty");
        }

        [Fact]
        public void Initialize_WithEmptyKey_ShouldFail()
        {
            // Act
            CryptoResult<HeaderEncryption> result = HeaderEncryption.Initialize([]);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Error.Should().Contain("null or empty");
        }

        [Fact]
        public void EncryptDecryptHeader_ShouldRoundTrip()
        {
            // Arrange
            byte[] rootKey = RandomNumberGenerator.GetBytes(32);
            using HeaderEncryption headerEncryption = HeaderEncryption.Initialize(rootKey).Value!;

            using ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            // RatchetHeader constructor: (dhPublicKey, previousChainLength, messageNumber)
            RatchetHeader header = new(ecdh.PublicKey.ExportSubjectPublicKeyInfo(), 10, 5);

            // Act
            CryptoResult<EncryptedHeader> encryptResult = headerEncryption.EncryptHeader(header);
            encryptResult.IsSuccess.Should().BeTrue();

            CryptoResult<RatchetHeader> decryptResult = headerEncryption.DecryptHeader(encryptResult.Value!);

            // Assert
            decryptResult.IsSuccess.Should().BeTrue();
            decryptResult.Value!.MessageNumber.Should().Be(5);
            decryptResult.Value.PreviousChainLength.Should().Be(10);
        }

        [Fact]
        public void EncryptHeader_WithNullHeader_ShouldFail()
        {
            // Arrange
            byte[] rootKey = RandomNumberGenerator.GetBytes(32);
            using HeaderEncryption headerEncryption = HeaderEncryption.Initialize(rootKey).Value!;

            // Act
            CryptoResult<EncryptedHeader> result = headerEncryption.EncryptHeader(null!);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Error.Should().Contain("null");
        }

        [Fact]
        public void RatchetHeaderKeys_ShouldUpdateKeys()
        {
            // Arrange
            byte[] rootKey = RandomNumberGenerator.GetBytes(32);
            using HeaderEncryption headerEncryption = HeaderEncryption.Initialize(rootKey).Value!;

            byte[] originalHeaderKey = [.. headerEncryption.GetCurrentHeaderKey()!];
            byte[] newRootKey = RandomNumberGenerator.GetBytes(32);

            // Act
            CryptoResult<bool> result = headerEncryption.RatchetHeaderKeys(newRootKey);

            // Assert
            result.IsSuccess.Should().BeTrue();
            headerEncryption.GetCurrentHeaderKey().Should().NotBeNull();
            headerEncryption.GetCurrentHeaderKey()!.SequenceEqual(originalHeaderKey).Should().BeFalse();
        }

        [Fact]
        public void EncryptedHeader_Serialize_ShouldRoundTrip()
        {
            // Arrange
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = RandomNumberGenerator.GetBytes(64);
            byte[] tag = RandomNumberGenerator.GetBytes(16);
            EncryptedHeader encryptedHeader = new(nonce, ciphertext, tag);

            // Act
            byte[] serialized = encryptedHeader.Serialize();
            CryptoResult<EncryptedHeader> deserializeResult = EncryptedHeader.Deserialize(serialized);

            // Assert
            deserializeResult.IsSuccess.Should().BeTrue();
            deserializeResult.Value!.Nonce.Should().BeEquivalentTo(nonce);
            deserializeResult.Value.Ciphertext.Should().BeEquivalentTo(ciphertext);
            deserializeResult.Value.Tag.Should().BeEquivalentTo(tag);
        }

        [Fact]
        public void EncryptedHeaderMessage_Serialize_ShouldRoundTrip()
        {
            // Arrange
            EncryptedHeader encryptedHeader = new(
                RandomNumberGenerator.GetBytes(12),
                RandomNumberGenerator.GetBytes(64),
                RandomNumberGenerator.GetBytes(16));

            EncryptedHeaderMessage message = new(
                encryptedHeader,
                RandomNumberGenerator.GetBytes(128),
                RandomNumberGenerator.GetBytes(12),
                RandomNumberGenerator.GetBytes(16));

            // Act
            byte[] serialized = message.Serialize();
            CryptoResult<EncryptedHeaderMessage> deserializeResult = EncryptedHeaderMessage.Deserialize(serialized);

            // Assert
            deserializeResult.IsSuccess.Should().BeTrue();
            deserializeResult.Value!.EncryptedPayload.Should().BeEquivalentTo(message.EncryptedPayload);
            deserializeResult.Value.PayloadNonce.Should().BeEquivalentTo(message.PayloadNonce);
            deserializeResult.Value.PayloadTag.Should().BeEquivalentTo(message.PayloadTag);
        }

        [Fact]
        public void DecryptHeader_WithWrongKey_ShouldFail()
        {
            // Arrange
            byte[] rootKey1 = RandomNumberGenerator.GetBytes(32);
            byte[] rootKey2 = RandomNumberGenerator.GetBytes(32);
            using HeaderEncryption headerEncryption1 = HeaderEncryption.Initialize(rootKey1).Value!;
            using HeaderEncryption headerEncryption2 = HeaderEncryption.Initialize(rootKey2).Value!;

            using ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            RatchetHeader header = new(ecdh.PublicKey.ExportSubjectPublicKeyInfo(), 5, 10);

            // Act
            CryptoResult<EncryptedHeader> encryptResult = headerEncryption1.EncryptHeader(header);
            encryptResult.IsSuccess.Should().BeTrue();

            CryptoResult<RatchetHeader> decryptResult = headerEncryption2.DecryptHeader(encryptResult.Value!);

            // Assert
            decryptResult.IsSuccess.Should().BeFalse();
        }

        [Fact]
        public void TryDecryptWithKey_WithInvalidKey_ShouldFail()
        {
            // Arrange
            byte[] invalidKey = RandomNumberGenerator.GetBytes(16); // Wrong size
            EncryptedHeader encryptedHeader = new(
                RandomNumberGenerator.GetBytes(12),
                RandomNumberGenerator.GetBytes(64),
                RandomNumberGenerator.GetBytes(16));

            // Act
            CryptoResult<RatchetHeader> result = HeaderEncryption.TryDecryptWithKey(invalidKey, encryptedHeader);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Error.Should().Contain("Invalid key");
        }

        [Fact]
        public void Dispose_ShouldClearKeys()
        {
            // Arrange
            byte[] rootKey = RandomNumberGenerator.GetBytes(32);
            HeaderEncryption headerEncryption = HeaderEncryption.Initialize(rootKey).Value!;
            headerEncryption.GetCurrentHeaderKey().Should().NotBeNull();

            // Act
            headerEncryption.Dispose();

            // Assert - After dispose, operations should fail
            using ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            RatchetHeader header = new(ecdh.PublicKey.ExportSubjectPublicKeyInfo(), 1, 0);
            CryptoResult<EncryptedHeader> result = headerEncryption.EncryptHeader(header);
            result.IsSuccess.Should().BeFalse();
        }
    }
}
#endif
// <copyright file="SecureMessagingTests.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using FluentAssertions;
using Lucinda.Abstractions;
using Lucinda.KeyExchange;
using Lucinda.Protocol.DoubleRatchet;
using Lucinda.Protocol.X3DH;

using Xunit;

namespace Lucinda.Tests
{
    /// <summary>
    /// Tests for the SecureMessaging class (Signal Protocol-like functionality).
    /// </summary>
    public class SecureMessagingTests
    {
        [Fact]
        public void GenerateIdentityKeyPair_ShouldReturnValidKeyPair()
        {
            // Arrange
            using SecureMessaging messaging = new();

            // Act
            CryptoResult<AsymmetricKeyPair> result = messaging.GenerateIdentityKeyPair();

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.PublicKey.Should().NotBeNullOrEmpty();
            result.Value.PrivateKey.Should().NotBeNullOrEmpty();
            messaging.HasIdentity.Should().BeTrue();
        }

        [Fact]
        public void GeneratePreKeyBundle_WithoutIdentity_ShouldFail()
        {
            // Arrange
            using SecureMessaging messaging = new();

            // Act
            CryptoResult<PreKeyBundleWithPrivateKeys> result = messaging.GeneratePreKeyBundle();

            // Assert
            result.IsFailure.Should().BeTrue();
            result.Error.Should().Contain("Identity key pair must be generated first");
        }

        [Fact]
        public void GeneratePreKeyBundle_WithIdentity_ShouldReturnValidBundle()
        {
            // Arrange
            using SecureMessaging messaging = new();
            messaging.GenerateIdentityKeyPair();

            // Act
            CryptoResult<PreKeyBundleWithPrivateKeys> result = messaging.GeneratePreKeyBundle();

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Bundle.Should().NotBeNull();
            result.Value.Bundle.IdentityKey.Should().NotBeNullOrEmpty();
            result.Value.Bundle.SignedPreKey.Should().NotBeNullOrEmpty();
            result.Value.Bundle.SignedPreKeySignature.Should().NotBeNullOrEmpty();
            messaging.HasPreKeyBundle.Should().BeTrue();
        }

        [Fact]
        public void InitializeSession_WithValidBundle_ShouldSucceed()
        {
            // Arrange
            using SecureMessaging alice = new();
            using SecureMessaging bob = new();

            alice.GenerateIdentityKeyPair();
            bob.GenerateIdentityKeyPair();
            bob.GeneratePreKeyBundle();

            CryptoResult<PreKeyBundle> bobBundle = bob.GetPublicPreKeyBundle();

            // Act
            CryptoResult<string> result = alice.InitializeSession("bob", bobBundle.Value);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNullOrEmpty();
            alice.HasSession("bob").Value.Should().BeTrue();
        }

        [Fact]
        public void SendAndReceiveMessage_SimpleTwoWayConversation_ShouldWork()
        {
            // Arrange - Setup Alice and Bob
            using SecureMessaging alice = new();
            using SecureMessaging bob = new();

            alice.GenerateIdentityKeyPair();
            bob.GenerateIdentityKeyPair();
            bob.GeneratePreKeyBundle();

            // Alice initiates session with Bob
            CryptoResult<PreKeyBundle> bobBundle = bob.GetPublicPreKeyBundle();
            alice.InitializeSession("bob", bobBundle.Value);

            // Bob creates session from initial message
            CryptoResult<InitialMessageData> initialMessage = alice.GetInitialMessageData("bob");
            bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);

            // Act - Alice sends message to Bob
            string originalMessage = "Hello, Bob! This is a secret message.";
            CryptoResult<byte[]> encryptedResult = alice.SendMessage("bob", originalMessage);

            // Assert encryption succeeded
            encryptedResult.IsSuccess.Should().BeTrue();
            encryptedResult.Value.Should().NotBeNullOrEmpty();

            // Act - Bob decrypts message
            CryptoResult<string> decryptedResult = bob.ReceiveMessage("alice", encryptedResult.Value);

            // Assert decryption succeeded
            decryptedResult.IsSuccess.Should().BeTrue();
            decryptedResult.Value.Should().Be(originalMessage);
        }

        [Fact]
        public void SendMultipleMessages_ShouldAllDecryptCorrectly()
        {
            // Arrange
            using SecureMessaging alice = new();
            using SecureMessaging bob = new();

            alice.GenerateIdentityKeyPair();
            bob.GenerateIdentityKeyPair();
            bob.GeneratePreKeyBundle();

            CryptoResult<PreKeyBundle> bobBundle = bob.GetPublicPreKeyBundle();
            alice.InitializeSession("bob", bobBundle.Value);

            CryptoResult<InitialMessageData> initialMessage = alice.GetInitialMessageData("bob");
            bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);

            // Act & Assert - Send multiple messages
            string[] messages =
            [
                "First message",
                "Second message",
                "Third message with some special characters: !@#$%^&*()",
                "Fourth message: 你好世界 🔐"
            ];

            foreach (string message in messages)
            {
                CryptoResult<byte[]> encrypted = alice.SendMessage("bob", message);
                encrypted.IsSuccess.Should().BeTrue();

                CryptoResult<string> decrypted = bob.ReceiveMessage("alice", encrypted.Value);
                decrypted.IsSuccess.Should().BeTrue();
                decrypted.Value.Should().Be(message);
            }
        }

        [Fact]
        public void ForwardSecrecy_DifferentMessagesHaveDifferentCiphertext()
        {
            // Arrange
            using SecureMessaging alice = new();
            using SecureMessaging bob = new();

            alice.GenerateIdentityKeyPair();
            bob.GenerateIdentityKeyPair();
            bob.GeneratePreKeyBundle();

            CryptoResult<PreKeyBundle> bobBundle = bob.GetPublicPreKeyBundle();
            alice.InitializeSession("bob", bobBundle.Value);

            CryptoResult<InitialMessageData> initialMessage = alice.GetInitialMessageData("bob");
            bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);

            // Act - Send the same message twice
            string message = "Same message";
            CryptoResult<byte[]> encrypted1 = alice.SendMessage("bob", message);
            CryptoResult<byte[]> encrypted2 = alice.SendMessage("bob", message);

            // Assert - Ciphertexts should be different (due to ratcheting)
            encrypted1.IsSuccess.Should().BeTrue();
            encrypted2.IsSuccess.Should().BeTrue();
            encrypted1.Value.Should().NotEqual(encrypted2.Value);
        }

        [Fact]
        public void DeleteSession_ShouldRemoveSession()
        {
            // Arrange
            using SecureMessaging alice = new();
            using SecureMessaging bob = new();

            alice.GenerateIdentityKeyPair();
            bob.GenerateIdentityKeyPair();
            bob.GeneratePreKeyBundle();

            CryptoResult<PreKeyBundle> bobBundle = bob.GetPublicPreKeyBundle();
            alice.InitializeSession("bob", bobBundle.Value);

            // Verify session exists
            alice.HasSession("bob").Value.Should().BeTrue();

            // Act
            CryptoResult<bool> result = alice.DeleteSession("bob");

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().BeTrue();
            alice.HasSession("bob").Value.Should().BeFalse();
        }

        [Fact]
        public void ListActiveSessions_ShouldReturnAllSessions()
        {
            // Arrange
            using SecureMessaging alice = new();
            alice.GenerateIdentityKeyPair();

            // Create mock bundles for multiple recipients
            using SecureMessaging bob = new();
            using SecureMessaging charlie = new();

            bob.GenerateIdentityKeyPair();
            bob.GeneratePreKeyBundle();

            charlie.GenerateIdentityKeyPair();
            charlie.GeneratePreKeyBundle();

            alice.InitializeSession("bob", bob.GetPublicPreKeyBundle().Value);
            alice.InitializeSession("charlie", charlie.GetPublicPreKeyBundle().Value);

            // Act
            CryptoResult<string[]> result = alice.ListActiveSessions();

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().HaveCount(2);
            result.Value.Should().Contain("bob");
            result.Value.Should().Contain("charlie");
        }
    }

    /// <summary>
    /// Tests for the X3DH key agreement.
    /// </summary>
    public class X3DHKeyAgreementTests
    {
        [Fact]
        public void GeneratePreKeyBundle_ShouldCreateValidBundle()
        {
            // Arrange
            using X3DHKeyAgreement x3dh = new();
            using EcdhKeyExchange ecdh = new();
            CryptoResult<AsymmetricKeyPair> identityKeyPair = ecdh.GenerateKeyPair();

            // Act
            CryptoResult<PreKeyBundleWithPrivateKeys> result = x3dh.GeneratePreKeyBundle(identityKeyPair.Value, 1, [1, 2, 3]);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Bundle.IdentityKey.Should().NotBeNullOrEmpty();
            result.Value.Bundle.SignedPreKey.Should().NotBeNullOrEmpty();
            result.Value.Bundle.SignedPreKeySignature.Should().NotBeNullOrEmpty();
            result.Value.SignedPreKeyPrivate.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public void InitiatorAndResponder_ShouldDeriveSharedSecret()
        {
            // Arrange
            using X3DHKeyAgreement x3dh = new();
            using EcdhKeyExchange aliceEcdh = new();
            using EcdhKeyExchange bobEcdh = new();

            CryptoResult<AsymmetricKeyPair> aliceIdentity = aliceEcdh.GenerateKeyPair();
            CryptoResult<AsymmetricKeyPair> bobIdentity = bobEcdh.GenerateKeyPair();

            CryptoResult<PreKeyBundleWithPrivateKeys> bobBundleResult = x3dh.GeneratePreKeyBundle(bobIdentity.Value, 1, [1]);
            PreKeyBundleWithPrivateKeys bobBundle = bobBundleResult.Value;

            // Act - Alice performs initiator agreement
            CryptoResult<X3DHResult> aliceResult = x3dh.InitiatorAgree(aliceIdentity.Value, bobBundle.Bundle);

            // Bob performs responder agreement
            AsymmetricKeyPair bobSignedPreKeyPair = new(
                bobBundle.Bundle.SignedPreKey,
                bobBundle.SignedPreKeyPrivate);

            AsymmetricKeyPair? bobOneTimePreKeyPair = null;
            if (aliceResult.Value.UsedOneTimePreKeyId.HasValue)
            {
                byte[]? otpkPrivate = bobBundle.GetOneTimePreKeyPrivate(aliceResult.Value.UsedOneTimePreKeyId.Value);
                if (otpkPrivate != null)
                {
                    bobOneTimePreKeyPair = new AsymmetricKeyPair(
                        bobBundle.Bundle.OneTimePreKey!,
                        otpkPrivate);
                }
            }

            CryptoResult<X3DHResult> bobResult = x3dh.ResponderAgree(
                bobIdentity.Value,
                bobSignedPreKeyPair,
                bobOneTimePreKeyPair,
                [.. aliceResult.Value.AssociatedData.Take(aliceIdentity.Value.PublicKey.Length)],
                aliceResult.Value.EphemeralPublicKey!);

            // Assert - Both should derive the same shared secret
            aliceResult.IsSuccess.Should().BeTrue();
            bobResult.IsSuccess.Should().BeTrue();
            aliceResult.Value.SharedSecret.Should().Equal(bobResult.Value.SharedSecret);
        }
    }

    /// <summary>
    /// Tests for the Double Ratchet algorithm.
    /// </summary>
    public class DoubleRatchetTests
    {
        [Fact]
        public void InitializeAsInitiator_ShouldCreateValidState()
        {
            // Arrange
            using DoubleRatchet ratchet = new();
            using EcdhKeyExchange ecdh = new();

            CryptoResult<AsymmetricKeyPair> remoteKeyPair = ecdh.GenerateKeyPair();
            byte[] sharedSecret = new byte[32];
            Random.Shared.NextBytes(sharedSecret);

            // Act
            CryptoResult<RatchetState> result = ratchet.InitializeAsInitiator(sharedSecret, remoteKeyPair.Value.PublicKey);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.RootKey.Should().NotBeNullOrEmpty();
            result.Value.SendingChainKey.Should().NotBeNullOrEmpty();
            result.Value.DHSendingPublicKey.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public void EncryptAndDecrypt_ShouldWork()
        {
            // Arrange
            using DoubleRatchet ratchet = new();
            using EcdhKeyExchange aliceEcdh = new();
            using EcdhKeyExchange bobEcdh = new();

            CryptoResult<AsymmetricKeyPair> bobKeyPair = bobEcdh.GenerateKeyPair();
            byte[] sharedSecret = new byte[32];
            Random.Shared.NextBytes(sharedSecret);

            CryptoResult<RatchetState> aliceState = ratchet.InitializeAsInitiator(sharedSecret, bobKeyPair.Value.PublicKey);
            CryptoResult<RatchetState> bobState = ratchet.InitializeAsResponder(sharedSecret, bobKeyPair.Value);

            byte[] plaintext = "Hello, Double Ratchet!"u8.ToArray();

            // Act - Alice encrypts
            CryptoResult<RatchetMessage> encryptResult = ratchet.Encrypt(aliceState.Value, plaintext);
            encryptResult.IsSuccess.Should().BeTrue();

            // Act - Bob decrypts
            CryptoResult<byte[]> decryptResult = ratchet.Decrypt(bobState.Value, encryptResult.Value);

            // Assert
            decryptResult.IsSuccess.Should().BeTrue();
            decryptResult.Value.Should().Equal(plaintext);
        }

        [Fact]
        public void MultipleMessages_ShouldAllDecrypt()
        {
            // Arrange
            using DoubleRatchet ratchet = new();
            using EcdhKeyExchange bobEcdh = new();

            CryptoResult<AsymmetricKeyPair> bobKeyPair = bobEcdh.GenerateKeyPair();
            byte[] sharedSecret = new byte[32];
            Random.Shared.NextBytes(sharedSecret);

            CryptoResult<RatchetState> aliceState = ratchet.InitializeAsInitiator(sharedSecret, bobKeyPair.Value.PublicKey);
            CryptoResult<RatchetState> bobState = ratchet.InitializeAsResponder(sharedSecret, bobKeyPair.Value);

            // Act & Assert
            for (int i = 0; i < 10; i++)
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes($"Message {i}");

                CryptoResult<RatchetMessage> encryptResult = ratchet.Encrypt(aliceState.Value, plaintext);
                encryptResult.IsSuccess.Should().BeTrue();

                CryptoResult<byte[]> decryptResult = ratchet.Decrypt(bobState.Value, encryptResult.Value);
                decryptResult.IsSuccess.Should().BeTrue();
                System.Text.Encoding.UTF8.GetString(decryptResult.Value).Should().Be($"Message {i}");
            }
        }
    }

    /// <summary>
    /// Tests for the KDF Chain.
    /// </summary>
    public class KdfChainTests
    {
        [Fact]
        public void RootKdf_ShouldDeriveNewKeys()
        {
            // Arrange
            using KdfChain kdf = new();
            byte[] rootKey = new byte[32];
            byte[] dhOutput = new byte[32];
            Random.Shared.NextBytes(rootKey);
            Random.Shared.NextBytes(dhOutput);

            // Act
            CryptoResult<(byte[] RootKey, byte[] ChainKey)> result = kdf.RootKdf(rootKey, dhOutput);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.RootKey.Should().NotBeNullOrEmpty();
            result.Value.RootKey.Should().HaveCount(32);
            result.Value.ChainKey.Should().NotBeNullOrEmpty();
            result.Value.ChainKey.Should().HaveCount(32);
            result.Value.RootKey.Should().NotEqual(rootKey);
        }

        [Fact]
        public void ChainKdf_ShouldDeriveMessageKey()
        {
            // Arrange
            using KdfChain kdf = new();
            byte[] chainKey = new byte[32];
            Random.Shared.NextBytes(chainKey);

            // Act
            CryptoResult<(byte[] MessageKey, byte[] NextChainKey)> result = kdf.ChainKdf(chainKey);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.MessageKey.Should().NotBeNullOrEmpty();
            result.Value.MessageKey.Should().HaveCount(32);
            result.Value.NextChainKey.Should().NotBeNullOrEmpty();
            result.Value.NextChainKey.Should().HaveCount(32);
            result.Value.NextChainKey.Should().NotEqual(chainKey);
        }

        [Fact]
        public void ChainKdf_SuccessiveCalls_ShouldProduceDifferentKeys()
        {
            // Arrange
            using KdfChain kdf = new();
            byte[] chainKey = new byte[32];
            Random.Shared.NextBytes(chainKey);

            // Act
            CryptoResult<(byte[] MessageKey, byte[] NextChainKey)> result1 = kdf.ChainKdf(chainKey);
            CryptoResult<(byte[] MessageKey, byte[] NextChainKey)> result2 = kdf.ChainKdf(result1.Value.NextChainKey);
            CryptoResult<(byte[] MessageKey, byte[] NextChainKey)> result3 = kdf.ChainKdf(result2.Value.NextChainKey);

            // Assert
            result1.Value.MessageKey.Should().NotEqual(result2.Value.MessageKey);
            result2.Value.MessageKey.Should().NotEqual(result3.Value.MessageKey);
        }
    }

    /// <summary>
    /// Tests for RatchetState serialization.
    /// </summary>
    public class RatchetStateTests
    {
        [Fact]
        public void SerializeAndDeserialize_ShouldPreserveState()
        {
            // Arrange
            RatchetState original = new()
            {
                RootKey = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
                SendingChainKey = [32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
                SendingMessageNumber = 5,
                ReceivingMessageNumber = 3,
                PreviousSendingChainLength = 10
            };

            // Act
            byte[] serialized = original.Serialize();
            RatchetState deserialized = RatchetState.Deserialize(serialized);

            // Assert
            deserialized.RootKey.Should().Equal(original.RootKey);
            deserialized.SendingChainKey.Should().Equal(original.SendingChainKey);
            deserialized.SendingMessageNumber.Should().Be(original.SendingMessageNumber);
            deserialized.ReceivingMessageNumber.Should().Be(original.ReceivingMessageNumber);
            deserialized.PreviousSendingChainLength.Should().Be(original.PreviousSendingChainLength);

            // Cleanup
            original.Dispose();
            deserialized.Dispose();
        }
    }
}
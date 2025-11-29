// -----------------------------------------------------------------------
// <copyright file="GroupSessionTests.cs" company="Taiizor">
// Copyright (c) Taiizor. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.
// </copyright>
// -----------------------------------------------------------------------

#if NET6_0_OR_GREATER
using FluentAssertions;
using Lucinda.Abstractions;
using Lucinda.Protocol.SenderKeys;
using System.Text;
using Xunit;

namespace Lucinda.Tests
{
    /// <summary>
    /// Unit tests for GroupSession (Sender Keys Protocol).
    /// </summary>
    public class GroupSessionTests
    {
        private const string TestGroupId = "test-group-123";

        [Fact]
        public void GroupSession_Create_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            using GroupSession session = new(TestGroupId, "alice");

            // Assert
            session.GroupId.Should().Be(TestGroupId);
            session.LocalParticipantId.Should().Be("alice");
            session.IsInitialized.Should().BeFalse();
            session.RemoteParticipantCount.Should().Be(0);
        }

        [Fact]
        public void Initialize_ShouldSetupSenderKey()
        {
            // Arrange
            using GroupSession session = new(TestGroupId, "alice");

            // Act
            CryptoResult<bool> result = session.Initialize();

            // Assert
            result.IsSuccess.Should().BeTrue();
            session.IsInitialized.Should().BeTrue();
        }

        [Fact]
        public void CreateDistributionMessage_WithoutInitialize_ShouldFail()
        {
            // Arrange
            using GroupSession session = new(TestGroupId, "alice");

            // Act
            CryptoResult<SenderKeyDistributionData> result = session.CreateDistributionMessage();

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Error.Should().Contain("not initialized");
        }

        [Fact]
        public void CreateDistributionMessage_AfterInitialize_ShouldSucceed()
        {
            // Arrange
            using GroupSession session = new(TestGroupId, "alice");
            session.Initialize();

            // Act
            CryptoResult<SenderKeyDistributionData> result = session.CreateDistributionMessage();

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNull();
            result.Value!.ChainKey.Should().HaveCount(32);
            result.Value.SignaturePublicKey.Should().NotBeEmpty();
        }

        [Fact]
        public void ProcessDistributionMessage_ShouldAddParticipant()
        {
            // Arrange
            using GroupSession aliceSession = new(TestGroupId, "alice");
            using GroupSession bobSession = new(TestGroupId, "bob");

            aliceSession.Initialize();
            SenderKeyDistributionData aliceDistribution = aliceSession.CreateDistributionMessage().Value!;

            // Act
            CryptoResult<bool> result = bobSession.ProcessDistributionMessage("alice", aliceDistribution);

            // Assert
            result.IsSuccess.Should().BeTrue();
            bobSession.HasParticipant("alice").Should().BeTrue();
            bobSession.RemoteParticipantCount.Should().Be(1);
        }

        [Fact]
        public void Encrypt_WithoutInitialize_ShouldFail()
        {
            // Arrange
            using GroupSession session = new(TestGroupId, "alice");
            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, Group!");

            // Act
            CryptoResult<GroupMessage> result = session.Encrypt(plaintext);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Error.Should().Contain("not initialized");
        }

        [Fact]
        public void EncryptDecrypt_BetweenParticipants_ShouldWork()
        {
            // Arrange
            using GroupSession aliceSession = new(TestGroupId, "alice");
            using GroupSession bobSession = new(TestGroupId, "bob");

            aliceSession.Initialize();
            bobSession.Initialize();

            // Exchange distribution messages
            SenderKeyDistributionData aliceDistribution = aliceSession.CreateDistributionMessage().Value!;
            SenderKeyDistributionData bobDistribution = bobSession.CreateDistributionMessage().Value!;

            aliceSession.ProcessDistributionMessage("bob", bobDistribution);
            bobSession.ProcessDistributionMessage("alice", aliceDistribution);

            string originalMessage = "Hello from Alice to the group!";
            byte[] plaintext = Encoding.UTF8.GetBytes(originalMessage);

            // Act
            CryptoResult<GroupMessage> encryptResult = aliceSession.Encrypt(plaintext);
            encryptResult.IsSuccess.Should().BeTrue();

            CryptoResult<byte[]> decryptResult = bobSession.Decrypt(encryptResult.Value!);

            // Assert
            decryptResult.IsSuccess.Should().BeTrue();
            Encoding.UTF8.GetString(decryptResult.Value!).Should().Be(originalMessage);
        }

        [Fact]
        public void Decrypt_FromUnknownSender_ShouldFail()
        {
            // Arrange
            using GroupSession aliceSession = new(TestGroupId, "alice");
            using GroupSession bobSession = new(TestGroupId, "bob");

            aliceSession.Initialize();
            bobSession.Initialize();

            // Bob does NOT have Alice's distribution
            byte[] plaintext = Encoding.UTF8.GetBytes("Secret message");
            CryptoResult<GroupMessage> encryptResult = aliceSession.Encrypt(plaintext);

            // Act
            CryptoResult<byte[]> decryptResult = bobSession.Decrypt(encryptResult.Value!);

            // Assert
            decryptResult.IsSuccess.Should().BeFalse();
            decryptResult.Error.Should().Contain("Unknown sender");
        }

        [Fact]
        public void MultipleMessages_ShouldDecryptCorrectly()
        {
            // Arrange
            using GroupSession aliceSession = new(TestGroupId, "alice");
            using GroupSession bobSession = new(TestGroupId, "bob");

            aliceSession.Initialize();
            bobSession.Initialize();

            SenderKeyDistributionData aliceDistribution = aliceSession.CreateDistributionMessage().Value!;
            bobSession.ProcessDistributionMessage("alice", aliceDistribution);

            string[] messages = new[]
            {
                "First message",
                "Second message",
                "Third message"
            };

            // Act & Assert
            foreach (string? message in messages)
            {
                byte[] plaintext = Encoding.UTF8.GetBytes(message);
                CryptoResult<GroupMessage> encryptResult = aliceSession.Encrypt(plaintext);
                encryptResult.IsSuccess.Should().BeTrue();

                CryptoResult<byte[]> decryptResult = bobSession.Decrypt(encryptResult.Value!);
                decryptResult.IsSuccess.Should().BeTrue();
                Encoding.UTF8.GetString(decryptResult.Value!).Should().Be(message);
            }
        }

        [Fact]
        public void ThreeParticipants_ShouldCommunicate()
        {
            // Arrange
            using GroupSession aliceSession = new(TestGroupId, "alice");
            using GroupSession bobSession = new(TestGroupId, "bob");
            using GroupSession charlieSession = new(TestGroupId, "charlie");

            aliceSession.Initialize();
            bobSession.Initialize();
            charlieSession.Initialize();

            // Full distribution
            SenderKeyDistributionData aliceDist = aliceSession.CreateDistributionMessage().Value!;
            SenderKeyDistributionData bobDist = bobSession.CreateDistributionMessage().Value!;
            SenderKeyDistributionData charlieDist = charlieSession.CreateDistributionMessage().Value!;

            // Everyone gets everyone's keys
            aliceSession.ProcessDistributionMessage("bob", bobDist);
            aliceSession.ProcessDistributionMessage("charlie", charlieDist);
            bobSession.ProcessDistributionMessage("alice", aliceDist);
            bobSession.ProcessDistributionMessage("charlie", charlieDist);
            charlieSession.ProcessDistributionMessage("alice", aliceDist);
            charlieSession.ProcessDistributionMessage("bob", bobDist);

            string aliceMessage = "Hello from Alice!";
            byte[] plaintext = Encoding.UTF8.GetBytes(aliceMessage);

            // Act
            GroupMessage encrypted = aliceSession.Encrypt(plaintext).Value!;
            CryptoResult<byte[]> bobDecrypt = bobSession.Decrypt(encrypted);
            CryptoResult<byte[]> charlieDecrypt = charlieSession.Decrypt(encrypted);

            // Assert
            bobDecrypt.IsSuccess.Should().BeTrue();
            charlieDecrypt.IsSuccess.Should().BeTrue();
            Encoding.UTF8.GetString(bobDecrypt.Value!).Should().Be(aliceMessage);
            Encoding.UTF8.GetString(charlieDecrypt.Value!).Should().Be(aliceMessage);
        }

        [Fact]
        public void RemoveParticipant_ShouldWork()
        {
            // Arrange
            using GroupSession session = new(TestGroupId, "alice");
            using GroupSession bobSession = new(TestGroupId, "bob");

            bobSession.Initialize();
            SenderKeyDistributionData bobDist = bobSession.CreateDistributionMessage().Value!;
            session.ProcessDistributionMessage("bob", bobDist);
            session.HasParticipant("bob").Should().BeTrue();

            // Act
            session.RemoveParticipant("bob");

            // Assert
            session.HasParticipant("bob").Should().BeFalse();
            session.RemoteParticipantCount.Should().Be(0);
        }

        [Fact]
        public void ReKey_ShouldGenerateNewDistribution()
        {
            // Arrange
            using GroupSession session = new(TestGroupId, "alice");
            session.Initialize();

            SenderKeyDistributionData originalDist = session.CreateDistributionMessage().Value!;
            int originalKeyId = originalDist.KeyId;

            // Act
            CryptoResult<SenderKeyDistributionData> reKeyResult = session.ReKey();

            // Assert
            reKeyResult.IsSuccess.Should().BeTrue();
            reKeyResult.Value!.KeyId.Should().NotBe(originalKeyId);
        }

        [Fact]
        public void SenderKeyDistributionData_Serialize_ShouldRoundTrip()
        {
            // Arrange
            using GroupSession session = new(TestGroupId, "alice");
            session.Initialize();

            SenderKeyDistributionData distribution = session.CreateDistributionMessage().Value!;

            // Act
            byte[] serialized = distribution.Serialize();
            SenderKeyDistributionData? deserialized = SenderKeyDistributionData.Deserialize(serialized);

            // Assert
            deserialized.Should().NotBeNull();
            deserialized!.KeyId.Should().Be(distribution.KeyId);
            deserialized.ChainIndex.Should().Be(distribution.ChainIndex);
            deserialized.ChainKey.Should().BeEquivalentTo(distribution.ChainKey);
            deserialized.SignaturePublicKey.Should().BeEquivalentTo(distribution.SignaturePublicKey);
        }

        [Fact]
        public void GroupMessage_Serialize_ShouldRoundTrip()
        {
            // Arrange
            using GroupSession session = new(TestGroupId, "alice");
            session.Initialize();

            byte[] plaintext = Encoding.UTF8.GetBytes("Test message");
            GroupMessage encrypted = session.Encrypt(plaintext).Value!;

            // Act
            byte[] serialized = encrypted.Serialize();
            CryptoResult<GroupMessage> deserializeResult = GroupMessage.Deserialize(serialized);

            // Assert
            deserializeResult.IsSuccess.Should().BeTrue();
            deserializeResult.Value!.GroupId.Should().Be(TestGroupId);
            deserializeResult.Value.SenderId.Should().Be("alice");
            deserializeResult.Value.Ciphertext.Should().BeEquivalentTo(encrypted.Ciphertext);
        }

        [Fact]
        public void GetParticipants_ShouldReturnAllKnown()
        {
            // Arrange
            using GroupSession session = new(TestGroupId, "alice");
            using GroupSession bobSession = new(TestGroupId, "bob");
            using GroupSession charlieSession = new(TestGroupId, "charlie");

            bobSession.Initialize();
            charlieSession.Initialize();

            session.ProcessDistributionMessage("bob", bobSession.CreateDistributionMessage().Value!);
            session.ProcessDistributionMessage("charlie", charlieSession.CreateDistributionMessage().Value!);

            // Act
            List<string> participants = [.. session.GetParticipants()];

            // Assert
            participants.Should().HaveCount(2);
            participants.Should().Contain("bob");
            participants.Should().Contain("charlie");
        }

        [Fact]
        public void Dispose_ShouldCleanUp()
        {
            // Arrange
            GroupSession session = new(TestGroupId, "alice");
            session.Initialize();

            // Act
            session.Dispose();

            // Assert - Operations should fail after dispose
            CryptoResult<GroupMessage> result = session.Encrypt([1, 2, 3]);
            result.IsSuccess.Should().BeFalse();
        }
    }
}
#endif
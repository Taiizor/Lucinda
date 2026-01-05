// <copyright file="PreKeyBundleMultiKeyTests.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using FluentAssertions;
using Lucinda.Abstractions;
using Lucinda.KeyExchange;
using Lucinda.Protocol.X3DH;

using Xunit;

namespace Lucinda.Tests
{
    /// <summary>
    /// Tests for PreKeyBundle multiple one-time pre-key support.
    /// These tests verify that PreKeyBundle correctly stores and manages
    /// all one-time pre-keys, enabling different users to use different keys.
    /// </summary>
    public class PreKeyBundleMultiKeyTests
    {
        [Fact]
        public void GeneratePreKeyBundle_ShouldContainAllOneTimePreKeys()
        {
            // Arrange
            using X3DHKeyAgreement x3dh = new();
            using EcdhKeyExchange ecdh = new();
            CryptoResult<AsymmetricKeyPair> identityKeyPair = ecdh.GenerateKeyPair();
            int[] oneTimePreKeyIds = [1, 2, 3, 4, 5];

            // Act
            CryptoResult<PreKeyBundleWithPrivateKeys> result = x3dh.GeneratePreKeyBundle(
                identityKeyPair.Value, 1, oneTimePreKeyIds);

            // Assert - Bundle should contain ALL one-time pre-keys, not just the first one
            result.IsSuccess.Should().BeTrue();
            result.Value.Bundle.OneTimePreKeys.Should().HaveCount(5);
            result.Value.Bundle.HasOneTimePreKey.Should().BeTrue();

            // All keys should be present
            foreach (int id in oneTimePreKeyIds)
            {
                result.Value.Bundle.OneTimePreKeys.Should().ContainKey(id);
                result.Value.Bundle.GetOneTimePreKey(id).Should().NotBeNull();
            }

            // Private keys should also be present for all
            result.Value.OneTimePreKeyPrivates.Should().HaveCount(5);
        }

        [Fact]
        public void MultipleSessionsWithSameBundle_ShouldUseDifferentOneTimeKeys()
        {
            // Arrange - Bob generates bundle with multiple one-time keys
            using X3DHKeyAgreement x3dh = new();
            using EcdhKeyExchange bobEcdh = new();

            CryptoResult<AsymmetricKeyPair> bobIdentity = bobEcdh.GenerateKeyPair();

            CryptoResult<PreKeyBundleWithPrivateKeys> bobBundleResult = x3dh.GeneratePreKeyBundle(
                bobIdentity.Value, 1, [1, 2, 3]);
            PreKeyBundleWithPrivateKeys bobBundle = bobBundleResult.Value;

            // Simulate server giving Alice one key
            (int Id, byte[] Key)? aliceKey = bobBundle.Bundle.ConsumeOneTimePreKey();
            aliceKey.Should().NotBeNull();

            // Simulate server giving Karen a different key
            (int Id, byte[] Key)? karenKey = bobBundle.Bundle.ConsumeOneTimePreKey();
            karenKey.Should().NotBeNull();

            // Assert - Alice and Karen got different keys
            aliceKey!.Value.Id.Should().NotBe(karenKey!.Value.Id);
            aliceKey.Value.Key.Should().NotEqual(karenKey.Value.Key);

            // One key should still remain
            bobBundle.Bundle.OneTimePreKeys.Should().HaveCount(1);
        }

        [Fact]
        public void ConsumeOneTimePreKey_ShouldRemoveKeyFromBundle()
        {
            // Arrange
            using X3DHKeyAgreement x3dh = new();
            using EcdhKeyExchange ecdh = new();
            CryptoResult<AsymmetricKeyPair> identityKeyPair = ecdh.GenerateKeyPair();

            CryptoResult<PreKeyBundleWithPrivateKeys> result = x3dh.GeneratePreKeyBundle(
                identityKeyPair.Value, 1, [1, 2]);
            PreKeyBundle bundle = result.Value.Bundle;

            // Act - Consume keys
            int initialCount = bundle.OneTimePreKeys.Count;
            (int Id, byte[] Key)? first = bundle.ConsumeOneTimePreKey();
            (int Id, byte[] Key)? second = bundle.ConsumeOneTimePreKey();
            (int Id, byte[] Key)? third = bundle.ConsumeOneTimePreKey();

            // Assert
            initialCount.Should().Be(2);
            first.Should().NotBeNull();
            second.Should().NotBeNull();
            third.Should().BeNull(); // No more keys
            bundle.OneTimePreKeys.Should().BeEmpty();
            bundle.HasOneTimePreKey.Should().BeFalse();
        }

        [Fact]
        public void BackwardCompatibility_SingleKeyAccessShouldWork()
        {
            // Arrange
            using X3DHKeyAgreement x3dh = new();
            using EcdhKeyExchange ecdh = new();
            CryptoResult<AsymmetricKeyPair> identityKeyPair = ecdh.GenerateKeyPair();

            CryptoResult<PreKeyBundleWithPrivateKeys> result = x3dh.GeneratePreKeyBundle(
                identityKeyPair.Value, 1, [1, 2, 3]);

            // Act - Use backward-compatible single key properties
            PreKeyBundle bundle = result.Value.Bundle;
            byte[]? singleKey = bundle.OneTimePreKey;
            int? singleKeyId = bundle.OneTimePreKeyId;

            // Assert - Should return the first available key
            singleKey.Should().NotBeNull();
            singleKeyId.Should().NotBeNull();
            bundle.HasOneTimePreKey.Should().BeTrue();
        }

        [Fact]
        public void GetOneTimePreKey_ShouldReturnSpecificKey()
        {
            // Arrange
            using X3DHKeyAgreement x3dh = new();
            using EcdhKeyExchange ecdh = new();
            CryptoResult<AsymmetricKeyPair> identityKeyPair = ecdh.GenerateKeyPair();

            CryptoResult<PreKeyBundleWithPrivateKeys> result = x3dh.GeneratePreKeyBundle(
                identityKeyPair.Value, 1, [10, 20, 30]);

            PreKeyBundle bundle = result.Value.Bundle;

            // Act
            byte[]? key10 = bundle.GetOneTimePreKey(10);
            byte[]? key20 = bundle.GetOneTimePreKey(20);
            byte[]? key30 = bundle.GetOneTimePreKey(30);
            byte[]? keyMissing = bundle.GetOneTimePreKey(999);

            // Assert
            key10.Should().NotBeNull();
            key20.Should().NotBeNull();
            key30.Should().NotBeNull();
            keyMissing.Should().BeNull();

            // All keys should be different
            key10.Should().NotEqual(key20);
            key20.Should().NotEqual(key30);
        }

        [Fact]
        public void EmptyOneTimePreKeys_ShouldHandleGracefully()
        {
            // Arrange
            using X3DHKeyAgreement x3dh = new();
            using EcdhKeyExchange ecdh = new();
            CryptoResult<AsymmetricKeyPair> identityKeyPair = ecdh.GenerateKeyPair();

            // Generate bundle without one-time pre-keys
            CryptoResult<PreKeyBundleWithPrivateKeys> result = x3dh.GeneratePreKeyBundle(
                identityKeyPair.Value, 1, null);

            PreKeyBundle bundle = result.Value.Bundle;

            // Act & Assert
            bundle.HasOneTimePreKey.Should().BeFalse();
            bundle.OneTimePreKey.Should().BeNull();
            bundle.OneTimePreKeyId.Should().BeNull();
            bundle.ConsumeOneTimePreKey().Should().BeNull();
            bundle.GetOneTimePreKey(1).Should().BeNull();
        }
    }
}
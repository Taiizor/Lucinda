// <copyright file="PreKeyDistributionManagerTests.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using FluentAssertions;
using Lucinda.Abstractions;
using Lucinda.KeyExchange;
using Lucinda.Protocol.X3DH;
using System.Collections.Concurrent;
using Xunit;

namespace Lucinda.Tests;

/// <summary>
/// Tests for the <see cref="PreKeyDistributionManager"/> class.
/// </summary>
public sealed class PreKeyDistributionManagerTests
{
    /// <summary>
    /// Helper method to create a PreKeyDistributionManager with specified one-time pre-key IDs.
    /// </summary>
    private static PreKeyDistributionManager CreateManager(int[] oneTimePreKeyIds)
    {
        using X3DHKeyAgreement x3dh = new();
        using EcdhKeyExchange ecdh = new();

        CryptoResult<AsymmetricKeyPair> identity = ecdh.GenerateKeyPair();
        CryptoResult<PreKeyBundleWithPrivateKeys> bundleResult = x3dh.GeneratePreKeyBundle(
            identity.Value, 1, oneTimePreKeyIds);

        return new PreKeyDistributionManager(bundleResult.Value);
    }

    [Fact]
    public void ConsumeKeyPair_ShouldReturnKeyPair_WhenKeysAvailable()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3]);

        // Act
        (int Id, byte[] PublicKey, byte[] PrivateKey)? consumed = manager.ConsumeKeyPair();

        // Assert
        consumed.Should().NotBeNull();
        consumed!.Value.Id.Should().BeOneOf(1, 2, 3);
        consumed.Value.PublicKey.Should().NotBeNullOrEmpty();
        consumed.Value.PrivateKey.Should().NotBeNullOrEmpty();
        manager.RemainingKeyCount.Should().Be(2);
    }

    [Fact]
    public void ConsumeKeyPair_ShouldReturnNull_WhenNoKeysAvailable()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([]);

        // Act
        (int Id, byte[] PublicKey, byte[] PrivateKey)? consumed = manager.ConsumeKeyPair();

        // Assert
        consumed.Should().BeNull();
        manager.HasKeysAvailable.Should().BeFalse();
    }

    [Fact]
    public void ConsumeKeyPair_ShouldConsumeAllKeys_WhenCalledMultipleTimes()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3]);
        HashSet<int> consumedIds = [];

        // Act
        for (int i = 0; i < 3; i++)
        {
            (int Id, byte[] PublicKey, byte[] PrivateKey)? consumed = manager.ConsumeKeyPair();
            consumed.Should().NotBeNull();
            consumedIds.Add(consumed!.Value.Id);
        }

        // Assert
        consumedIds.Should().BeEquivalentTo([1, 2, 3]);
        manager.RemainingKeyCount.Should().Be(0);
        manager.HasKeysAvailable.Should().BeFalse();
        manager.ConsumeKeyPair().Should().BeNull();
    }

    [Fact]
    public void KeysRunningLow_ShouldFire_WhenBelowThreshold()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3, 4, 5]);
        manager.LowKeyThreshold = 3;

        int? reportedCount = null;
        manager.KeysRunningLow += count => reportedCount = count;

        // Act
        manager.ConsumeKeyPair(); // 4 remaining
        manager.ConsumeKeyPair(); // 3 remaining - should fire

        // Assert
        reportedCount.Should().Be(3);
    }

    [Fact]
    public void KeysRunningLow_ShouldFireOnlyOnce_WhenBelowThreshold()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3, 4, 5]);
        manager.LowKeyThreshold = 3;

        int eventFireCount = 0;
        manager.KeysRunningLow += _ => eventFireCount++;

        // Act
        manager.ConsumeKeyPair(); // 4 remaining
        manager.ConsumeKeyPair(); // 3 remaining - should fire
        manager.ConsumeKeyPair(); // 2 remaining - should NOT fire
        manager.ConsumeKeyPair(); // 1 remaining - should NOT fire

        // Assert
        eventFireCount.Should().Be(1);
    }

    [Fact]
    public void KeysExhausted_ShouldFire_WhenAllKeysConsumed()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1]);

        bool exhaustedFired = false;
        manager.KeysExhausted += () => exhaustedFired = true;

        // Act
        manager.ConsumeKeyPair();

        // Assert
        exhaustedFired.Should().BeTrue();
        manager.RemainingKeyCount.Should().Be(0);
    }

    [Fact]
    public void GetKeyPair_ShouldReturnKeyPair_WithoutConsuming()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3]);

        // Act
        (byte[] PublicKey, byte[] PrivateKey)? keyPair = manager.GetKeyPair(1);

        // Assert
        keyPair.Should().NotBeNull();
        keyPair!.Value.PublicKey.Should().NotBeNullOrEmpty();
        keyPair.Value.PrivateKey.Should().NotBeNullOrEmpty();
        manager.RemainingKeyCount.Should().Be(3);
    }

    [Fact]
    public void GetKeyPair_ShouldReturnNull_WhenKeyIdNotFound()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3]);

        // Act
        (byte[] PublicKey, byte[] PrivateKey)? keyPair = manager.GetKeyPair(999);

        // Assert
        keyPair.Should().BeNull();
    }

    [Fact]
    public void Bundle_ShouldExposeUnderlyingBundle()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3]);

        // Assert
        manager.Bundle.Should().NotBeNull();
        manager.Bundle.IdentityKey.Should().NotBeNullOrEmpty();
        manager.Bundle.SignedPreKey.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentNullException_WhenBundleIsNull()
    {
        // Act & Assert
        FluentActions.Invoking(() => new PreKeyDistributionManager(null!))
            .Should().Throw<ArgumentNullException>()
            .WithParameterName("bundleWithPrivates");
    }

    [Fact]
    public void ConsumeKeyPair_ShouldBeThreadSafe_AndReturnValidKeyData()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager(Enumerable.Range(1, 100).ToArray());
        ConcurrentBag<(int Id, byte[] PublicKey, byte[] PrivateKey)> consumedKeys = [];

        // Act
        Parallel.For(0, 100, _ =>
        {
            (int Id, byte[] PublicKey, byte[] PrivateKey)? consumed = manager.ConsumeKeyPair();
            if (consumed.HasValue)
            {
                consumedKeys.Add(consumed.Value);
            }
        });

        // Assert - All 100 unique keys should have been consumed with valid data
        consumedKeys.Should().HaveCount(100);
        consumedKeys.Select(k => k.Id).Distinct().Should().HaveCount(100);
        manager.RemainingKeyCount.Should().Be(0);

        // Verify key data integrity - all keys should have valid lengths
        foreach ((int Id, byte[] PublicKey, byte[] PrivateKey) key in consumedKeys)
        {
            key.PublicKey.Should().NotBeNullOrEmpty("public key should not be corrupted");
            key.PrivateKey.Should().NotBeNullOrEmpty("private key should not be corrupted");
            key.PublicKey.Length.Should().BeGreaterThan(0);
            key.PrivateKey.Length.Should().BeGreaterThan(0);
        }
    }

    [Fact]
    public void ConsumeKeyPairById_ShouldReturnKeyPair_WhenKeyExists()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3]);

        // Act
        (byte[] PublicKey, byte[] PrivateKey)? consumed = manager.ConsumeKeyPairById(2);

        // Assert
        consumed.Should().NotBeNull();
        consumed!.Value.PublicKey.Should().NotBeNullOrEmpty();
        consumed.Value.PrivateKey.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ConsumeKeyPairById_ShouldReturnNull_WhenKeyDoesNotExist()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3]);

        // Act
        (byte[] PublicKey, byte[] PrivateKey)? consumed = manager.ConsumeKeyPairById(999);

        // Assert
        consumed.Should().BeNull();
    }

    [Fact]
    public void ConsumeKeyPairById_ShouldRemoveBothPublicAndPrivateKeys()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3]);
        int initialKeyCount = manager.Bundle.OneTimePreKeysCount;

        // Act
        (byte[] PublicKey, byte[] PrivateKey)? consumed = manager.ConsumeKeyPairById(2);

        // Assert
        consumed.Should().NotBeNull();
        manager.GetKeyPair(2).Should().BeNull("both keys should be removed");
        manager.Bundle.GetOneTimePreKey(2).Should().BeNull("public key should be removed");
        manager.Bundle.OneTimePreKeysCount.Should().Be(initialKeyCount - 1);
    }

    [Fact]
    public void ConsumeKeyPairById_ShouldFireKeysRunningLow_WhenBelowThreshold()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3, 4, 5]);
        manager.LowKeyThreshold = 3;

        int? reportedCount = null;
        manager.KeysRunningLow += count => reportedCount = count;

        // Act
        manager.ConsumeKeyPairById(1); // 4 remaining
        manager.ConsumeKeyPairById(2); // 3 remaining - should fire

        // Assert
        reportedCount.Should().Be(3);
    }

    [Fact]
    public void ConsumeKeyPairById_ShouldFireKeysExhausted_WhenLastKeyConsumed()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1]);

        bool exhaustedFired = false;
        manager.KeysExhausted += () => exhaustedFired = true;

        // Act
        manager.ConsumeKeyPairById(1);

        // Assert
        exhaustedFired.Should().BeTrue();
    }

    /// <summary>
    /// Tests that sequential consumption of the same key ID returns null on second attempt.
    /// Thread-safety for concurrent access is tested separately in ConsumeKeyPairById_ShouldBeThreadSafe.
    /// </summary>
    [Fact]
    public void ConsumeKeyPairById_Sequential_ShouldNotReturnSameKeyTwice()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager([1, 2, 3]);

        // Act
        (byte[] PublicKey, byte[] PrivateKey)? first = manager.ConsumeKeyPairById(2);
        (byte[] PublicKey, byte[] PrivateKey)? second = manager.ConsumeKeyPairById(2);

        // Assert
        first.Should().NotBeNull();
        second.Should().BeNull("key should not be returned twice");
    }

    [Fact]
    public void ConsumeKeyPairById_ShouldBeThreadSafe_AndReturnValidKeyData()
    {
        // Arrange
        PreKeyDistributionManager manager = CreateManager(Enumerable.Range(1, 100).ToArray());
        ConcurrentBag<(int KeyId, byte[] PublicKey, byte[] PrivateKey)> successfulConsumptions = [];
        ConcurrentBag<int> failedConsumptions = [];

        // Act
        Parallel.For(0, 100, i =>
        {
            int keyId = (i % 50) + 1; // Try keys 1-50 with duplicates
            (byte[] PublicKey, byte[] PrivateKey)? consumed = manager.ConsumeKeyPairById(keyId);
            if (consumed.HasValue)
            {
                successfulConsumptions.Add((keyId, consumed.Value.PublicKey, consumed.Value.PrivateKey));
            }
            else
            {
                failedConsumptions.Add(keyId);
            }
        });

        // Assert - Each key should only be consumed once
        successfulConsumptions.Should().HaveCount(50);
        successfulConsumptions.Select(k => k.KeyId).Distinct().Should().HaveCount(50);
        failedConsumptions.Should().HaveCount(50);

        // Verify key data integrity
        foreach ((int KeyId, byte[] PublicKey, byte[] PrivateKey) key in successfulConsumptions)
        {
            key.PublicKey.Should().NotBeNullOrEmpty("public key should not be corrupted");
            key.PrivateKey.Should().NotBeNullOrEmpty("private key should not be corrupted");
        }
    }
}
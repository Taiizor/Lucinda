// <copyright file="CryptoHelpersTests.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using FluentAssertions;
using Lucinda.Utilities;
using Xunit;

namespace Lucinda.Tests.Utilities
{
    public class CryptoHelpersTests
    {
        [Fact]
        public void ConstantTimeEquals_WithEqualArrays_ShouldReturnTrue()
        {
            // Arrange
            byte[] a = new byte[] { 1, 2, 3, 4, 5 };
            byte[] b = new byte[] { 1, 2, 3, 4, 5 };

            // Act
            bool result = CryptoHelpers.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void ConstantTimeEquals_WithDifferentArrays_ShouldReturnFalse()
        {
            // Arrange
            byte[] a = new byte[] { 1, 2, 3, 4, 5 };
            byte[] b = new byte[] { 1, 2, 3, 4, 6 };

            // Act
            bool result = CryptoHelpers.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public void ConstantTimeEquals_WithDifferentLengths_ShouldReturnFalse()
        {
            // Arrange
            byte[] a = new byte[] { 1, 2, 3 };
            byte[] b = new byte[] { 1, 2, 3, 4, 5 };

            // Act
            bool result = CryptoHelpers.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public void ToHexString_AndFromHexString_ShouldRoundTrip()
        {
            // Arrange
            byte[] original = new byte[] { 0x00, 0xFF, 0xAB, 0xCD, 0x12 };

            // Act
            string hex = CryptoHelpers.ToHexString(original);
            byte[] restored = CryptoHelpers.FromHexString(hex);

            // Assert
            restored.Should().BeEquivalentTo(original);
        }

        [Fact]
        public void ToBase64_AndFromBase64_ShouldRoundTrip()
        {
            // Arrange
            byte[] original = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

            // Act
            string base64 = CryptoHelpers.ToBase64(original);
            byte[] restored = CryptoHelpers.FromBase64(base64);

            // Assert
            restored.Should().BeEquivalentTo(original);
        }

        [Fact]
        public void GetUtf8Bytes_AndGetUtf8String_ShouldRoundTrip()
        {
            // Arrange
            string original = "Hello, World! 🌍";

            // Act
            byte[] bytes = CryptoHelpers.GetUtf8Bytes(original);
            string restored = CryptoHelpers.GetUtf8String(bytes);

            // Assert
            restored.Should().Be(original);
        }

        [Fact]
        public void Concatenate_ShouldCombineArrays()
        {
            // Arrange
            byte[] a = new byte[] { 1, 2, 3 };
            byte[] b = new byte[] { 4, 5, 6 };
            byte[] c = new byte[] { 7, 8, 9 };

            // Act
            byte[] result = CryptoHelpers.Concatenate(a, b, c);

            // Assert
            result.Should().BeEquivalentTo(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 });
        }

        [Fact]
        public void ComputeSha256_ShouldReturnCorrectHash()
        {
            // Arrange
            byte[] data = "Hello, World!"u8.ToArray();

            // Act
            byte[] hash = CryptoHelpers.ComputeSha256(data);

            // Assert
            hash.Should().HaveCount(32); // SHA-256 is 256 bits = 32 bytes
        }

        [Fact]
        public void ComputeSha384_ShouldReturnCorrectHash()
        {
            // Arrange
            byte[] data = "Hello, World!"u8.ToArray();

            // Act
            byte[] hash = CryptoHelpers.ComputeSha384(data);

            // Assert
            hash.Should().HaveCount(48); // SHA-384 is 384 bits = 48 bytes
        }

        [Fact]
        public void ComputeSha512_ShouldReturnCorrectHash()
        {
            // Arrange
            byte[] data = "Hello, World!"u8.ToArray();

            // Act
            byte[] hash = CryptoHelpers.ComputeSha512(data);

            // Assert
            hash.Should().HaveCount(64); // SHA-512 is 512 bits = 64 bytes
        }

        [Fact]
        public void ComputeHmacSha256_ShouldReturnCorrectMac()
        {
            // Arrange
            byte[] key = "secret-key"u8.ToArray();
            byte[] data = "message to authenticate"u8.ToArray();

            // Act
            byte[] mac = CryptoHelpers.ComputeHmacSha256(key, data);

            // Assert
            mac.Should().HaveCount(32); // HMAC-SHA256 is 256 bits = 32 bytes
        }

        [Fact]
        public void ComputeHmacSha256_SameInputs_ShouldProduceSameMac()
        {
            // Arrange
            byte[] key = "secret-key"u8.ToArray();
            byte[] data = "message"u8.ToArray();

            // Act
            byte[] mac1 = CryptoHelpers.ComputeHmacSha256(key, data);
            byte[] mac2 = CryptoHelpers.ComputeHmacSha256(key, data);

            // Assert
            mac1.Should().BeEquivalentTo(mac2);
        }

        [Fact]
        public void SecureClear_ShouldZeroOutArray()
        {
            // Arrange
            byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            // Act
            CryptoHelpers.SecureClear(data);

            // Assert
            data.Should().OnlyContain(b => b == 0);
        }
    }
}
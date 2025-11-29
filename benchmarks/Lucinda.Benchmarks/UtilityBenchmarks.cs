// <copyright file="UtilityBenchmarks.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Order;

using Lucinda.Utilities;

namespace Lucinda.Benchmarks
{
    /// <summary>
    /// Benchmarks for cryptographic utility operations (hashing, HMAC, random generation).
    /// </summary>
    [RankColumn]
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 3, iterationCount: 5)]
    public class UtilityBenchmarks
    {
        private byte[] _smallData = null!;
        private byte[] _mediumData = null!;
        private byte[] _largeData = null!;
        private byte[] _key = null!;

        /// <summary>
        /// Setup benchmark data.
        /// </summary>
        [GlobalSetup]
        public void Setup()
        {
            // Generate test data
            _smallData = new byte[256];
            _mediumData = new byte[1024 * 10]; // 10 KB
            _largeData = new byte[1024 * 100]; // 100 KB
            _key = new byte[32]; // 256-bit key

            Random.Shared.NextBytes(_smallData);
            Random.Shared.NextBytes(_mediumData);
            Random.Shared.NextBytes(_largeData);
            Random.Shared.NextBytes(_key);
        }

        // ==================== Hashing Benchmarks ====================

        /// <summary>
        /// Benchmark SHA-256 hashing of 256 bytes data.
        /// </summary>
        [Benchmark(Baseline = true, Description = "SHA-256 Hash 256B")]
        public byte[] Sha256_256B()
        {
            return CryptoHelpers.ComputeSha256(_smallData);
        }

        /// <summary>
        /// Benchmark SHA-256 hashing of 10 KB data.
        /// </summary>
        [Benchmark(Description = "SHA-256 Hash 10KB")]
        public byte[] Sha256_10KB()
        {
            return CryptoHelpers.ComputeSha256(_mediumData);
        }

        /// <summary>
        /// Benchmark SHA-256 hashing of 100 KB data.
        /// </summary>
        [Benchmark(Description = "SHA-256 Hash 100KB")]
        public byte[] Sha256_100KB()
        {
            return CryptoHelpers.ComputeSha256(_largeData);
        }

        /// <summary>
        /// Benchmark SHA-512 hashing of 256 bytes data.
        /// </summary>
        [Benchmark(Description = "SHA-512 Hash 256B")]
        public byte[] Sha512_256B()
        {
            return CryptoHelpers.ComputeSha512(_smallData);
        }

        /// <summary>
        /// Benchmark SHA-512 hashing of 10 KB data.
        /// </summary>
        [Benchmark(Description = "SHA-512 Hash 10KB")]
        public byte[] Sha512_10KB()
        {
            return CryptoHelpers.ComputeSha512(_mediumData);
        }

        // ==================== HMAC Benchmarks ====================

        /// <summary>
        /// Benchmark HMAC-SHA256 of 256 bytes data.
        /// </summary>
        [Benchmark(Description = "HMAC-SHA256 256B")]
        public byte[] HmacSha256_256B()
        {
            return CryptoHelpers.ComputeHmacSha256(_key, _smallData);
        }

        /// <summary>
        /// Benchmark HMAC-SHA256 of 10 KB data.
        /// </summary>
        [Benchmark(Description = "HMAC-SHA256 10KB")]
        public byte[] HmacSha256_10KB()
        {
            return CryptoHelpers.ComputeHmacSha256(_key, _mediumData);
        }

        /// <summary>
        /// Benchmark HMAC-SHA512 of 256 bytes data.
        /// </summary>
        [Benchmark(Description = "HMAC-SHA512 256B")]
        public byte[] HmacSha512_256B()
        {
            return CryptoHelpers.ComputeHmacSha512(_key, _smallData);
        }

        // ==================== Random Generation Benchmarks ====================

        /// <summary>
        /// Benchmark secure random key generation (128-bit).
        /// </summary>
        [Benchmark(Description = "SecureRandom Key 128-bit")]
        public byte[] SecureRandom_Key_128()
        {
            return SecureRandom.GenerateKey(128);
        }

        /// <summary>
        /// Benchmark secure random key generation (256-bit).
        /// </summary>
        [Benchmark(Description = "SecureRandom Key 256-bit")]
        public byte[] SecureRandom_Key_256()
        {
            return SecureRandom.GenerateKey(256);
        }

        /// <summary>
        /// Benchmark secure random salt generation (16 bytes).
        /// </summary>
        [Benchmark(Description = "SecureRandom Salt 16B")]
        public byte[] SecureRandom_Salt_16B()
        {
            return SecureRandom.GenerateSalt(16);
        }

        /// <summary>
        /// Benchmark secure random salt generation (32 bytes).
        /// </summary>
        [Benchmark(Description = "SecureRandom Salt 32B")]
        public byte[] SecureRandom_Salt_32B()
        {
            return SecureRandom.GenerateSalt(32);
        }

        /// <summary>
        /// Benchmark secure random nonce generation (12 bytes for GCM).
        /// </summary>
        [Benchmark(Description = "SecureRandom Nonce 12B")]
        public byte[] SecureRandom_Nonce_12B()
        {
            return SecureRandom.GenerateNonce(12);
        }

        // ==================== Constant-Time Comparison Benchmark ====================

        /// <summary>
        /// Benchmark constant-time comparison of 32 byte arrays.
        /// </summary>
        [Benchmark(Description = "ConstantTime Compare 32B")]
        public bool ConstantTimeEquals_32B()
        {
            return CryptoHelpers.ConstantTimeEquals(_key, _key);
        }

        // ==================== Encoding Benchmarks ====================

        /// <summary>
        /// Benchmark Base64 encoding of 256 bytes data.
        /// </summary>
        [Benchmark(Description = "Base64 Encode 256B")]
        public string Base64Encode_256B()
        {
            return CryptoHelpers.ToBase64(_smallData);
        }

        /// <summary>
        /// Benchmark Hex encoding of 256 bytes data.
        /// </summary>
        [Benchmark(Description = "Hex Encode 256B")]
        public string HexEncode_256B()
        {
            return CryptoHelpers.ToHexString(_smallData);
        }
    }
}
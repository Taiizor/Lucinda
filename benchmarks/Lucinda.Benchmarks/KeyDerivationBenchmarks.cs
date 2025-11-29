// <copyright file="KeyDerivationBenchmarks.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Order;

using Lucinda.KeyDerivation;

using System.Security.Cryptography;

namespace Lucinda.Benchmarks
{
    /// <summary>
    /// Benchmarks for key derivation operations (PBKDF2 and HKDF).
    /// </summary>
    [RankColumn]
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 2, iterationCount: 5)]
    public class KeyDerivationBenchmarks
    {
        private const string TestPassword = "SecurePassword123!@#";
        private byte[] _salt = null!;
        private byte[] _inputKeyMaterial = null!;
        private byte[] _info = null!;
        private Pbkdf2KeyDerivation _pbkdf2Sha256 = null!;
        private Pbkdf2KeyDerivation _pbkdf2Sha512 = null!;
        private HkdfKeyDerivation _hkdfSha256 = null!;
        private HkdfKeyDerivation _hkdfSha512 = null!;

        /// <summary>
        /// Setup benchmark data and key derivation instances.
        /// </summary>
        [GlobalSetup]
        public void Setup()
        {
            // Generate salt and input key material
            _salt = new byte[32];
            _inputKeyMaterial = new byte[32];
            _info = new byte[16];

            Random.Shared.NextBytes(_salt);
            Random.Shared.NextBytes(_inputKeyMaterial);
            Random.Shared.NextBytes(_info);

            // Initialize key derivation instances
            _pbkdf2Sha256 = new Pbkdf2KeyDerivation(HashAlgorithmName.SHA256);
            _pbkdf2Sha512 = new Pbkdf2KeyDerivation(HashAlgorithmName.SHA512);
            _hkdfSha256 = new HkdfKeyDerivation(HashAlgorithmName.SHA256);
            _hkdfSha512 = new HkdfKeyDerivation(HashAlgorithmName.SHA512);
        }

        /// <summary>
        /// Cleanup benchmark resources.
        /// </summary>
        [GlobalCleanup]
        public void Cleanup()
        {
            _pbkdf2Sha256?.Dispose();
            _pbkdf2Sha512?.Dispose();
            _hkdfSha256?.Dispose();
            _hkdfSha512?.Dispose();
        }

        // ==================== PBKDF2 Benchmarks ====================

        /// <summary>
        /// Benchmark PBKDF2-SHA256 with 10,000 iterations (fast but less secure).
        /// </summary>
        [Benchmark(Baseline = true, Description = "PBKDF2-SHA256 10K iterations")]
        public byte[] Pbkdf2Sha256_10K_Iterations()
        {
            return _pbkdf2Sha256.DeriveKey(TestPassword, _salt, 10000, 32).Value;
        }

        /// <summary>
        /// Benchmark PBKDF2-SHA256 with 100,000 iterations (minimum recommended).
        /// </summary>
        [Benchmark(Description = "PBKDF2-SHA256 100K iterations")]
        public byte[] Pbkdf2Sha256_100K_Iterations()
        {
            return _pbkdf2Sha256.DeriveKey(TestPassword, _salt, 100000, 32).Value;
        }

        /// <summary>
        /// Benchmark PBKDF2-SHA256 with 600,000 iterations (high security).
        /// </summary>
        [Benchmark(Description = "PBKDF2-SHA256 600K iterations")]
        public byte[] Pbkdf2Sha256_600K_Iterations()
        {
            return _pbkdf2Sha256.DeriveKey(TestPassword, _salt, 600000, 32).Value;
        }

        /// <summary>
        /// Benchmark PBKDF2-SHA512 with 100,000 iterations.
        /// </summary>
        [Benchmark(Description = "PBKDF2-SHA512 100K iterations")]
        public byte[] Pbkdf2Sha512_100K_Iterations()
        {
            return _pbkdf2Sha512.DeriveKey(TestPassword, _salt, 100000, 32).Value;
        }

        /// <summary>
        /// Benchmark PBKDF2 salt generation (32 bytes).
        /// </summary>
        [Benchmark(Description = "PBKDF2 Salt Generation 32B")]
        public byte[] Pbkdf2SaltGeneration()
        {
            return _pbkdf2Sha256.GenerateSalt(32).Value;
        }

        // ==================== HKDF Benchmarks ====================

        /// <summary>
        /// Benchmark HKDF-SHA256 key derivation (32 bytes output).
        /// </summary>
        [Benchmark(Description = "HKDF-SHA256 Derive 32B")]
        public byte[] HkdfSha256_Derive_32B()
        {
            return _hkdfSha256.DeriveKey(_inputKeyMaterial, _salt, _info, 32).Value;
        }

        /// <summary>
        /// Benchmark HKDF-SHA256 key derivation (64 bytes output).
        /// </summary>
        [Benchmark(Description = "HKDF-SHA256 Derive 64B")]
        public byte[] HkdfSha256_Derive_64B()
        {
            return _hkdfSha256.DeriveKey(_inputKeyMaterial, _salt, _info, 64).Value;
        }

        /// <summary>
        /// Benchmark HKDF-SHA256 key derivation (128 bytes output).
        /// </summary>
        [Benchmark(Description = "HKDF-SHA256 Derive 128B")]
        public byte[] HkdfSha256_Derive_128B()
        {
            return _hkdfSha256.DeriveKey(_inputKeyMaterial, _salt, _info, 128).Value;
        }

        /// <summary>
        /// Benchmark HKDF-SHA512 key derivation (32 bytes output).
        /// </summary>
        [Benchmark(Description = "HKDF-SHA512 Derive 32B")]
        public byte[] HkdfSha512_Derive_32B()
        {
            return _hkdfSha512.DeriveKey(_inputKeyMaterial, _salt, _info, 32).Value;
        }

        /// <summary>
        /// Benchmark HKDF-SHA256 Extract operation.
        /// </summary>
        [Benchmark(Description = "HKDF-SHA256 Extract")]
        public byte[] HkdfSha256_Extract()
        {
            return _hkdfSha256.Extract(_salt, _inputKeyMaterial).Value;
        }

        /// <summary>
        /// Benchmark HKDF-SHA256 Expand operation.
        /// </summary>
        [Benchmark(Description = "HKDF-SHA256 Expand 32B")]
        public byte[] HkdfSha256_Expand()
        {
            byte[] prk = _hkdfSha256.Extract(_salt, _inputKeyMaterial).Value;
            return _hkdfSha256.Expand(prk, _info, 32).Value;
        }
    }
}
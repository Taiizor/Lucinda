// <copyright file="SymmetricEncryptionBenchmarks.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Order;

using Lucinda.Symmetric;

namespace Lucinda.Benchmarks
{
    /// <summary>
    /// Benchmarks for symmetric encryption operations (AES-GCM and AES-CBC).
    /// </summary>
    [RankColumn]
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 3, iterationCount: 5)]
    public class SymmetricEncryptionBenchmarks
    {
        private byte[] _smallData = null!;
        private byte[] _mediumData = null!;
        private byte[] _largeData = null!;
        private byte[] _aad = null!;
        private AesGcmEncryption _aesGcm256 = null!;
        private AesGcmEncryption _aesGcm128 = null!;
        private AesCbcEncryption _aesCbc256 = null!;
        private AesCbcEncryption _aesCbc256NoHmac = null!;
        private byte[] _encryptedSmallGcm = null!;
        private byte[] _encryptedMediumGcm = null!;
        private byte[] _encryptedLargeGcm = null!;
        private byte[] _encryptedSmallCbc = null!;

        /// <summary>
        /// Setup benchmark data and encryption instances.
        /// </summary>
        [GlobalSetup]
        public void Setup()
        {
            // Generate test data of various sizes
            _smallData = new byte[1024]; // 1 KB
            _mediumData = new byte[1024 * 100]; // 100 KB
            _largeData = new byte[1024 * 1024]; // 1 MB
            _aad = new byte[64]; // Additional authenticated data

            Random.Shared.NextBytes(_smallData);
            Random.Shared.NextBytes(_mediumData);
            Random.Shared.NextBytes(_largeData);
            Random.Shared.NextBytes(_aad);

            // Initialize encryption instances
            _aesGcm256 = new AesGcmEncryption(256);
            _aesGcm128 = new AesGcmEncryption(128);
            _aesCbc256 = new AesCbcEncryption(256, useHmac: true);
            _aesCbc256NoHmac = new AesCbcEncryption(256, useHmac: false);

            // Pre-encrypt data for decryption benchmarks
            _encryptedSmallGcm = _aesGcm256.Encrypt(_smallData).Value;
            _encryptedMediumGcm = _aesGcm256.Encrypt(_mediumData).Value;
            _encryptedLargeGcm = _aesGcm256.Encrypt(_largeData).Value;
            _encryptedSmallCbc = _aesCbc256.Encrypt(_smallData).Value;
        }

        /// <summary>
        /// Cleanup benchmark resources.
        /// </summary>
        [GlobalCleanup]
        public void Cleanup()
        {
            _aesGcm256?.Dispose();
            _aesGcm128?.Dispose();
            _aesCbc256?.Dispose();
            _aesCbc256NoHmac?.Dispose();
        }

        // ==================== AES-GCM Encryption Benchmarks ====================

        /// <summary>
        /// Benchmark AES-256-GCM encryption of 1 KB data.
        /// </summary>
        [Benchmark(Baseline = true, Description = "AES-256-GCM Encrypt 1KB")]
        public byte[] AesGcm256_Encrypt_1KB()
        {
            return _aesGcm256.Encrypt(_smallData).Value;
        }

        /// <summary>
        /// Benchmark AES-256-GCM encryption of 100 KB data.
        /// </summary>
        [Benchmark(Description = "AES-256-GCM Encrypt 100KB")]
        public byte[] AesGcm256_Encrypt_100KB()
        {
            return _aesGcm256.Encrypt(_mediumData).Value;
        }

        /// <summary>
        /// Benchmark AES-256-GCM encryption of 1 MB data.
        /// </summary>
        [Benchmark(Description = "AES-256-GCM Encrypt 1MB")]
        public byte[] AesGcm256_Encrypt_1MB()
        {
            return _aesGcm256.Encrypt(_largeData).Value;
        }

        /// <summary>
        /// Benchmark AES-128-GCM encryption of 1 KB data.
        /// </summary>
        [Benchmark(Description = "AES-128-GCM Encrypt 1KB")]
        public byte[] AesGcm128_Encrypt_1KB()
        {
            return _aesGcm128.Encrypt(_smallData).Value;
        }

        /// <summary>
        /// Benchmark AES-256-GCM encryption with AAD.
        /// </summary>
        [Benchmark(Description = "AES-256-GCM Encrypt 1KB with AAD")]
        public byte[] AesGcm256_Encrypt_1KB_WithAAD()
        {
            return _aesGcm256.Encrypt(_smallData, _aad).Value;
        }

        // ==================== AES-GCM Decryption Benchmarks ====================

        /// <summary>
        /// Benchmark AES-256-GCM decryption of 1 KB data.
        /// </summary>
        [Benchmark(Description = "AES-256-GCM Decrypt 1KB")]
        public byte[] AesGcm256_Decrypt_1KB()
        {
            return _aesGcm256.Decrypt(_encryptedSmallGcm).Value;
        }

        /// <summary>
        /// Benchmark AES-256-GCM decryption of 100 KB data.
        /// </summary>
        [Benchmark(Description = "AES-256-GCM Decrypt 100KB")]
        public byte[] AesGcm256_Decrypt_100KB()
        {
            return _aesGcm256.Decrypt(_encryptedMediumGcm).Value;
        }

        /// <summary>
        /// Benchmark AES-256-GCM decryption of 1 MB data.
        /// </summary>
        [Benchmark(Description = "AES-256-GCM Decrypt 1MB")]
        public byte[] AesGcm256_Decrypt_1MB()
        {
            return _aesGcm256.Decrypt(_encryptedLargeGcm).Value;
        }

        // ==================== AES-CBC Benchmarks ====================

        /// <summary>
        /// Benchmark AES-256-CBC-HMAC encryption of 1 KB data.
        /// </summary>
        [Benchmark(Description = "AES-256-CBC-HMAC Encrypt 1KB")]
        public byte[] AesCbc256Hmac_Encrypt_1KB()
        {
            return _aesCbc256.Encrypt(_smallData).Value;
        }

        /// <summary>
        /// Benchmark AES-256-CBC (without HMAC) encryption of 1 KB data.
        /// </summary>
        [Benchmark(Description = "AES-256-CBC Encrypt 1KB (No HMAC)")]
        public byte[] AesCbc256_Encrypt_1KB_NoHmac()
        {
            return _aesCbc256NoHmac.Encrypt(_smallData).Value;
        }

        /// <summary>
        /// Benchmark AES-256-CBC-HMAC decryption of 1 KB data.
        /// </summary>
        [Benchmark(Description = "AES-256-CBC-HMAC Decrypt 1KB")]
        public byte[] AesCbc256Hmac_Decrypt_1KB()
        {
            return _aesCbc256.Decrypt(_encryptedSmallCbc).Value;
        }

        // ==================== Key Generation Benchmarks ====================

        /// <summary>
        /// Benchmark AES key generation.
        /// </summary>
        [Benchmark(Description = "AES-256 Key Generation")]
        public byte[] AesKeyGeneration()
        {
            return _aesGcm256.GenerateKey().Value;
        }

        /// <summary>
        /// Benchmark AES IV/Nonce generation.
        /// </summary>
        [Benchmark(Description = "AES-GCM Nonce Generation")]
        public byte[] AesNonceGeneration()
        {
            return _aesGcm256.GenerateIV().Value;
        }
    }
}
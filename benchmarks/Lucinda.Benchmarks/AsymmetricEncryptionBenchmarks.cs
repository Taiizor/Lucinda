// <copyright file="AsymmetricEncryptionBenchmarks.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Order;

using Lucinda.Abstractions;
using Lucinda.Asymmetric;

namespace Lucinda.Benchmarks
{
    /// <summary>
    /// Benchmarks for asymmetric encryption operations (RSA and RSA-AES Hybrid).
    /// </summary>
    [RankColumn]
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 2, iterationCount: 5)]
    public class AsymmetricEncryptionBenchmarks
    {
        private byte[] _smallData = null!;
        private byte[] _mediumData = null!;
        private byte[] _largeData = null!;
        private RsaEncryption _rsa2048 = null!;
        private RsaEncryption _rsa3072 = null!;
        private RsaEncryption _rsa4096 = null!;
        private RsaAesHybridEncryption _hybrid2048 = null!;
        private RsaAesHybridEncryption _hybrid4096 = null!;
        private byte[] _recipientPublicKey2048 = null!;
        private byte[] _recipientPrivateKey2048 = null!;
        private byte[] _recipientPublicKey4096 = null!;
        private byte[] _recipientPrivateKey4096 = null!;
        private byte[] _encryptedSmallRsa2048 = null!;
        private HybridEncryptedData _encryptedMediumHybrid = null!;
        private HybridEncryptedData _encryptedLargeHybrid = null!;

        /// <summary>
        /// Setup benchmark data and encryption instances.
        /// </summary>
        [GlobalSetup]
        public void Setup()
        {
            // Generate test data
            _smallData = new byte[128]; // 128 bytes (max for RSA-2048 with OAEP-SHA256 is 190 bytes)
            _mediumData = new byte[1024 * 10]; // 10 KB
            _largeData = new byte[1024 * 100]; // 100 KB

            Random.Shared.NextBytes(_smallData);
            Random.Shared.NextBytes(_mediumData);
            Random.Shared.NextBytes(_largeData);

            // Initialize RSA encryption instances
            _rsa2048 = new RsaEncryption(2048);
            _rsa3072 = new RsaEncryption(3072);
            _rsa4096 = new RsaEncryption(4096);

            // Initialize Hybrid encryption instances
            _hybrid2048 = new RsaAesHybridEncryption(2048, 256);
            _hybrid4096 = new RsaAesHybridEncryption(4096, 256);

            // Generate key pairs for hybrid encryption
            AsymmetricKeyPair keyPair2048 = _hybrid2048.GenerateKeyPair().Value;
            _recipientPublicKey2048 = keyPair2048.PublicKey;
            _recipientPrivateKey2048 = keyPair2048.PrivateKey;

            AsymmetricKeyPair keyPair4096 = _hybrid4096.GenerateKeyPair().Value;
            _recipientPublicKey4096 = keyPair4096.PublicKey;
            _recipientPrivateKey4096 = keyPair4096.PrivateKey;

            // Pre-encrypt data for decryption benchmarks
            _encryptedSmallRsa2048 = _rsa2048.Encrypt(_smallData).Value;
            _encryptedMediumHybrid = _hybrid2048.Encrypt(_mediumData, _recipientPublicKey2048).Value;
            _encryptedLargeHybrid = _hybrid2048.Encrypt(_largeData, _recipientPublicKey2048).Value;
        }

        /// <summary>
        /// Cleanup benchmark resources.
        /// </summary>
        [GlobalCleanup]
        public void Cleanup()
        {
            _rsa2048?.Dispose();
            _rsa3072?.Dispose();
            _rsa4096?.Dispose();
            _hybrid2048?.Dispose();
            _hybrid4096?.Dispose();
        }

        // ==================== RSA Key Generation Benchmarks ====================

        /// <summary>
        /// Benchmark RSA-2048 key pair generation.
        /// </summary>
        [Benchmark(Baseline = true, Description = "RSA-2048 Key Generation")]
        public AsymmetricKeyPair RsaKeyGeneration_2048()
        {
            return _rsa2048.GenerateKeyPair().Value;
        }

        /// <summary>
        /// Benchmark RSA-3072 key pair generation.
        /// </summary>
        [Benchmark(Description = "RSA-3072 Key Generation")]
        public AsymmetricKeyPair RsaKeyGeneration_3072()
        {
            return _rsa3072.GenerateKeyPair().Value;
        }

        /// <summary>
        /// Benchmark RSA-4096 key pair generation.
        /// </summary>
        [Benchmark(Description = "RSA-4096 Key Generation")]
        public AsymmetricKeyPair RsaKeyGeneration_4096()
        {
            return _rsa4096.GenerateKeyPair().Value;
        }

        // ==================== RSA Encryption Benchmarks ====================

        /// <summary>
        /// Benchmark RSA-2048 encryption of small data.
        /// </summary>
        [Benchmark(Description = "RSA-2048 Encrypt 128B")]
        public byte[] Rsa2048_Encrypt()
        {
            return _rsa2048.Encrypt(_smallData).Value;
        }

        /// <summary>
        /// Benchmark RSA-4096 encryption of small data.
        /// </summary>
        [Benchmark(Description = "RSA-4096 Encrypt 128B")]
        public byte[] Rsa4096_Encrypt()
        {
            return _rsa4096.Encrypt(_smallData).Value;
        }

        /// <summary>
        /// Benchmark RSA-2048 decryption of small data.
        /// </summary>
        [Benchmark(Description = "RSA-2048 Decrypt 128B")]
        public byte[] Rsa2048_Decrypt()
        {
            return _rsa2048.Decrypt(_encryptedSmallRsa2048).Value;
        }

        // ==================== Hybrid Encryption Benchmarks ====================

        /// <summary>
        /// Benchmark RSA-2048 + AES-256 hybrid encryption of 10 KB data.
        /// </summary>
        [Benchmark(Description = "Hybrid RSA-2048+AES-256 Encrypt 10KB")]
        public HybridEncryptedData Hybrid2048_Encrypt_10KB()
        {
            return _hybrid2048.Encrypt(_mediumData, _recipientPublicKey2048).Value;
        }

        /// <summary>
        /// Benchmark RSA-2048 + AES-256 hybrid encryption of 100 KB data.
        /// </summary>
        [Benchmark(Description = "Hybrid RSA-2048+AES-256 Encrypt 100KB")]
        public HybridEncryptedData Hybrid2048_Encrypt_100KB()
        {
            return _hybrid2048.Encrypt(_largeData, _recipientPublicKey2048).Value;
        }

        /// <summary>
        /// Benchmark RSA-4096 + AES-256 hybrid encryption of 10 KB data.
        /// </summary>
        [Benchmark(Description = "Hybrid RSA-4096+AES-256 Encrypt 10KB")]
        public HybridEncryptedData Hybrid4096_Encrypt_10KB()
        {
            return _hybrid4096.Encrypt(_mediumData, _recipientPublicKey4096).Value;
        }

        /// <summary>
        /// Benchmark RSA-2048 + AES-256 hybrid decryption of 10 KB data.
        /// </summary>
        [Benchmark(Description = "Hybrid RSA-2048+AES-256 Decrypt 10KB")]
        public byte[] Hybrid2048_Decrypt_10KB()
        {
            return _hybrid2048.Decrypt(_encryptedMediumHybrid, _recipientPrivateKey2048).Value;
        }

        /// <summary>
        /// Benchmark RSA-2048 + AES-256 hybrid decryption of 100 KB data.
        /// </summary>
        [Benchmark(Description = "Hybrid RSA-2048+AES-256 Decrypt 100KB")]
        public byte[] Hybrid2048_Decrypt_100KB()
        {
            return _hybrid2048.Decrypt(_encryptedLargeHybrid, _recipientPrivateKey2048).Value;
        }
    }
}
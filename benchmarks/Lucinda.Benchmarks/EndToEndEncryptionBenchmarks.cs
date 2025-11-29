// <copyright file="EndToEndEncryptionBenchmarks.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Order;

using Lucinda.Abstractions;

namespace Lucinda.Benchmarks
{
    /// <summary>
    /// Benchmarks for high-level end-to-end encryption operations.
    /// </summary>
    [RankColumn]
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 2, iterationCount: 5)]
    public class EndToEndEncryptionBenchmarks
    {
        private const string TestMessage = "Hello, this is a test message for E2EE benchmarking!";
        private EndToEndEncryption _e2ee = null!;
        private byte[] _recipientPublicKey = null!;
        private byte[] _recipientPrivateKey = null!;
        private byte[] _senderSigningPrivateKey = null!;
        private byte[] _senderSigningPublicKey = null!;
        private byte[] _smallData = null!;
        private byte[] _mediumData = null!;
        private byte[] _largeData = null!;
        private byte[] _encryptedSmall = null!;
        private byte[] _encryptedMedium = null!;
        private byte[] _encryptedLarge = null!;
        private SignedEncryptedData _signedEncrypted = null!;

        /// <summary>
        /// Setup benchmark data and E2EE instances.
        /// </summary>
        [GlobalSetup]
        public void Setup()
        {
            // Initialize E2EE instance with signatures enabled
            _e2ee = new EndToEndEncryption(new EndToEndEncryptionOptions
            {
                EnableSignatures = true
            });

            // Generate key pairs
            AsymmetricKeyPair encryptionKeyPair = _e2ee.GenerateKeyPair().Value;
            _recipientPublicKey = encryptionKeyPair.PublicKey;
            _recipientPrivateKey = encryptionKeyPair.PrivateKey;

            AsymmetricKeyPair signingKeyPair = _e2ee.GenerateSigningKeyPair().Value;
            _senderSigningPrivateKey = signingKeyPair.PrivateKey;
            _senderSigningPublicKey = signingKeyPair.PublicKey;

            // Generate test data
            _smallData = new byte[1024]; // 1 KB
            _mediumData = new byte[1024 * 10]; // 10 KB
            _largeData = new byte[1024 * 100]; // 100 KB

            Random.Shared.NextBytes(_smallData);
            Random.Shared.NextBytes(_mediumData);
            Random.Shared.NextBytes(_largeData);

            // Pre-encrypt data for decryption benchmarks
            _encryptedSmall = _e2ee.EncryptData(_smallData, _recipientPublicKey).Value;
            _encryptedMedium = _e2ee.EncryptData(_mediumData, _recipientPublicKey).Value;
            _encryptedLarge = _e2ee.EncryptData(_largeData, _recipientPublicKey).Value;

            // Pre-encrypt and sign data for verify and decrypt benchmark
            _signedEncrypted = _e2ee.EncryptAndSign(_smallData, _recipientPublicKey, _senderSigningPrivateKey).Value;
        }

        /// <summary>
        /// Cleanup benchmark resources.
        /// </summary>
        [GlobalCleanup]
        public void Cleanup()
        {
            _e2ee?.Dispose();
        }

        // ==================== Key Generation Benchmarks ====================

        /// <summary>
        /// Benchmark E2EE encryption key pair generation.
        /// </summary>
        [Benchmark(Baseline = true, Description = "E2EE Key Pair Generation")]
        public AsymmetricKeyPair E2EE_KeyPairGeneration()
        {
            return _e2ee.GenerateKeyPair().Value;
        }

        /// <summary>
        /// Benchmark E2EE signing key pair generation.
        /// </summary>
        [Benchmark(Description = "E2EE Signing Key Pair Generation")]
        public AsymmetricKeyPair E2EE_SigningKeyPairGeneration()
        {
            return _e2ee.GenerateSigningKeyPair().Value;
        }

        // ==================== Message Encryption Benchmarks ====================

        /// <summary>
        /// Benchmark E2EE message encryption (string message).
        /// </summary>
        [Benchmark(Description = "E2EE Encrypt String Message")]
        public byte[] E2EE_EncryptMessage()
        {
            return _e2ee.EncryptMessage(TestMessage, _recipientPublicKey).Value;
        }

        /// <summary>
        /// Benchmark E2EE data encryption (1 KB).
        /// </summary>
        [Benchmark(Description = "E2EE Encrypt 1KB")]
        public byte[] E2EE_EncryptData_1KB()
        {
            return _e2ee.EncryptData(_smallData, _recipientPublicKey).Value;
        }

        /// <summary>
        /// Benchmark E2EE data encryption (10 KB).
        /// </summary>
        [Benchmark(Description = "E2EE Encrypt 10KB")]
        public byte[] E2EE_EncryptData_10KB()
        {
            return _e2ee.EncryptData(_mediumData, _recipientPublicKey).Value;
        }

        /// <summary>
        /// Benchmark E2EE data encryption (100 KB).
        /// </summary>
        [Benchmark(Description = "E2EE Encrypt 100KB")]
        public byte[] E2EE_EncryptData_100KB()
        {
            return _e2ee.EncryptData(_largeData, _recipientPublicKey).Value;
        }

        // ==================== Message Decryption Benchmarks ====================

        /// <summary>
        /// Benchmark E2EE data decryption (1 KB).
        /// </summary>
        [Benchmark(Description = "E2EE Decrypt 1KB")]
        public byte[] E2EE_DecryptData_1KB()
        {
            return _e2ee.DecryptData(_encryptedSmall, _recipientPrivateKey).Value;
        }

        /// <summary>
        /// Benchmark E2EE data decryption (10 KB).
        /// </summary>
        [Benchmark(Description = "E2EE Decrypt 10KB")]
        public byte[] E2EE_DecryptData_10KB()
        {
            return _e2ee.DecryptData(_encryptedMedium, _recipientPrivateKey).Value;
        }

        /// <summary>
        /// Benchmark E2EE data decryption (100 KB).
        /// </summary>
        [Benchmark(Description = "E2EE Decrypt 100KB")]
        public byte[] E2EE_DecryptData_100KB()
        {
            return _e2ee.DecryptData(_encryptedLarge, _recipientPrivateKey).Value;
        }

        // ==================== Sign & Encrypt Benchmarks ====================

        /// <summary>
        /// Benchmark E2EE encrypt and sign (1 KB).
        /// </summary>
        [Benchmark(Description = "E2EE Encrypt & Sign 1KB")]
        public SignedEncryptedData E2EE_EncryptAndSign_1KB()
        {
            return _e2ee.EncryptAndSign(_smallData, _recipientPublicKey, _senderSigningPrivateKey).Value;
        }

        /// <summary>
        /// Benchmark E2EE verify and decrypt (1 KB).
        /// </summary>
        [Benchmark(Description = "E2EE Verify & Decrypt 1KB")]
        public byte[] E2EE_VerifyAndDecrypt_1KB()
        {
            return _e2ee.VerifyAndDecrypt(_signedEncrypted, _recipientPrivateKey, _senderSigningPublicKey).Value;
        }

        // ==================== Password Key Derivation Benchmark ====================

        /// <summary>
        /// Benchmark E2EE password-based key derivation.
        /// </summary>
        [Benchmark(Description = "E2EE Derive Key from Password")]
        public (byte[] Key, byte[] Salt) E2EE_DeriveKeyFromPassword()
        {
            return _e2ee.DeriveKeyFromPassword("SecurePassword123!").Value;
        }
    }
}
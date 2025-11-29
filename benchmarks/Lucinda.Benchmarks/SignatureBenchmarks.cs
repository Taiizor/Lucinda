// <copyright file="SignatureBenchmarks.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Order;

using Lucinda.Abstractions;
using Lucinda.Signatures;

using System.Security.Cryptography;

namespace Lucinda.Benchmarks
{
    /// <summary>
    /// Benchmarks for digital signature operations (ECDSA and RSA-PSS).
    /// </summary>
    [RankColumn]
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 2, iterationCount: 5)]
    public class SignatureBenchmarks
    {
        private byte[] _smallData = null!;
        private byte[] _mediumData = null!;
        private byte[] _largeData = null!;
        private byte[] _dataHash = null!;
        private EcdsaSignature _ecdsaP256 = null!;
        private EcdsaSignature _ecdsaP384 = null!;
        private EcdsaSignature _ecdsaP521 = null!;
        private RsaSignature _rsaPss2048 = null!;
        private RsaSignature _rsaPss4096 = null!;
        private byte[] _ecdsaP256Signature = null!;
        private byte[] _ecdsaP384Signature = null!;
        private byte[] _rsaPss2048Signature = null!;

        /// <summary>
        /// Setup benchmark data and signature instances.
        /// </summary>
        [GlobalSetup]
        public void Setup()
        {
            // Generate test data
            _smallData = new byte[256];
            _mediumData = new byte[1024 * 10]; // 10 KB
            _largeData = new byte[1024 * 100]; // 100 KB

            Random.Shared.NextBytes(_smallData);
            Random.Shared.NextBytes(_mediumData);
            Random.Shared.NextBytes(_largeData);

            // Pre-compute hash for hash-based signature benchmarks
            _dataHash = SHA256.HashData(_smallData);

            // Initialize ECDSA signature instances
            _ecdsaP256 = new EcdsaSignature(ECCurve.NamedCurves.nistP256);
            _ecdsaP384 = new EcdsaSignature(ECCurve.NamedCurves.nistP384);
            _ecdsaP521 = new EcdsaSignature(ECCurve.NamedCurves.nistP521);

            // Initialize RSA-PSS signature instances
            _rsaPss2048 = new RsaSignature(2048);
            _rsaPss4096 = new RsaSignature(4096);

            // Pre-sign data for verification benchmarks
            _ecdsaP256Signature = _ecdsaP256.Sign(_smallData).Value;
            _ecdsaP384Signature = _ecdsaP384.Sign(_smallData).Value;
            _rsaPss2048Signature = _rsaPss2048.Sign(_smallData).Value;
        }

        /// <summary>
        /// Cleanup benchmark resources.
        /// </summary>
        [GlobalCleanup]
        public void Cleanup()
        {
            _ecdsaP256?.Dispose();
            _ecdsaP384?.Dispose();
            _ecdsaP521?.Dispose();
            _rsaPss2048?.Dispose();
            _rsaPss4096?.Dispose();
        }

        // ==================== ECDSA Key Generation Benchmarks ====================

        /// <summary>
        /// Benchmark ECDSA P-256 key pair generation.
        /// </summary>
        [Benchmark(Baseline = true, Description = "ECDSA P-256 Key Generation")]
        public AsymmetricKeyPair EcdsaP256_KeyGeneration()
        {
            return _ecdsaP256.GenerateKeyPair().Value;
        }

        /// <summary>
        /// Benchmark ECDSA P-384 key pair generation.
        /// </summary>
        [Benchmark(Description = "ECDSA P-384 Key Generation")]
        public AsymmetricKeyPair EcdsaP384_KeyGeneration()
        {
            return _ecdsaP384.GenerateKeyPair().Value;
        }

        /// <summary>
        /// Benchmark ECDSA P-521 key pair generation.
        /// </summary>
        [Benchmark(Description = "ECDSA P-521 Key Generation")]
        public AsymmetricKeyPair EcdsaP521_KeyGeneration()
        {
            return _ecdsaP521.GenerateKeyPair().Value;
        }

        // ==================== ECDSA Signing Benchmarks ====================

        /// <summary>
        /// Benchmark ECDSA P-256 signing of 256 bytes data.
        /// </summary>
        [Benchmark(Description = "ECDSA P-256 Sign 256B")]
        public byte[] EcdsaP256_Sign_256B()
        {
            return _ecdsaP256.Sign(_smallData).Value;
        }

        /// <summary>
        /// Benchmark ECDSA P-256 signing of 10 KB data.
        /// </summary>
        [Benchmark(Description = "ECDSA P-256 Sign 10KB")]
        public byte[] EcdsaP256_Sign_10KB()
        {
            return _ecdsaP256.Sign(_mediumData).Value;
        }

        /// <summary>
        /// Benchmark ECDSA P-256 signing of 100 KB data.
        /// </summary>
        [Benchmark(Description = "ECDSA P-256 Sign 100KB")]
        public byte[] EcdsaP256_Sign_100KB()
        {
            return _ecdsaP256.Sign(_largeData).Value;
        }

        /// <summary>
        /// Benchmark ECDSA P-384 signing of 256 bytes data.
        /// </summary>
        [Benchmark(Description = "ECDSA P-384 Sign 256B")]
        public byte[] EcdsaP384_Sign_256B()
        {
            return _ecdsaP384.Sign(_smallData).Value;
        }

        /// <summary>
        /// Benchmark ECDSA P-521 signing of 256 bytes data.
        /// </summary>
        [Benchmark(Description = "ECDSA P-521 Sign 256B")]
        public byte[] EcdsaP521_Sign_256B()
        {
            return _ecdsaP521.Sign(_smallData).Value;
        }

        /// <summary>
        /// Benchmark ECDSA P-256 signing of pre-computed hash.
        /// </summary>
        [Benchmark(Description = "ECDSA P-256 SignHash")]
        public byte[] EcdsaP256_SignHash()
        {
            return _ecdsaP256.SignHash(_dataHash).Value;
        }

        // ==================== ECDSA Verification Benchmarks ====================

        /// <summary>
        /// Benchmark ECDSA P-256 signature verification.
        /// </summary>
        [Benchmark(Description = "ECDSA P-256 Verify 256B")]
        public bool EcdsaP256_Verify()
        {
            return _ecdsaP256.Verify(_smallData, _ecdsaP256Signature).Value;
        }

        /// <summary>
        /// Benchmark ECDSA P-384 signature verification.
        /// </summary>
        [Benchmark(Description = "ECDSA P-384 Verify 256B")]
        public bool EcdsaP384_Verify()
        {
            return _ecdsaP384.Verify(_smallData, _ecdsaP384Signature).Value;
        }

        // ==================== RSA-PSS Benchmarks ====================

        /// <summary>
        /// Benchmark RSA-PSS-2048 key pair generation.
        /// </summary>
        [Benchmark(Description = "RSA-PSS-2048 Key Generation")]
        public AsymmetricKeyPair RsaPss2048_KeyGeneration()
        {
            return _rsaPss2048.GenerateKeyPair().Value;
        }

        /// <summary>
        /// Benchmark RSA-PSS-2048 signing of 256 bytes data.
        /// </summary>
        [Benchmark(Description = "RSA-PSS-2048 Sign 256B")]
        public byte[] RsaPss2048_Sign_256B()
        {
            return _rsaPss2048.Sign(_smallData).Value;
        }

        /// <summary>
        /// Benchmark RSA-PSS-4096 signing of 256 bytes data.
        /// </summary>
        [Benchmark(Description = "RSA-PSS-4096 Sign 256B")]
        public byte[] RsaPss4096_Sign_256B()
        {
            return _rsaPss4096.Sign(_smallData).Value;
        }

        /// <summary>
        /// Benchmark RSA-PSS-2048 signature verification.
        /// </summary>
        [Benchmark(Description = "RSA-PSS-2048 Verify 256B")]
        public bool RsaPss2048_Verify()
        {
            return _rsaPss2048.Verify(_smallData, _rsaPss2048Signature).Value;
        }
    }
}
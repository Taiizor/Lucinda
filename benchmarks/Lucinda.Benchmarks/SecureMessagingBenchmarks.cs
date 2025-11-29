// <copyright file="SecureMessagingBenchmarks.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Order;

using Lucinda.Abstractions;
using Lucinda.KeyExchange;
using Lucinda.Protocol.DoubleRatchet;
using Lucinda.Protocol.X3DH;

namespace Lucinda.Benchmarks
{
    /// <summary>
    /// Benchmarks for Signal Protocol-like secure messaging operations.
    /// </summary>
    /// <remarks>
    /// These benchmarks measure the performance of:
    /// <list type="bullet">
    /// <item><description>X3DH key agreement (session establishment)</description></item>
    /// <item><description>Double Ratchet encryption/decryption</description></item>
    /// <item><description>Pre-key bundle generation</description></item>
    /// <item><description>High-level SecureMessaging API</description></item>
    /// </list>
    /// </remarks>
    [RankColumn]
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 2, iterationCount: 5)]
    public class SecureMessagingBenchmarks
    {
        private SecureMessaging _alice = null!;
        private SecureMessaging _bob = null!;
        private X3DHKeyAgreement _x3dh = null!;
        private DoubleRatchet _doubleRatchet = null!;
        private EcdhKeyExchange _ecdh = null!;

        private byte[] _smallMessage = null!;
        private byte[] _mediumMessage = null!;
        private byte[] _largeMessage = null!;

        private AsymmetricKeyPair _aliceIdentityKeyPair = null!;
        private PreKeyBundle _bobPreKeyBundle = null!;
        private PreKeyBundleWithPrivateKeys _bobPreKeyBundleWithKeys = null!;

        private RatchetState _aliceRatchetState = null!;
        private RatchetState _bobRatchetState = null!;
        private byte[] _sharedSecret = null!;

        /// <summary>
        /// Setup benchmark data and instances.
        /// </summary>
        [GlobalSetup]
        public void Setup()
        {
            // Initialize components
            _x3dh = new X3DHKeyAgreement();
            _doubleRatchet = new DoubleRatchet();
            _ecdh = new EcdhKeyExchange();

            // Generate test messages
            _smallMessage = new byte[64]; // 64 bytes - typical short message
            _mediumMessage = new byte[1024]; // 1 KB
            _largeMessage = new byte[1024 * 10]; // 10 KB

            Random.Shared.NextBytes(_smallMessage);
            Random.Shared.NextBytes(_mediumMessage);
            Random.Shared.NextBytes(_largeMessage);

            // Setup Alice and Bob for SecureMessaging benchmarks
            _alice = new SecureMessaging();
            _bob = new SecureMessaging();

            _alice.GenerateIdentityKeyPair();
            _bob.GenerateIdentityKeyPair();
            _bob.GeneratePreKeyBundle();

            CryptoResult<PreKeyBundle> bobBundle = _bob.GetPublicPreKeyBundle();
            _alice.InitializeSession("bob", bobBundle.Value);

            CryptoResult<InitialMessageData> initialMessage = _alice.GetInitialMessageData("bob");
            _bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);

            // Setup for low-level X3DH benchmarks
            _aliceIdentityKeyPair = _ecdh.GenerateKeyPair().Value;
            _bobPreKeyBundleWithKeys = _x3dh.GeneratePreKeyBundle(_aliceIdentityKeyPair, 1, [1]).Value;
            _bobPreKeyBundle = _bobPreKeyBundleWithKeys.Bundle;

            // Setup for Double Ratchet benchmarks
            CryptoResult<X3DHResult> x3dhResult = _x3dh.InitiatorAgree(_aliceIdentityKeyPair, _bobPreKeyBundle);
            _sharedSecret = x3dhResult.Value.SharedSecret;

            _aliceRatchetState = _doubleRatchet.InitializeAsInitiator(_sharedSecret, _bobPreKeyBundle.SignedPreKey).Value;

            AsymmetricKeyPair bobSignedPreKeyPair = new(
                _bobPreKeyBundleWithKeys.Bundle.SignedPreKey,
                _bobPreKeyBundleWithKeys.SignedPreKeyPrivate);
            _bobRatchetState = _doubleRatchet.InitializeAsResponder(_sharedSecret, bobSignedPreKeyPair).Value;
        }

        /// <summary>
        /// Cleanup benchmark resources.
        /// </summary>
        [GlobalCleanup]
        public void Cleanup()
        {
            _alice?.Dispose();
            _bob?.Dispose();
            _x3dh?.Dispose();
            _doubleRatchet?.Dispose();
            _ecdh?.Dispose();
            _aliceRatchetState?.Dispose();
            _bobRatchetState?.Dispose();
        }

        // ==================== Pre-Key Bundle Generation ====================

        /// <summary>
        /// Benchmark pre-key bundle generation (one-time setup operation).
        /// </summary>
        [Benchmark(Baseline = true, Description = "Pre-Key Bundle Generation")]
        public PreKeyBundleWithPrivateKeys PreKeyBundle_Generation()
        {
            using EcdhKeyExchange ecdh = new();
            CryptoResult<AsymmetricKeyPair> identity = ecdh.GenerateKeyPair();
            return _x3dh.GeneratePreKeyBundle(identity.Value, 1, [1]).Value;
        }

        // ==================== X3DH Key Agreement ====================

        /// <summary>
        /// Benchmark X3DH initiator key agreement (Alice initiates session).
        /// </summary>
        [Benchmark(Description = "X3DH Initiator Agreement")]
        public X3DHResult X3DH_InitiatorAgree()
        {
            return _x3dh.InitiatorAgree(_aliceIdentityKeyPair, _bobPreKeyBundle).Value;
        }

        /// <summary>
        /// Benchmark X3DH responder key agreement (Bob accepts session).
        /// </summary>
        [Benchmark(Description = "X3DH Responder Agreement")]
        public X3DHResult X3DH_ResponderAgree()
        {
            AsymmetricKeyPair signedPreKeyPair = new(
                _bobPreKeyBundleWithKeys.Bundle.SignedPreKey,
                _bobPreKeyBundleWithKeys.SignedPreKeyPrivate);

            AsymmetricKeyPair? oneTimePreKeyPair = null;
            if (_bobPreKeyBundleWithKeys.OneTimePreKeyPrivates.Count > 0)
            {
                byte[] otpkPrivate = _bobPreKeyBundleWithKeys.OneTimePreKeyPrivates.First().Value;
                oneTimePreKeyPair = new AsymmetricKeyPair(_bobPreKeyBundle.OneTimePreKey!, otpkPrivate);
            }

            // Create a mock identity key pair for Bob
            using EcdhKeyExchange tempEcdh = new();
            AsymmetricKeyPair bobIdentity = tempEcdh.GenerateKeyPair().Value;

            return _x3dh.ResponderAgree(
                bobIdentity,
                signedPreKeyPair,
                oneTimePreKeyPair,
                _aliceIdentityKeyPair.PublicKey,
                _aliceIdentityKeyPair.PublicKey // Using as ephemeral for benchmark
            ).Value;
        }

        // ==================== Double Ratchet Operations ====================

        /// <summary>
        /// Benchmark Double Ratchet encryption (small message - 64 bytes).
        /// </summary>
        [Benchmark(Description = "Double Ratchet Encrypt (64B)")]
        public RatchetMessage DoubleRatchet_Encrypt_Small()
        {
            return _doubleRatchet.Encrypt(_aliceRatchetState, _smallMessage).Value;
        }

        /// <summary>
        /// Benchmark Double Ratchet encryption (medium message - 1KB).
        /// </summary>
        [Benchmark(Description = "Double Ratchet Encrypt (1KB)")]
        public RatchetMessage DoubleRatchet_Encrypt_Medium()
        {
            return _doubleRatchet.Encrypt(_aliceRatchetState, _mediumMessage).Value;
        }

        /// <summary>
        /// Benchmark Double Ratchet encryption (large message - 10KB).
        /// </summary>
        [Benchmark(Description = "Double Ratchet Encrypt (10KB)")]
        public RatchetMessage DoubleRatchet_Encrypt_Large()
        {
            return _doubleRatchet.Encrypt(_aliceRatchetState, _largeMessage).Value;
        }

        // ==================== SecureMessaging High-Level API ====================

        /// <summary>
        /// Benchmark full session establishment (identity + pre-key bundle + X3DH).
        /// </summary>
        [Benchmark(Description = "Full Session Establishment")]
        public string SecureMessaging_SessionEstablishment()
        {
            using SecureMessaging sender = new();
            using SecureMessaging receiver = new();

            sender.GenerateIdentityKeyPair();
            receiver.GenerateIdentityKeyPair();
            receiver.GeneratePreKeyBundle();

            CryptoResult<PreKeyBundle> bundle = receiver.GetPublicPreKeyBundle();
            return sender.InitializeSession("receiver", bundle.Value).Value;
        }

        /// <summary>
        /// Benchmark SecureMessaging send message (string API).
        /// </summary>
        [Benchmark(Description = "SecureMessaging Send (string)")]
        public byte[] SecureMessaging_SendMessage()
        {
            return _alice.SendMessage("bob", "Hello, this is a benchmark message!").Value;
        }

        /// <summary>
        /// Benchmark SecureMessaging receive/decrypt message.
        /// Note: This benchmark measures the decrypt operation by first encrypting a fresh message,
        /// because Double Ratchet state changes after each decrypt (security feature).
        /// </summary>
        [Benchmark(Description = "SecureMessaging Receive")]
        public string SecureMessaging_ReceiveMessage()
        {
            // Must encrypt fresh message each time because ratchet state advances
            byte[] encrypted = _alice.SendMessage("bob", "Benchmark decrypt message").Value;
            return _bob.ReceiveMessage("alice", encrypted).Value;
        }

        /// <summary>
        /// Benchmark full round-trip: encrypt + decrypt.
        /// </summary>
        [Benchmark(Description = "SecureMessaging Round-Trip")]
        public string SecureMessaging_RoundTrip()
        {
            byte[] encrypted = _alice.SendMessage("bob", "Round-trip benchmark message").Value;
            return _bob.ReceiveMessage("alice", encrypted).Value;
        }
    }
}

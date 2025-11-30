// <copyright file="Program.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Abstractions;
using Lucinda.Protocol.DoubleRatchet;
using Lucinda.Protocol.SenderKeys;
using Lucinda.Utilities;
using System.Security.Cryptography;
using System.Text;

namespace Lucinda.Samples.SignalProtocol
{
    /// <summary>
    /// Comprehensive demonstration of Signal Protocol features in Lucinda library.
    /// This sample showcases:
    /// - Header Encryption for metadata protection
    /// - GroupSession (Sender Keys Protocol) for efficient group messaging
    /// - SecureMessagingOptions customization
    /// </summary>
    class Program
    {
        static void Main()
        {
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;

            Console.WriteLine("╔══════════════════════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║      Lucinda E2EE - Advanced Signal Protocol Features                            ║");
            Console.WriteLine("║      (Header Encryption, Sender Keys, Custom Providers)                          ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════════════════════════╝");
            Console.WriteLine();

            // Run demonstrations
            DemonstrateHeaderEncryption();
            DemonstrateGroupSession();
            DemonstrateSecureMessagingOptions();
            DemonstrateGroupConversation();

            Console.WriteLine("\n✅ All Signal Protocol demonstrations completed successfully!");

            if (!Console.IsInputRedirected)
            {
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }

        /// <summary>
        /// Demonstrates Header Encryption for protecting message metadata.
        /// </summary>
        static void DemonstrateHeaderEncryption()
        {
            PrintHeader("1. Header Encryption (Metadata Protection)");

            Console.WriteLine("📋 Scenario: Encrypt Double Ratchet headers to hide metadata");
            Console.WriteLine("   Without header encryption, observers can see:");
            Console.WriteLine("   - Ratchet public keys (linked to sender identity)");
            Console.WriteLine("   - Message numbers (reveals communication patterns)");
            Console.WriteLine();

            // Initialize header encryption with a root key
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 1: Initialize Header Encryption");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            byte[] rootKey = RandomNumberGenerator.GetBytes(32);
            CryptoResult<HeaderEncryption> headerEncResult = HeaderEncryption.Initialize(rootKey);

            if (headerEncResult.IsFailure)
            {
                Console.WriteLine($"  ❌ Failed to initialize: {headerEncResult.Error}");
                return;
            }

            using HeaderEncryption headerEncryption = headerEncResult.Value!;
            Console.WriteLine($"  ✓ Header encryption initialized");
            Console.WriteLine($"    Root key: {CryptoHelpers.ToBase64(rootKey)[..20]}...");
            Console.WriteLine();

            // Create a sample ratchet header
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 2: Create and Encrypt a Ratchet Header");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            using ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            byte[] dhPublicKey = ecdh.PublicKey.ExportSubjectPublicKeyInfo();

            // RatchetHeader(dhPublicKey, previousChainLength, messageNumber)
            RatchetHeader header = new(dhPublicKey, 5, 42);

            Console.WriteLine("  📄 Original Header:");
            Console.WriteLine($"     • DH Public Key: {CryptoHelpers.ToBase64(header.DHPublicKey)[..30]}...");
            Console.WriteLine($"     • Previous Chain Length: {header.PreviousChainLength}");
            Console.WriteLine($"     • Message Number: {header.MessageNumber}");
            Console.WriteLine();

            // Encrypt the header
            CryptoResult<EncryptedHeader> encryptResult = headerEncryption.EncryptHeader(header);

            if (encryptResult.IsFailure)
            {
                Console.WriteLine($"  ❌ Encryption failed: {encryptResult.Error}");
                return;
            }

            EncryptedHeader encryptedHeader = encryptResult.Value!;
            Console.WriteLine("  🔐 Encrypted Header:");
            Console.WriteLine($"     • Nonce: {CryptoHelpers.ToBase64(encryptedHeader.Nonce)}");
            Console.WriteLine($"     • Ciphertext: {CryptoHelpers.ToBase64(encryptedHeader.Ciphertext)[..30]}...");
            Console.WriteLine($"     • Tag: {CryptoHelpers.ToBase64(encryptedHeader.Tag)}");
            Console.WriteLine();

            // Decrypt the header
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 3: Decrypt the Header");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            CryptoResult<RatchetHeader> decryptResult = headerEncryption.DecryptHeader(encryptedHeader);

            if (decryptResult.IsFailure)
            {
                Console.WriteLine($"  ❌ Decryption failed: {decryptResult.Error}");
                return;
            }

            RatchetHeader decryptedHeader = decryptResult.Value!;
            Console.WriteLine("  ✓ Decrypted Header:");
            Console.WriteLine($"     • Previous Chain Length: {decryptedHeader.PreviousChainLength}");
            Console.WriteLine($"     • Message Number: {decryptedHeader.MessageNumber}");
            Console.WriteLine($"     • DH Public Key matches: {header.DHPublicKey.SequenceEqual(decryptedHeader.DHPublicKey)}");
            Console.WriteLine();

            // Demonstrate header key ratcheting
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 4: Ratchet Header Keys (after DH ratchet)");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            byte[] newRootKey = RandomNumberGenerator.GetBytes(32);
            CryptoResult<bool> ratchetResult = headerEncryption.RatchetHeaderKeys(newRootKey);

            Console.WriteLine($"  ✓ Header keys ratcheted: {ratchetResult.IsSuccess}");
            Console.WriteLine("    💡 New header keys derived from new root key");
            Console.WriteLine("    💡 Old headers can still be decrypted (next header key preserved)");
            Console.WriteLine();
        }

        /// <summary>
        /// Demonstrates the GroupSession class for Sender Keys protocol.
        /// </summary>
        static void DemonstrateGroupSession()
        {
            PrintHeader("2. GroupSession (Sender Keys Protocol)");

            Console.WriteLine("📋 Scenario: Efficient group messaging using Sender Keys");
            Console.WriteLine("   Each participant has one sender key for ALL recipients");
            Console.WriteLine("   Much more efficient than per-recipient encryption!");
            Console.WriteLine();

            // Create group sessions
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 1: Create Group Sessions for Each Participant");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            string groupId = "family-chat-2024";

            using GroupSession alice = new(groupId, "alice");
            using GroupSession bob = new(groupId, "bob");
            using GroupSession charlie = new(groupId, "charlie");

            Console.WriteLine($"  ✓ Group ID: {groupId}");
            Console.WriteLine($"  ✓ Alice's session created (participant: {alice.LocalParticipantId})");
            Console.WriteLine($"  ✓ Bob's session created (participant: {bob.LocalParticipantId})");
            Console.WriteLine($"  ✓ Charlie's session created (participant: {charlie.LocalParticipantId})");
            Console.WriteLine();

            // Initialize sender keys
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 2: Initialize Sender Keys");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            alice.Initialize();
            bob.Initialize();
            charlie.Initialize();

            Console.WriteLine($"  ✓ Alice initialized: {alice.IsInitialized}");
            Console.WriteLine($"  ✓ Bob initialized: {bob.IsInitialized}");
            Console.WriteLine($"  ✓ Charlie initialized: {charlie.IsInitialized}");
            Console.WriteLine();

            // Create and exchange distribution messages
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 3: Exchange Sender Key Distribution Messages");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            SenderKeyDistributionData aliceDist = alice.CreateDistributionMessage().Value!;
            SenderKeyDistributionData bobDist = bob.CreateDistributionMessage().Value!;
            SenderKeyDistributionData charlieDist = charlie.CreateDistributionMessage().Value!;

            Console.WriteLine("  📦 Distribution messages created:");
            Console.WriteLine($"     • Alice's Key ID: {aliceDist.KeyId}");
            Console.WriteLine($"     • Bob's Key ID: {bobDist.KeyId}");
            Console.WriteLine($"     • Charlie's Key ID: {charlieDist.KeyId}");
            Console.WriteLine();

            // Each participant processes others' distributions
            // Alice gets Bob's and Charlie's keys
            alice.ProcessDistributionMessage("bob", bobDist);
            alice.ProcessDistributionMessage("charlie", charlieDist);

            // Bob gets Alice's and Charlie's keys
            bob.ProcessDistributionMessage("alice", aliceDist);
            bob.ProcessDistributionMessage("charlie", charlieDist);

            // Charlie gets Alice's and Bob's keys
            charlie.ProcessDistributionMessage("alice", aliceDist);
            charlie.ProcessDistributionMessage("bob", bobDist);

            Console.WriteLine("  ✓ Distribution messages exchanged");
            Console.WriteLine($"     • Alice knows {alice.RemoteParticipantCount} remote participants");
            Console.WriteLine($"     • Bob knows {bob.RemoteParticipantCount} remote participants");
            Console.WriteLine($"     • Charlie knows {charlie.RemoteParticipantCount} remote participants");
            Console.WriteLine();

            // Send a group message
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 4: Alice Sends a Message to the Group");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            string message = "Hey everyone! 🎉 Group chat is working!";
            byte[] plaintext = Encoding.UTF8.GetBytes(message);

            Console.WriteLine($"  📤 Alice's message: \"{message}\"");

            CryptoResult<GroupMessage> encryptResult = alice.Encrypt(plaintext);

            if (encryptResult.IsFailure)
            {
                Console.WriteLine($"  ❌ Encryption failed: {encryptResult.Error}");
                return;
            }

            GroupMessage groupMessage = encryptResult.Value!;
            Console.WriteLine($"  🔐 Encrypted (single encryption for all recipients!):");
            Console.WriteLine($"     • Sender: {groupMessage.SenderId}");
            Console.WriteLine($"     • Key ID: {groupMessage.KeyId}");
            Console.WriteLine($"     • Chain Index: {groupMessage.ChainIndex}");
            Console.WriteLine($"     • Ciphertext: {CryptoHelpers.ToBase64(groupMessage.Ciphertext)[..30]}...");
            Console.WriteLine();

            // Bob and Charlie decrypt
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 5: Bob and Charlie Decrypt the Message");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            CryptoResult<byte[]> bobDecrypt = bob.Decrypt(groupMessage);
            CryptoResult<byte[]> charlieDecrypt = charlie.Decrypt(groupMessage);

            Console.WriteLine($"  📥 Bob decrypts: \"{Encoding.UTF8.GetString(bobDecrypt.Value!)}\"");
            Console.WriteLine($"  📥 Charlie decrypts: \"{Encoding.UTF8.GetString(charlieDecrypt.Value!)}\"");
            Console.WriteLine();

            // Demonstrate serialization
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 6: Message Serialization (for network transport)");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            byte[] serialized = groupMessage.Serialize();
            CryptoResult<GroupMessage> deserialized = GroupMessage.Deserialize(serialized);

            Console.WriteLine($"  ✓ Serialized message size: {serialized.Length} bytes");
            Console.WriteLine($"  ✓ Deserialization successful: {deserialized.IsSuccess}");
            Console.WriteLine($"  ✓ Sender matches: {deserialized.Value!.SenderId == groupMessage.SenderId}");
            Console.WriteLine();
        }

        /// <summary>
        /// Demonstrates SecureMessagingOptions customization.
        /// </summary>
        static void DemonstrateSecureMessagingOptions()
        {
            PrintHeader("3. SecureMessagingOptions Customization");

            Console.WriteLine("📋 Scenario: Configure SecureMessaging with custom options");
            Console.WriteLine();

            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Available Configuration Options:");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            SecureMessagingOptions options = new()
            {
                // Cryptographic settings
                Curve = System.Security.Cryptography.ECCurve.NamedCurves.nistP256,
                HashAlgorithm = System.Security.Cryptography.HashAlgorithmName.SHA256,

                // Message handling
                MaxSkipMessageKeys = 100,
                MaxChainLength = 2000,
                StoreSkippedMessageKeys = true,

                // Pre-key settings
                OneTimePreKeyCount = 100,
                AutoDeleteUsedOneTimePreKeys = true,

                // Header encryption
                EnableHeaderEncryption = false, // Set to true to enable

                // Key rotation
                SignedPreKeyRotationInterval = TimeSpan.FromDays(7),
                SessionExpirationTime = TimeSpan.FromDays(30),

                // Custom providers (for X25519/Ed25519 support)
                Curve25519Provider = null, // Implement ICurve25519 for X25519
                EdDSAProvider = null        // Implement IEdDSA for Ed25519
            };

            Console.WriteLine($"  📌 Curve: {options.Curve.Oid.FriendlyName}");
            Console.WriteLine($"  📌 Hash Algorithm: {options.HashAlgorithm.Name}");
            Console.WriteLine($"  📌 Max Skip Message Keys: {options.MaxSkipMessageKeys}");
            Console.WriteLine($"  📌 Max Chain Length: {options.MaxChainLength}");
            Console.WriteLine($"  📌 Store Skipped Keys: {options.StoreSkippedMessageKeys}");
            Console.WriteLine($"  📌 One-Time Pre-Key Count: {options.OneTimePreKeyCount}");
            Console.WriteLine($"  📌 Auto-Delete Used Pre-Keys: {options.AutoDeleteUsedOneTimePreKeys}");
            Console.WriteLine($"  📌 Enable Header Encryption: {options.EnableHeaderEncryption}");
            Console.WriteLine($"  📌 Signed Pre-Key Rotation: {options.SignedPreKeyRotationInterval.TotalDays} days");
            Console.WriteLine($"  📌 Session Expiration: {options.SessionExpirationTime.TotalDays} days");
            Console.WriteLine();

            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Custom Provider Interfaces:");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            Console.WriteLine("  💡 ICurve25519 - Implement for X25519 key exchange:");
            Console.WriteLine("     • GenerateKeyPair() -> Curve25519KeyPair");
            Console.WriteLine("     • ComputeSharedSecret(privateKey, publicKey) -> byte[]");
            Console.WriteLine("     • GetPublicKey(privateKey) -> byte[]");
            Console.WriteLine("     • ValidatePublicKey(publicKey) -> bool");
            Console.WriteLine();

            Console.WriteLine("  💡 IEdDSA - Implement for Ed25519 signatures:");
            Console.WriteLine("     • GenerateKeyPair() -> EdDSAKeyPair");
            Console.WriteLine("     • Sign(privateKey, message) -> byte[]");
            Console.WriteLine("     • Verify(publicKey, message, signature) -> bool");
            Console.WriteLine("     • GetPublicKey(privateKey) -> byte[]");
            Console.WriteLine();

            Console.WriteLine("  📦 Example usage with libsodium-net:");
            Console.WriteLine("     options.Curve25519Provider = new LibsodiumCurve25519();");
            Console.WriteLine("     options.EdDSAProvider = new LibsodiumEd25519();");
            Console.WriteLine();
        }

        /// <summary>
        /// Demonstrates a complete group conversation flow.
        /// </summary>
        static void DemonstrateGroupConversation()
        {
            PrintHeader("4. Complete Group Conversation Demo");

            Console.WriteLine("📋 Scenario: A realistic group chat conversation");
            Console.WriteLine();

            string groupId = "project-team";

            using GroupSession alice = new(groupId, "Alice");
            using GroupSession bob = new(groupId, "Bob");
            using GroupSession carol = new(groupId, "Carol");

            // Initialize all
            alice.Initialize();
            bob.Initialize();
            carol.Initialize();

            // Full key exchange
            SenderKeyDistributionData aliceDist = alice.CreateDistributionMessage().Value!;
            SenderKeyDistributionData bobDist = bob.CreateDistributionMessage().Value!;
            SenderKeyDistributionData carolDist = carol.CreateDistributionMessage().Value!;

            alice.ProcessDistributionMessage("Bob", bobDist);
            alice.ProcessDistributionMessage("Carol", carolDist);
            bob.ProcessDistributionMessage("Alice", aliceDist);
            bob.ProcessDistributionMessage("Carol", carolDist);
            carol.ProcessDistributionMessage("Alice", aliceDist);
            carol.ProcessDistributionMessage("Bob", bobDist);

            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Group Chat: Project Team");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();

            // Simulate a conversation
            (GroupSession Sender, string Name, string Message)[] conversation = new[]
            {
                (Sender: alice, Name: "Alice", Message: "Hey team! Ready for the standup? 👋"),
                (Sender: bob, Name: "Bob", Message: "Good morning! Yes, ready to go."),
                (Sender: carol, Name: "Carol", Message: "Morning everyone! ☕"),
                (Sender: alice, Name: "Alice", Message: "Great! Let's start. Bob, any blockers?"),
                (Sender: bob, Name: "Bob", Message: "No blockers. Finished the API integration yesterday."),
                (Sender: carol, Name: "Carol", Message: "Nice work Bob! 🎉"),
                (Sender: alice, Name: "Alice", Message: "Excellent! Carol, how about you?"),
                (Sender: carol, Name: "Carol", Message: "Working on the UI tests. Should be done by EOD."),
                (Sender: alice, Name: "Alice", Message: "Perfect. Let's sync again tomorrow. Thanks everyone!"),
                (Sender: bob, Name: "Bob", Message: "👍"),
                (Sender: carol, Name: "Carol", Message: "See you tomorrow!")
            };

            Dictionary<string, GroupSession> receivers = new()
            {
                ["Alice"] = alice,
                ["Bob"] = bob,
                ["Carol"] = carol
            };

            foreach ((GroupSession? sender, string? name, string? message) in conversation)
            {
                // Encrypt
                GroupMessage encrypted = sender.Encrypt(Encoding.UTF8.GetBytes(message)).Value!;

                // All others decrypt
                Console.WriteLine($"  [{name}]: {message}");

                // Verify all recipients can decrypt
                foreach ((string? receiverName, GroupSession? receiver) in receivers)
                {
                    if (receiverName != name)
                    {
                        byte[] decrypted = receiver.Decrypt(encrypted).Value!;
                        // Silently verify - in production you'd use this
                        _ = Encoding.UTF8.GetString(decrypted);
                    }
                }
            }

            Console.WriteLine();
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("  ✓ All messages encrypted with Sender Keys protocol");
            Console.WriteLine("  ✓ Each message: single encryption, multiple decryptions");
            Console.WriteLine("  ✓ Messages are signed to prevent forgery");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
        }

        static void PrintHeader(string title)
        {
            Console.WriteLine();
            Console.WriteLine("╔══════════════════════════════════════════════════════════════════════════════════╗");
            Console.WriteLine($"║  {title,-80}║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════════════════════════╝");
            Console.WriteLine();
        }
    }
}
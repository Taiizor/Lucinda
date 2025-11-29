// <copyright file="Program.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Abstractions;
using Lucinda.Protocol.X3DH;
using Lucinda.Utilities;
using System.Text;

namespace Lucinda.Samples.SecureMessaging
{
    /// <summary>
    /// Demonstrates the Signal Protocol-like SecureMessaging API for end-to-end encrypted conversations.
    /// This sample shows X3DH key agreement and Double Ratchet algorithm in action.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Signal Protocol Components Demonstrated:</b>
    /// </para>
    /// <list type="bullet">
    /// <item><description>X3DH (Extended Triple Diffie-Hellman): Asynchronous key agreement</description></item>
    /// <item><description>Double Ratchet: Forward-secure message encryption</description></item>
    /// <item><description>Pre-Key Bundles: Enables offline session establishment</description></item>
    /// </list>
    /// <para>
    /// <b>Security Properties:</b>
    /// </para>
    /// <list type="bullet">
    /// <item><description>Forward Secrecy: Past messages remain secure if keys are compromised</description></item>
    /// <item><description>Post-Compromise Security: Future messages become secure after compromise</description></item>
    /// <item><description>Asynchronous: Sessions can be established with offline recipients</description></item>
    /// </list>
    /// <para>
    /// <b>Used by:</b> Signal, WhatsApp, Facebook Messenger (Secret Conversations)
    /// </para>
    /// </remarks>
    class Program
    {
        static void Main()
        {
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;

            Console.WriteLine("╔══════════════════════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║      Lucinda E2EE - Signal Protocol Style Secure Messaging                       ║");
            Console.WriteLine("║      (X3DH Key Agreement + Double Ratchet Algorithm)                             ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════════════════════════╝");
            Console.WriteLine();

            // Run demonstrations
            DemonstrateBasicConversation();
            DemonstrateForwardSecrecy();
            DemonstrateAsynchronousSetup();
            DemonstrateBidirectionalConversation();

            Console.WriteLine("\n✅ All Signal Protocol demonstrations completed successfully!");

            // Only wait for key press if running interactively
            if (!Console.IsInputRedirected)
            {
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }

        /// <summary>
        /// Demonstrates a basic secure conversation between Alice and Bob.
        /// </summary>
        static void DemonstrateBasicConversation()
        {
            PrintHeader("1. Basic Secure Conversation (X3DH + Double Ratchet)");

            Console.WriteLine("📋 Scenario: Alice wants to send secure messages to Bob");
            Console.WriteLine();

            // Create secure messaging instances for Alice and Bob
            using Lucinda.SecureMessaging alice = new();
            using Lucinda.SecureMessaging bob = new();

            // Step 1: Generate identity key pairs
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 1: Generate Identity Key Pairs (Long-term keys)");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            CryptoResult<AsymmetricKeyPair> aliceIdentity = alice.GenerateIdentityKeyPair();
            CryptoResult<AsymmetricKeyPair> bobIdentity = bob.GenerateIdentityKeyPair();

            Console.WriteLine($"  ✓ Alice generated identity key pair");
            Console.WriteLine($"    Public Key: {CryptoHelpers.ToBase64(aliceIdentity.Value.PublicKey)[..30]}...");
            Console.WriteLine($"  ✓ Bob generated identity key pair");
            Console.WriteLine($"    Public Key: {CryptoHelpers.ToBase64(bobIdentity.Value.PublicKey)[..30]}...");
            Console.WriteLine();

            // Step 2: Bob generates and publishes a pre-key bundle
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 2: Bob generates Pre-Key Bundle (for asynchronous contact)");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            CryptoResult<PreKeyBundleWithPrivateKeys> bobBundle = bob.GeneratePreKeyBundle();

            Console.WriteLine("  📦 Bob's Pre-Key Bundle contains:");
            Console.WriteLine($"     • Identity Public Key: {CryptoHelpers.ToBase64(bobBundle.Value.Bundle.IdentityKey)[..20]}...");
            Console.WriteLine($"     • Signed Pre-Key: {CryptoHelpers.ToBase64(bobBundle.Value.Bundle.SignedPreKey)[..20]}...");
            Console.WriteLine($"     • Signature: {CryptoHelpers.ToBase64(bobBundle.Value.Bundle.SignedPreKeySignature)[..20]}...");
            Console.WriteLine($"     • One-Time Pre-Key: {(bobBundle.Value.Bundle.OneTimePreKey != null ? "Available" : "None")}");
            Console.WriteLine();
            Console.WriteLine("  💡 Bob publishes this bundle to a server so others can contact him");
            Console.WriteLine("     even when he's offline.");
            Console.WriteLine();

            // Step 3: Alice initiates session using Bob's pre-key bundle (X3DH)
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 3: Alice performs X3DH Key Agreement");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            CryptoResult<Lucinda.Protocol.X3DH.PreKeyBundle> publicBundle = bob.GetPublicPreKeyBundle();
            CryptoResult<string> sessionResult = alice.InitializeSession("bob", publicBundle.Value);

            Console.WriteLine("  🔐 X3DH Key Agreement:");
            Console.WriteLine("     Alice performs 3-4 ECDH computations:");
            Console.WriteLine("     • DH1: Alice's Identity Key ⟷ Bob's Signed Pre-Key");
            Console.WriteLine("     • DH2: Alice's Ephemeral Key ⟷ Bob's Identity Key");
            Console.WriteLine("     • DH3: Alice's Ephemeral Key ⟷ Bob's Signed Pre-Key");
            Console.WriteLine("     • DH4: Alice's Ephemeral Key ⟷ Bob's One-Time Pre-Key (optional)");
            Console.WriteLine();
            Console.WriteLine($"  ✓ Session established: {sessionResult.Value}");
            Console.WriteLine();

            // Step 4: Alice sends initial message data to Bob
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 4: Bob creates session from Alice's initial contact");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            CryptoResult<InitialMessageData> initialMessage = alice.GetInitialMessageData("bob");
            CryptoResult<string> bobSession = bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);

            Console.WriteLine("  📨 Alice sends initial message data:");
            Console.WriteLine($"     • Her Identity Public Key: {CryptoHelpers.ToBase64(initialMessage.Value.SenderIdentityPublicKey)[..20]}...");
            Console.WriteLine($"     • Her Ephemeral Public Key: {CryptoHelpers.ToBase64(initialMessage.Value.SenderEphemeralPublicKey)[..20]}...");
            Console.WriteLine($"     • Used One-Time Pre-Key ID: {initialMessage.Value.UsedOneTimePreKeyId ?? -1}");
            Console.WriteLine();
            Console.WriteLine($"  ✓ Bob established matching session: {bobSession.Value}");
            Console.WriteLine();

            // Step 5: Alice sends encrypted messages (Double Ratchet)
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 5: Send encrypted messages (Double Ratchet)");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            string[] messages =
            [
                "Hello Bob! 👋",
                "This message is encrypted with the Double Ratchet algorithm.",
                "Each message uses a different encryption key! 🔐"
            ];

            foreach (string message in messages)
            {
                Console.WriteLine($"\n  📤 Alice sends: \"{message}\"");

                CryptoResult<byte[]> encrypted = alice.SendMessage("bob", message);
                Console.WriteLine($"     Encrypted ({encrypted.Value.Length} bytes): {CryptoHelpers.ToBase64(encrypted.Value)[..40]}...");

                CryptoResult<string> decrypted = bob.ReceiveMessage("alice", encrypted.Value);
                Console.WriteLine($"  📥 Bob decrypts: \"{decrypted.Value}\"");
                Console.WriteLine($"     ✓ Message delivered securely!");
            }

            Console.WriteLine();
        }

        /// <summary>
        /// Demonstrates the forward secrecy property of the Double Ratchet algorithm.
        /// </summary>
        static void DemonstrateForwardSecrecy()
        {
            PrintHeader("2. Forward Secrecy Demonstration");

            Console.WriteLine("📋 Scenario: Each message uses a unique encryption key");
            Console.WriteLine("   Even if one key is compromised, other messages remain secure.");
            Console.WriteLine();

            using Lucinda.SecureMessaging alice = new();
            using Lucinda.SecureMessaging bob = new();

            // Setup session
            alice.GenerateIdentityKeyPair();
            bob.GenerateIdentityKeyPair();
            bob.GeneratePreKeyBundle();

            CryptoResult<PreKeyBundle> publicBundle = bob.GetPublicPreKeyBundle();
            alice.InitializeSession("bob", publicBundle.Value);

            CryptoResult<InitialMessageData> initialMessage = alice.GetInitialMessageData("bob");
            bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);

            // Send multiple messages and show that ciphertexts are different
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Sending the SAME message multiple times:");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            string sameMessage = "Hello!";
            List<byte[]> ciphertexts = [];

            for (int i = 1; i <= 3; i++)
            {
                CryptoResult<byte[]> encrypted = alice.SendMessage("bob", sameMessage);
                ciphertexts.Add(encrypted.Value);

                Console.WriteLine($"\n  Message #{i}: \"{sameMessage}\"");
                Console.WriteLine($"  Ciphertext: {CryptoHelpers.ToBase64(encrypted.Value)[..50]}...");

                CryptoResult<string> decrypted = bob.ReceiveMessage("alice", encrypted.Value);
                Console.WriteLine($"  Decrypted: \"{decrypted.Value}\"");
            }

            // Verify all ciphertexts are different
            Console.WriteLine("\n═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Forward Secrecy Analysis:");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            bool allDifferent = true;
            for (int i = 0; i < ciphertexts.Count; i++)
            {
                for (int j = i + 1; j < ciphertexts.Count; j++)
                {
                    bool different = !ciphertexts[i].SequenceEqual(ciphertexts[j]);
                    if (!different)
                    {
                        allDifferent = false;
                    }

                    Console.WriteLine($"  Ciphertext #{i + 1} vs #{j + 1}: {(different ? "✓ Different" : "✗ Same")}");
                }
            }

            Console.WriteLine();
            Console.WriteLine($"  🔐 Result: {(allDifferent ? "✓ All ciphertexts are unique!" : "✗ Some ciphertexts matched")}");
            Console.WriteLine("     → Even identical plaintext produces different ciphertext");
            Console.WriteLine("     → Each message key is derived, used once, then deleted");
            Console.WriteLine("     → Compromise of one key doesn't reveal other messages");
            Console.WriteLine();
        }

        /// <summary>
        /// Demonstrates asynchronous session establishment (offline recipient).
        /// </summary>
        static void DemonstrateAsynchronousSetup()
        {
            PrintHeader("3. Asynchronous Session Setup (Offline Recipient)");

            Console.WriteLine("📋 Scenario: Bob is offline, but Alice can still establish a session");
            Console.WriteLine("   and queue encrypted messages for when Bob comes online.");
            Console.WriteLine();

            // Bob sets up his pre-key bundle before going offline
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Phase 1: Bob sets up and goes offline");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            using Lucinda.SecureMessaging bob = new();
            bob.GenerateIdentityKeyPair();
            CryptoResult<PreKeyBundleWithPrivateKeys> bobBundleWithKeys = bob.GeneratePreKeyBundle();
            CryptoResult<PreKeyBundle> bobPublicBundle = bob.GetPublicPreKeyBundle();

            Console.WriteLine("  ✓ Bob generated identity and pre-key bundle");
            Console.WriteLine("  ✓ Bob published pre-key bundle to server");
            Console.WriteLine("  📴 Bob is now OFFLINE");
            Console.WriteLine();

            // Alice initiates session while Bob is offline
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Phase 2: Alice initiates session (Bob still offline)");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            using Lucinda.SecureMessaging alice = new();
            alice.GenerateIdentityKeyPair();
            alice.InitializeSession("bob", bobPublicBundle.Value);

            Console.WriteLine("  ✓ Alice retrieved Bob's pre-key bundle from server");
            Console.WriteLine("  ✓ Alice performed X3DH key agreement");
            Console.WriteLine("  ✓ Alice's session is ready (Bob still offline!)");
            Console.WriteLine();

            // Alice sends messages to the queue
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Phase 3: Alice sends messages to server queue");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            CryptoResult<InitialMessageData> initialMessage = alice.GetInitialMessageData("bob");

            string[] queuedMessages =
            [
                "Hey Bob! Are you there?",
                "I wanted to share some exciting news!",
                "Let me know when you're back online. 📱"
            ];

            List<byte[]> encryptedQueue = [];
            foreach (string msg in queuedMessages)
            {
                CryptoResult<byte[]> encrypted = alice.SendMessage("bob", msg);
                encryptedQueue.Add(encrypted.Value);
                Console.WriteLine($"  📤 Queued: \"{msg}\"");
            }

            Console.WriteLine();
            Console.WriteLine($"  💾 {encryptedQueue.Count} encrypted messages waiting on server");
            Console.WriteLine();

            // Bob comes online and receives messages
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Phase 4: Bob comes online and receives messages");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            Console.WriteLine("  📱 Bob is now ONLINE");

            // Bob creates session from initial message
            bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);
            Console.WriteLine("  ✓ Bob established session from Alice's initial message");
            Console.WriteLine();

            // Bob decrypts queued messages
            Console.WriteLine("  📥 Bob downloads and decrypts queued messages:");
            for (int i = 0; i < encryptedQueue.Count; i++)
            {
                CryptoResult<string> decrypted = bob.ReceiveMessage("alice", encryptedQueue[i]);
                Console.WriteLine($"     Message {i + 1}: \"{decrypted.Value}\"");
            }

            Console.WriteLine();
            Console.WriteLine("  ✓ All messages delivered successfully!");
            Console.WriteLine("  💡 X3DH enabled secure contact even with offline recipient");
            Console.WriteLine();
        }

        /// <summary>
        /// Demonstrates a bidirectional conversation with multiple exchanges.
        /// </summary>
        static void DemonstrateBidirectionalConversation()
        {
            PrintHeader("4. Bidirectional Conversation");

            Console.WriteLine("📋 Scenario: Alice and Bob have a back-and-forth conversation");
            Console.WriteLine("   The Double Ratchet continuously updates keys in both directions.");
            Console.WriteLine();

            using Lucinda.SecureMessaging alice = new();
            using Lucinda.SecureMessaging bob = new();

            // Setup
            alice.GenerateIdentityKeyPair();
            bob.GenerateIdentityKeyPair();
            bob.GeneratePreKeyBundle();

            CryptoResult<PreKeyBundle> publicBundle = bob.GetPublicPreKeyBundle();
            alice.InitializeSession("bob", publicBundle.Value);

            CryptoResult<InitialMessageData> initialMessage = alice.GetInitialMessageData("bob");
            bob.CreateSessionFromInitialMessage("alice", initialMessage.Value);

            Console.WriteLine("  ✓ Session established between Alice and Bob");
            Console.WriteLine();

            // Simulated conversation
            (string sender, string message)[] conversation =
            [
                ("Alice", "Hey Bob! Did you see the news? 📰"),
                ("Alice", "It's about that new cryptography breakthrough!"),
                ("Bob", "Oh hey Alice! Yes, I heard about it! 🔐"),
                ("Bob", "The Signal Protocol implementation looks amazing."),
                ("Alice", "Right? Forward secrecy is so important!"),
                ("Bob", "Absolutely. Our messages are safe even if keys leak later."),
                ("Alice", "That's the beauty of the Double Ratchet! 🎯"),
                ("Bob", "Each message, new keys. Love it! 💪")
            ];

            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Conversation (with DH Ratchet steps):");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();

            string lastSender = "";
            int ratchetStep = 0;

            foreach ((string sender, string message) in conversation)
            {
                // Track DH ratchet steps (happens when sender changes)
                if (sender != lastSender && lastSender != "")
                {
                    ratchetStep++;
                    Console.WriteLine($"  🔄 DH Ratchet Step {ratchetStep} (direction change: {lastSender} → {sender})");
                    Console.WriteLine();
                }

                if (sender == "Alice")
                {
                    // Alice sends to Bob
                    CryptoResult<byte[]> encrypted = alice.SendMessage("bob", message);
                    CryptoResult<string> decrypted = bob.ReceiveMessage("alice", encrypted.Value);

                    Console.WriteLine($"  👩 Alice: \"{message}\"");
                    Console.WriteLine($"     → Bob received: \"{decrypted.Value}\"");
                }
                else
                {
                    // Bob sends to Alice
                    CryptoResult<byte[]> encrypted = bob.SendMessage("alice", message);
                    CryptoResult<string> decrypted = alice.ReceiveMessage("bob", encrypted.Value);

                    Console.WriteLine($"  👨 Bob: \"{message}\"");
                    Console.WriteLine($"     → Alice received: \"{decrypted.Value}\"");
                }

                lastSender = sender;
                Console.WriteLine();
            }

            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Conversation Summary:");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine($"  • Total messages: {conversation.Length}");
            Console.WriteLine($"  • DH Ratchet steps: {ratchetStep}");
            Console.WriteLine("  • Each direction change triggered a DH ratchet");
            Console.WriteLine("  • Each message used a unique symmetric key");
            Console.WriteLine("  • Perfect forward secrecy maintained throughout");
            Console.WriteLine();
        }

        /// <summary>
        /// Prints a formatted header for each demonstration section.
        /// </summary>
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
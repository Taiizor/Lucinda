// <copyright file="Program.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Abstractions;
using Lucinda.Utilities;
using System.Text;

namespace Lucinda.Samples.GroupMessaging.PerRecipient
{
    /// <summary>
    /// Demonstrates the Per-Recipient Encryption approach for group E2EE messaging.
    /// Each message is encrypted separately for each recipient using their public key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>How Per-Recipient Encryption Works:</b>
    /// </para>
    /// <list type="number">
    /// <item>Each user has their own RSA key pair</item>
    /// <item>Public keys are exchanged between all group members</item>
    /// <item>When sending a message, the sender encrypts it separately for EACH recipient</item>
    /// <item>Each recipient receives their own encrypted copy and decrypts with their private key</item>
    /// </list>
    /// <para>
    /// <b>Advantages:</b>
    /// - Simple conceptually
    /// - Each recipient gets their own encrypted copy
    /// - No shared secrets between group members
    /// </para>
    /// <para>
    /// <b>Disadvantages:</b>
    /// - Inefficient for large groups (N encryptions for N recipients)
    /// - More bandwidth usage
    /// </para>
    /// </remarks>
    class Program
    {
        static void Main()
        {
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;

            Console.WriteLine("╔══════════════════════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║      Lucinda E2EE - Group Messaging: Per-Recipient Encryption                    ║");
            Console.WriteLine("║      (Each message encrypted separately for each recipient)                      ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════════════════════════╝");
            Console.WriteLine();

            // Create group members
            using GroupMember alice = new("Alice");
            using GroupMember bob = new("Bob");
            using GroupMember jessica = new("Jessica");

            Console.WriteLine("📋 Group Created: Alice, Bob, Jessica");
            Console.WriteLine();

            // Step 1: Each member generates their key pair
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 1: Each member generates their RSA key pair");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            alice.GenerateKeyPair();
            bob.GenerateKeyPair();
            jessica.GenerateKeyPair();

            Console.WriteLine($"  ✓ Alice generated key pair (Public Key: {CryptoHelpers.ToBase64(alice.PublicKey!)[..20]}...)");
            Console.WriteLine($"  ✓ Bob generated key pair (Public Key: {CryptoHelpers.ToBase64(bob.PublicKey!)[..20]}...)");
            Console.WriteLine($"  ✓ Jessica generated key pair (Public Key: {CryptoHelpers.ToBase64(jessica.PublicKey!)[..20]}...)");
            Console.WriteLine();

            // Step 2: Exchange public keys
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 2: Public keys are exchanged between group members");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            // Bob and Jessica get Alice's public key
            bob.StorePublicKey("Alice", alice.PublicKey!);
            jessica.StorePublicKey("Alice", alice.PublicKey!);
            Console.WriteLine("  ✓ Alice shared her public key with Bob and Jessica");

            // Alice and Jessica get Bob's public key
            alice.StorePublicKey("Bob", bob.PublicKey!);
            jessica.StorePublicKey("Bob", bob.PublicKey!);
            Console.WriteLine("  ✓ Bob shared his public key with Alice and Jessica");

            // Alice and Bob get Jessica's public key
            alice.StorePublicKey("Jessica", jessica.PublicKey!);
            bob.StorePublicKey("Jessica", jessica.PublicKey!);
            Console.WriteLine("  ✓ Jessica shared her public key with Alice and Bob");
            Console.WriteLine();

            // Step 3: Alice sends a message to the group
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 3: Alice sends a message to the group");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            string aliceMessage = "Hello everyone! This is Alice. How are you all doing today? 👋";
            Console.WriteLine($"  Alice's message: \"{aliceMessage}\"");
            Console.WriteLine();

            // Alice encrypts the message separately for Bob and Jessica
            Console.WriteLine("  📤 Alice encrypts the message for EACH recipient separately:");
            Console.WriteLine();

            // Encrypt for Bob
            byte[] encryptedForBob = alice.EncryptMessageFor("Bob", aliceMessage);
            Console.WriteLine($"     🔐 Encrypted for Bob: {CryptoHelpers.ToBase64(encryptedForBob)[..40]}...");

            // Encrypt for Jessica
            byte[] encryptedForJessica = alice.EncryptMessageFor("Jessica", aliceMessage);
            Console.WriteLine($"     🔐 Encrypted for Jessica: {CryptoHelpers.ToBase64(encryptedForJessica)[..40]}...");
            Console.WriteLine();

            Console.WriteLine("     ⚠️  Note: TWO separate encryptions were performed!");
            Console.WriteLine("         (For a group of 100, this would be 99 encryptions)");
            Console.WriteLine();

            // Bob decrypts his copy
            Console.WriteLine("  📥 Bob receives and decrypts his copy:");
            string bobDecrypted = bob.DecryptMessage(encryptedForBob);
            Console.WriteLine($"     Decrypted: \"{bobDecrypted}\"");
            Console.WriteLine();

            // Jessica decrypts her copy
            Console.WriteLine("  📥 Jessica receives and decrypts her copy:");
            string jessicaDecrypted = jessica.DecryptMessage(encryptedForJessica);
            Console.WriteLine($"     Decrypted: \"{jessicaDecrypted}\"");
            Console.WriteLine();

            // Step 4: Bob replies
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 4: Bob replies to the group");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            string bobMessage = "Hey Alice! I'm doing great, thanks for asking! 🎉";
            Console.WriteLine($"  Bob's message: \"{bobMessage}\"");
            Console.WriteLine();

            // Bob encrypts for Alice and Jessica
            Console.WriteLine("  📤 Bob encrypts the message for EACH recipient:");
            Console.WriteLine();

            byte[] encryptedForAlice = bob.EncryptMessageFor("Alice", bobMessage);
            Console.WriteLine($"     🔐 Encrypted for Alice: {CryptoHelpers.ToBase64(encryptedForAlice)[..40]}...");

            byte[] encryptedForJessica2 = bob.EncryptMessageFor("Jessica", bobMessage);
            Console.WriteLine($"     🔐 Encrypted for Jessica: {CryptoHelpers.ToBase64(encryptedForJessica2)[..40]}...");
            Console.WriteLine();

            // Alice and Jessica decrypt
            Console.WriteLine("  📥 Alice receives and decrypts:");
            string aliceDecrypted = alice.DecryptMessage(encryptedForAlice);
            Console.WriteLine($"     Decrypted: \"{aliceDecrypted}\"");
            Console.WriteLine();

            Console.WriteLine("  📥 Jessica receives and decrypts:");
            string jessicaDecrypted2 = jessica.DecryptMessage(encryptedForJessica2);
            Console.WriteLine($"     Decrypted: \"{jessicaDecrypted2}\"");
            Console.WriteLine();

            // Step 5: Demonstrate that messages are unique per recipient
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 5: Verifying unique encryption per recipient");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("  🔍 Comparing encrypted messages for Bob vs Jessica:");
            Console.WriteLine($"     For Bob length: {encryptedForBob.Length} bytes");
            Console.WriteLine($"     For Jessica length: {encryptedForJessica.Length} bytes");

            bool areDifferent = !CryptoHelpers.ConstantTimeEquals(encryptedForBob, encryptedForJessica);
            Console.WriteLine($"     Are they different? {areDifferent} ✓");
            Console.WriteLine();
            Console.WriteLine("  📝 Each recipient gets a completely unique encrypted blob!");
            Console.WriteLine("     - Bob's copy can ONLY be decrypted with Bob's private key");
            Console.WriteLine("     - Jessica's copy can ONLY be decrypted with Jessica's private key");
            Console.WriteLine();

            // Step 6: Demonstrate E2EE is maintained
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 6: Verifying E2EE - Server cannot read messages");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("  🖥️  What the server sees:");
            Console.WriteLine($"     - Encrypted for Bob: {CryptoHelpers.ToBase64(encryptedForBob)[..30]}...");
            Console.WriteLine($"     - Encrypted for Jessica: {CryptoHelpers.ToBase64(encryptedForJessica)[..30]}...");
            Console.WriteLine("     - Sender: Alice");
            Console.WriteLine("     - Timestamp: " + DateTime.UtcNow.ToString("O"));
            Console.WriteLine();
            Console.WriteLine("  🔒 The server CANNOT decrypt because it doesn't have private keys!");
            Console.WriteLine("  ✅ E2EE is maintained - only intended recipients can read");
            Console.WriteLine();

            // Summary
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Summary: Per-Recipient Encryption Approach");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("  ✓ Each member has their own RSA key pair");
            Console.WriteLine("  ✓ Messages encrypted separately for each recipient");
            Console.WriteLine("  ✓ Each recipient can only decrypt their own copy");
            Console.WriteLine("  ✓ E2EE is maintained - server cannot read messages");
            Console.WriteLine();
            Console.WriteLine("  ⚠️  Considerations:");
            Console.WriteLine("     - Inefficient for large groups (N encryptions for N-1 recipients)");
            Console.WriteLine("     - More bandwidth usage (N separate encrypted blobs)");
            Console.WriteLine("     - Better for small groups or 1-on-1 messaging");
            Console.WriteLine();

            Console.WriteLine("✅ Demo completed!");

            if (!Console.IsInputRedirected)
            {
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }
    }

    /// <summary>
    /// Represents a group member with per-recipient encryption capabilities.
    /// </summary>
    class GroupMember(string name) : IDisposable
    {
        private readonly EndToEndEncryption _e2ee = new();
        private readonly Dictionary<string, byte[]> _otherPublicKeys = [];
        private byte[]? _privateKey;
        private bool _disposed;

        public string Name { get; } = name;
        public byte[]? PublicKey { get; private set; }

        /// <summary>
        /// Generates a new key pair for this member.
        /// </summary>
        public void GenerateKeyPair()
        {
            CryptoResult<AsymmetricKeyPair> result = _e2ee.GenerateKeyPair();
            if (result.IsFailure)
            {
                throw new InvalidOperationException($"Key generation failed: {result.Error}");
            }

            PublicKey = result.Value.PublicKey;
            _privateKey = result.Value.PrivateKey;
        }

        /// <summary>
        /// Stores another member's public key.
        /// </summary>
        public void StorePublicKey(string memberName, byte[] publicKey)
        {
            _otherPublicKeys[memberName] = publicKey;
        }

        /// <summary>
        /// Encrypts a message for a specific recipient.
        /// </summary>
        public byte[] EncryptMessageFor(string recipientName, string message)
        {
            if (!_otherPublicKeys.TryGetValue(recipientName, out byte[]? recipientPublicKey))
            {
                throw new InvalidOperationException($"Public key for {recipientName} not found.");
            }

            CryptoResult<byte[]> result = _e2ee.EncryptMessage(message, recipientPublicKey);
            if (result.IsFailure)
            {
                throw new InvalidOperationException($"Encryption failed: {result.Error}");
            }

            return result.Value;
        }

        /// <summary>
        /// Decrypts a message using this member's private key.
        /// </summary>
        public string DecryptMessage(byte[] encryptedMessage)
        {
            if (_privateKey == null)
            {
                throw new InvalidOperationException("Private key not available.");
            }

            CryptoResult<string> result = _e2ee.DecryptMessage(encryptedMessage, _privateKey);
            if (result.IsFailure)
            {
                throw new InvalidOperationException($"Decryption failed: {result.Error}");
            }

            return result.Value;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _e2ee.Dispose();

            if (_privateKey != null)
            {
                CryptoHelpers.SecureClear(_privateKey);
            }

            _disposed = true;
        }
    }
}
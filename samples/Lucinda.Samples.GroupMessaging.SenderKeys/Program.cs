// <copyright file="Program.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Abstractions;
using Lucinda.Symmetric;
using Lucinda.Utilities;
using System.Text;

namespace Lucinda.Samples.GroupMessaging.SenderKeys
{
    /// <summary>
    /// Demonstrates the Sender Keys approach for group E2EE messaging.
    /// Each user creates a "sender key" (symmetric key) that they share with all group members.
    /// When sending a message, the sender encrypts with their own sender key.
    /// All recipients who have the sender key can decrypt.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>How Sender Keys Work:</b>
    /// </para>
    /// <list type="number">
    /// <item>Each user generates a symmetric "sender key" when joining a group</item>
    /// <item>The sender key is encrypted for each group member using their public key and distributed</item>
    /// <item>When sending a message, the user encrypts with their sender key (one encryption for all recipients)</item>
    /// <item>All group members who have that sender key can decrypt the message</item>
    /// </list>
    /// <para>
    /// <b>Advantages:</b>
    /// - Efficient: Only one encryption operation per message (not N encryptions for N recipients)
    /// - Scalable: Works well for large groups
    /// </para>
    /// <para>
    /// <b>Used by:</b> Signal Protocol (for group messages)
    /// </para>
    /// </remarks>
    class Program
    {
        static void Main()
        {
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;

            Console.WriteLine("╔══════════════════════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║      Lucinda E2EE - Group Messaging: Sender Keys Approach                        ║");
            Console.WriteLine("║      (Signal Protocol Style)                                                     ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════════════════════════╝");
            Console.WriteLine();

            // Create group members
            GroupMember alice = new("Alice");
            GroupMember bob = new("Bob");
            GroupMember jessica = new("Jessica");

            Console.WriteLine("📋 Group Created: Alice, Bob, Jessica");
            Console.WriteLine();

            // Step 1: Each member generates a sender key for this group
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 1: Each member generates their Sender Key for the group");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            alice.GenerateSenderKey();
            bob.GenerateSenderKey();
            jessica.GenerateSenderKey();

            Console.WriteLine($"  ✓ Alice generated sender key: {CryptoHelpers.ToBase64(alice.SenderKey!)[..20]}...");
            Console.WriteLine($"  ✓ Bob generated sender key: {CryptoHelpers.ToBase64(bob.SenderKey!)[..20]}...");
            Console.WriteLine($"  ✓ Jessica generated sender key: {CryptoHelpers.ToBase64(jessica.SenderKey!)[..20]}...");
            Console.WriteLine();

            // Step 2: Exchange sender keys (in real app, this would be encrypted with each recipient's public key)
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 2: Sender Keys are distributed to group members");
            Console.WriteLine("        (In production, each key is encrypted with recipient's public key)");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            // Alice shares her sender key with Bob and Jessica
            bob.StoreSenderKey("Alice", alice.SenderKey!);
            jessica.StoreSenderKey("Alice", alice.SenderKey!);
            Console.WriteLine("  ✓ Alice shared her sender key with Bob and Jessica");

            // Bob shares his sender key with Alice and Jessica
            alice.StoreSenderKey("Bob", bob.SenderKey!);
            jessica.StoreSenderKey("Bob", bob.SenderKey!);
            Console.WriteLine("  ✓ Bob shared his sender key with Alice and Jessica");

            // Jessica shares her sender key with Alice and Bob
            alice.StoreSenderKey("Jessica", jessica.SenderKey!);
            bob.StoreSenderKey("Jessica", jessica.SenderKey!);
            Console.WriteLine("  ✓ Jessica shared her sender key with Alice and Bob");
            Console.WriteLine();

            // Step 3: Alice sends a message to the group
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 3: Alice sends a message to the group");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            string aliceMessage = "Hello everyone! This is Alice. How are you all doing today? 👋";
            Console.WriteLine($"  Alice's message: \"{aliceMessage}\"");
            Console.WriteLine();

            // Alice encrypts the message with her sender key (ONE encryption for ALL recipients)
            byte[] encryptedMessage = alice.EncryptMessage(aliceMessage);
            Console.WriteLine($"  📤 Alice encrypts ONCE with her sender key");
            Console.WriteLine($"     Encrypted (Base64): {CryptoHelpers.ToBase64(encryptedMessage)[..50]}...");
            Console.WriteLine();

            // Bob decrypts using Alice's sender key
            Console.WriteLine("  📥 Bob receives and decrypts:");
            string bobDecrypted = bob.DecryptMessage("Alice", encryptedMessage);
            Console.WriteLine($"     Decrypted: \"{bobDecrypted}\"");
            Console.WriteLine();

            // Jessica decrypts using Alice's sender key
            Console.WriteLine("  📥 Jessica receives and decrypts:");
            string jessicaDecrypted = jessica.DecryptMessage("Alice", encryptedMessage);
            Console.WriteLine($"     Decrypted: \"{jessicaDecrypted}\"");
            Console.WriteLine();

            // Step 4: Bob replies
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 4: Bob replies to the group");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            string bobMessage = "Hey Alice! I'm doing great, thanks for asking! 🎉";
            Console.WriteLine($"  Bob's message: \"{bobMessage}\"");
            Console.WriteLine();

            byte[] bobEncrypted = bob.EncryptMessage(bobMessage);
            Console.WriteLine($"  📤 Bob encrypts ONCE with his sender key");
            Console.WriteLine($"     Encrypted (Base64): {CryptoHelpers.ToBase64(bobEncrypted)[..50]}...");
            Console.WriteLine();

            // Alice decrypts Bob's message
            Console.WriteLine("  📥 Alice receives and decrypts:");
            string aliceDecrypted = alice.DecryptMessage("Bob", bobEncrypted);
            Console.WriteLine($"     Decrypted: \"{aliceDecrypted}\"");
            Console.WriteLine();

            // Jessica decrypts Bob's message
            Console.WriteLine("  📥 Jessica receives and decrypts:");
            string jessicaDecrypted2 = jessica.DecryptMessage("Bob", bobEncrypted);
            Console.WriteLine($"     Decrypted: \"{jessicaDecrypted2}\"");
            Console.WriteLine();

            // Step 5: Demonstrate E2EE is maintained
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 5: Verifying E2EE - Server cannot read messages");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("  🖥️  What the server sees:");
            Console.WriteLine($"     - Encrypted blob: {CryptoHelpers.ToBase64(encryptedMessage)[..40]}...");
            Console.WriteLine("     - Sender: Alice");
            Console.WriteLine("     - Recipients: [Bob, Jessica]");
            Console.WriteLine("     - Timestamp: " + DateTime.UtcNow.ToString("O"));
            Console.WriteLine();
            Console.WriteLine("  🔒 The server CANNOT decrypt because it doesn't have the sender keys!");
            Console.WriteLine("  ✅ E2EE is maintained - only group members with the sender key can read");
            Console.WriteLine();

            // Summary
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Summary: Sender Keys Approach");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("  ✓ Each member has one sender key for the group");
            Console.WriteLine("  ✓ Messages are encrypted ONCE regardless of group size");
            Console.WriteLine("  ✓ Very efficient for large groups (1 encryption vs N encryptions)");
            Console.WriteLine("  ✓ E2EE is maintained - server cannot read messages");
            Console.WriteLine();
            Console.WriteLine("  ⚠️  Considerations:");
            Console.WriteLine("     - Sender keys must be re-distributed when members join/leave");
            Console.WriteLine("     - Forward secrecy requires regular key rotation");
            Console.WriteLine();

            // Cleanup
            alice.Dispose();
            bob.Dispose();
            jessica.Dispose();

            Console.WriteLine("✅ Demo completed!");

            if (!Console.IsInputRedirected)
            {
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }
    }

    /// <summary>
    /// Represents a group member with sender key capabilities.
    /// </summary>
    class GroupMember : IDisposable
    {
        private readonly AesGcmEncryption _encryption;
        private readonly Dictionary<string, byte[]> _otherSenderKeys;
        private bool _disposed;

        public string Name { get; }
        public byte[]? SenderKey { get; private set; }

        public GroupMember(string name)
        {
            Name = name;
            _encryption = new AesGcmEncryption(256);
            _otherSenderKeys = [];
        }

        /// <summary>
        /// Generates a new sender key for this group member.
        /// </summary>
        public void GenerateSenderKey()
        {
            SenderKey = SecureRandom.GenerateKey(256);
        }

        /// <summary>
        /// Stores another member's sender key.
        /// </summary>
        public void StoreSenderKey(string memberName, byte[] senderKey)
        {
            _otherSenderKeys[memberName] = senderKey;
        }

        /// <summary>
        /// Encrypts a message using this member's sender key.
        /// </summary>
        public byte[] EncryptMessage(string message)
        {
            if (SenderKey == null)
            {
                throw new InvalidOperationException("Sender key not generated.");
            }

            using AesGcmEncryption encryption = new(SenderKey);
            byte[] messageBytes = CryptoHelpers.GetUtf8Bytes(message);
            CryptoResult<byte[]> result = encryption.Encrypt(messageBytes);

            if (result.IsFailure)
            {
                throw new InvalidOperationException($"Encryption failed: {result.Error}");
            }

            return result.Value;
        }

        /// <summary>
        /// Decrypts a message using another member's sender key.
        /// </summary>
        public string DecryptMessage(string senderName, byte[] encryptedMessage)
        {
            if (!_otherSenderKeys.TryGetValue(senderName, out byte[]? senderKey))
            {
                throw new InvalidOperationException($"Sender key for {senderName} not found.");
            }

            using AesGcmEncryption encryption = new(senderKey);
            CryptoResult<byte[]> result = encryption.Decrypt(encryptedMessage);

            if (result.IsFailure)
            {
                throw new InvalidOperationException($"Decryption failed: {result.Error}");
            }

            return CryptoHelpers.GetUtf8String(result.Value);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _encryption.Dispose();

            if (SenderKey != null)
            {
                CryptoHelpers.SecureClear(SenderKey);
            }

            foreach (byte[] key in _otherSenderKeys.Values)
            {
                CryptoHelpers.SecureClear(key);
            }

            _disposed = true;
        }
    }
}
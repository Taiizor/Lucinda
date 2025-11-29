// <copyright file="Program.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Abstractions;
using Lucinda.Symmetric;
using Lucinda.Utilities;
using System.Security.Cryptography;
using System.Text;

namespace Lucinda.Samples.GroupMessaging.Hybrid
{
    /// <summary>
    /// Demonstrates the Hybrid Encryption approach for group E2EE messaging.
    /// The message is encrypted once with a random AES key, then the AES key is encrypted
    /// separately for each recipient using their RSA public key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>How Hybrid Group Encryption Works:</b>
    /// </para>
    /// <list type="number">
    /// <item>Each user has their own RSA key pair</item>
    /// <item>Public keys are exchanged between all group members</item>
    /// <item>When sending a message:
    ///   <list type="bullet">
    ///     <item>Generate a random AES session key</item>
    ///     <item>Encrypt the message ONCE with AES (fast)</item>
    ///     <item>Encrypt the AES key for EACH recipient using their RSA public key</item>
    ///   </list>
    /// </item>
    /// <item>Send: [Encrypted Message] + [AES Key encrypted for Bob] + [AES Key encrypted for Jessica]</item>
    /// <item>Each recipient decrypts the AES key with their private key, then decrypts the message</item>
    /// </list>
    /// <para>
    /// <b>Advantages:</b>
    /// - Best of both worlds: efficient + secure
    /// - Message encrypted only ONCE (fast AES)
    /// - Only the small AES key is encrypted per-recipient (RSA is slow but key is small)
    /// - Scales well for large groups
    /// </para>
    /// <para>
    /// <b>Used by:</b> PGP/GPG, most modern E2EE implementations for groups
    /// </para>
    /// </remarks>
    class Program
    {
        static void Main()
        {
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;

            Console.WriteLine("╔══════════════════════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║      Lucinda E2EE - Group Messaging: Hybrid Encryption                          ║");
            Console.WriteLine("║      (AES for message + RSA for key distribution - Most Efficient)               ║");
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

            bob.StorePublicKey("Alice", alice.PublicKey!);
            jessica.StorePublicKey("Alice", alice.PublicKey!);
            Console.WriteLine("  ✓ Alice shared her public key with Bob and Jessica");

            alice.StorePublicKey("Bob", bob.PublicKey!);
            jessica.StorePublicKey("Bob", bob.PublicKey!);
            Console.WriteLine("  ✓ Bob shared his public key with Alice and Jessica");

            alice.StorePublicKey("Jessica", jessica.PublicKey!);
            bob.StorePublicKey("Jessica", jessica.PublicKey!);
            Console.WriteLine("  ✓ Jessica shared her public key with Alice and Bob");
            Console.WriteLine();

            // Step 3: Alice sends a message to the group
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 3: Alice sends a message to the group (Hybrid Encryption)");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            string aliceMessage = "Hello everyone! This is Alice. How are you all doing today? 👋";
            Console.WriteLine($"  Alice's message: \"{aliceMessage}\"");
            Console.WriteLine();

            // Alice encrypts using hybrid approach
            Console.WriteLine("  📤 Alice performs Hybrid Encryption:");
            Console.WriteLine();

            GroupMessage groupMessage = alice.EncryptForGroup(aliceMessage, ["Bob", "Jessica"]);

            Console.WriteLine($"     Step 3a: Generate random AES session key (256-bit)");
            Console.WriteLine($"              AES Key: {CryptoHelpers.ToBase64(groupMessage.DebugAesKey!)[..20]}...");
            Console.WriteLine();
            Console.WriteLine($"     Step 3b: Encrypt message ONCE with AES-GCM (fast!)");
            Console.WriteLine($"              Encrypted Message: {CryptoHelpers.ToBase64(groupMessage.EncryptedMessage)[..40]}...");
            Console.WriteLine($"              Message encrypted: 1 time (regardless of group size!)");
            Console.WriteLine();
            Console.WriteLine($"     Step 3c: Encrypt AES key for each recipient with RSA:");
            Console.WriteLine($"              🔑 AES Key for Bob: {CryptoHelpers.ToBase64(groupMessage.EncryptedKeys["Bob"])[..30]}...");
            Console.WriteLine($"              🔑 AES Key for Jessica: {CryptoHelpers.ToBase64(groupMessage.EncryptedKeys["Jessica"])[..30]}...");
            Console.WriteLine($"              Keys encrypted: {groupMessage.EncryptedKeys.Count} times (one per recipient)");
            Console.WriteLine();

            // Show what's sent to the server
            Console.WriteLine("  📦 Package sent to server:");
            Console.WriteLine("     {");
            Console.WriteLine($"       \"encryptedMessage\": \"{CryptoHelpers.ToBase64(groupMessage.EncryptedMessage)[..30]}...\",");
            Console.WriteLine("       \"encryptedKeys\": {");
            Console.WriteLine($"         \"Bob\": \"{CryptoHelpers.ToBase64(groupMessage.EncryptedKeys["Bob"])[..30]}...\",");
            Console.WriteLine($"         \"Jessica\": \"{CryptoHelpers.ToBase64(groupMessage.EncryptedKeys["Jessica"])[..30]}...\"");
            Console.WriteLine("       }");
            Console.WriteLine("     }");
            Console.WriteLine();

            // Bob decrypts
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 4: Bob receives and decrypts");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("  📥 Bob's decryption process:");
            Console.WriteLine($"     Step 4a: Decrypt AES key using Bob's RSA private key");
            Console.WriteLine($"     Step 4b: Use AES key to decrypt the message");

            string bobDecrypted = bob.DecryptGroupMessage(groupMessage);
            Console.WriteLine($"     ✓ Decrypted: \"{bobDecrypted}\"");
            Console.WriteLine();

            // Jessica decrypts
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 5: Jessica receives and decrypts");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("  📥 Jessica's decryption process:");
            Console.WriteLine($"     Step 5a: Decrypt AES key using Jessica's RSA private key");
            Console.WriteLine($"     Step 5b: Use AES key to decrypt the message");

            string jessicaDecrypted = jessica.DecryptGroupMessage(groupMessage);
            Console.WriteLine($"     ✓ Decrypted: \"{jessicaDecrypted}\"");
            Console.WriteLine();

            // Step 6: Bob replies
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 6: Bob replies to the group");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            string bobMessage = "Hey Alice! I'm doing great, thanks for asking! 🎉";
            Console.WriteLine($"  Bob's message: \"{bobMessage}\"");
            Console.WriteLine();

            GroupMessage bobGroupMessage = bob.EncryptForGroup(bobMessage, ["Alice", "Jessica"]);
            Console.WriteLine("  📤 Bob's Hybrid Encryption:");
            Console.WriteLine($"     - Message encrypted ONCE with new AES key");
            Console.WriteLine($"     - AES key encrypted for Alice and Jessica");
            Console.WriteLine();

            string aliceDecrypted = alice.DecryptGroupMessage(bobGroupMessage);
            Console.WriteLine($"  📥 Alice decrypts: \"{aliceDecrypted}\"");

            string jessicaDecrypted2 = jessica.DecryptGroupMessage(bobGroupMessage);
            Console.WriteLine($"  📥 Jessica decrypts: \"{jessicaDecrypted2}\"");
            Console.WriteLine();

            // Efficiency comparison
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 7: Efficiency Comparison");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("  📊 For a group with 100 members sending a 1MB file:");
            Console.WriteLine();
            Console.WriteLine("  ┌─────────────────────────┬────────────────┬─────────────────┐");
            Console.WriteLine("  │ Approach                │ Encryptions    │ Data Sent       │");
            Console.WriteLine("  ├─────────────────────────┼────────────────┼─────────────────┤");
            Console.WriteLine("  │ Per-Recipient           │ 99 (1MB each!) │ ~99 MB          │");
            Console.WriteLine("  │ Sender Keys             │ 1 (1MB)        │ ~1 MB           │");
            Console.WriteLine("  │ Hybrid (This approach)  │ 1 AES + 99 RSA │ ~1 MB + ~25 KB  │");
            Console.WriteLine("  └─────────────────────────┴────────────────┴─────────────────┘");
            Console.WriteLine();
            Console.WriteLine("  🏆 Hybrid is the best balance of security and efficiency!");
            Console.WriteLine();

            // E2EE verification
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Step 8: Verifying E2EE - Server cannot read messages");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("  🖥️  What the server sees:");
            Console.WriteLine($"     - Encrypted message blob (AES-GCM encrypted)");
            Console.WriteLine($"     - Encrypted AES keys (RSA encrypted) for each recipient");
            Console.WriteLine();
            Console.WriteLine("  ❌ Server CANNOT:");
            Console.WriteLine("     - Decrypt the AES key (no private keys)");
            Console.WriteLine("     - Decrypt the message (no AES key)");
            Console.WriteLine("     - Read any content whatsoever");
            Console.WriteLine();
            Console.WriteLine("  ✅ E2EE is FULLY maintained!");
            Console.WriteLine();

            // Summary
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("Summary: Hybrid Encryption Approach");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("  ✓ Message encrypted ONCE with fast symmetric encryption (AES-GCM)");
            Console.WriteLine("  ✓ Only small AES key is encrypted per-recipient (RSA)");
            Console.WriteLine("  ✓ Scales efficiently for large groups");
            Console.WriteLine("  ✓ Each recipient can only decrypt with their private key");
            Console.WriteLine("  ✓ E2EE is maintained - server cannot read messages");
            Console.WriteLine();
            Console.WriteLine("  📝 This is the approach used by:");
            Console.WriteLine("     - PGP/GPG for email encryption");
            Console.WriteLine("     - Most modern messaging apps");
            Console.WriteLine("     - File sharing with multiple recipients");
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
    /// Represents an encrypted group message with per-recipient key encapsulation.
    /// </summary>
    class GroupMessage
    {
        /// <summary>
        /// The message encrypted with AES-GCM (nonce + ciphertext + tag).
        /// </summary>
        public required byte[] EncryptedMessage { get; init; }

        /// <summary>
        /// AES key encrypted for each recipient using their RSA public key.
        /// Key: recipient name, Value: RSA-encrypted AES key.
        /// </summary>
        public required Dictionary<string, byte[]> EncryptedKeys { get; init; }

        /// <summary>
        /// For demo purposes only - shows the AES key used.
        /// In production, this would never be exposed!
        /// </summary>
        public byte[]? DebugAesKey { get; init; }
    }

    /// <summary>
    /// Represents a group member with hybrid encryption capabilities.
    /// </summary>
    class GroupMember : IDisposable
    {
        private readonly Dictionary<string, byte[]> _otherPublicKeys;
        private RSA? _rsa;
        private bool _disposed;

        public string Name { get; }
        public byte[]? PublicKey { get; private set; }

        public GroupMember(string name)
        {
            Name = name;
            _otherPublicKeys = [];
        }

        /// <summary>
        /// Generates a new RSA key pair for this member.
        /// </summary>
        public void GenerateKeyPair()
        {
            _rsa = RSA.Create(2048);
            PublicKey = _rsa.ExportSubjectPublicKeyInfo();
        }

        /// <summary>
        /// Stores another member's public key.
        /// </summary>
        public void StorePublicKey(string memberName, byte[] publicKey)
        {
            _otherPublicKeys[memberName] = publicKey;
        }

        /// <summary>
        /// Encrypts a message for multiple recipients using hybrid encryption.
        /// </summary>
        public GroupMessage EncryptForGroup(string message, string[] recipients)
        {
            // Step 1: Generate random AES session key
            byte[] aesKey = SecureRandom.GenerateKey(256);

            // Step 2: Encrypt message with AES-GCM (ONE encryption)
            byte[] encryptedMessage;
            using (AesGcmEncryption aes = new(aesKey))
            {
                byte[] messageBytes = CryptoHelpers.GetUtf8Bytes(message);
                CryptoResult<byte[]> encryptResult = aes.Encrypt(messageBytes);
                if (encryptResult.IsFailure)
                {
                    throw new InvalidOperationException($"Encryption failed: {encryptResult.Error}");
                }
                encryptedMessage = encryptResult.Value;
            }

            // Step 3: Encrypt AES key for each recipient using their RSA public key
            Dictionary<string, byte[]> encryptedKeys = [];
            foreach (string recipient in recipients)
            {
                if (!_otherPublicKeys.TryGetValue(recipient, out byte[]? recipientPublicKey))
                {
                    throw new InvalidOperationException($"Public key for {recipient} not found.");
                }

                using RSA recipientRsa = RSA.Create();
                recipientRsa.ImportSubjectPublicKeyInfo(recipientPublicKey, out _);
                byte[] encryptedKey = recipientRsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
                encryptedKeys[recipient] = encryptedKey;
            }

            // Create debug copy of AES key (for demo purposes only!)
            byte[] debugKey = new byte[aesKey.Length];
            Array.Copy(aesKey, debugKey, aesKey.Length);

            // Securely clear the AES key
            CryptoHelpers.SecureClear(aesKey);

            return new GroupMessage
            {
                EncryptedMessage = encryptedMessage,
                EncryptedKeys = encryptedKeys,
                DebugAesKey = debugKey
            };
        }

        /// <summary>
        /// Decrypts a group message using this member's private key.
        /// </summary>
        public string DecryptGroupMessage(GroupMessage groupMessage)
        {
            if (_rsa == null)
            {
                throw new InvalidOperationException("Key pair not generated.");
            }

            // Find this member's encrypted key
            if (!groupMessage.EncryptedKeys.TryGetValue(Name, out byte[]? encryptedKey))
            {
                throw new InvalidOperationException($"No encrypted key found for {Name}.");
            }

            // Step 1: Decrypt AES key using our RSA private key
            byte[] aesKey = _rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);

            try
            {
                // Step 2: Decrypt message using AES key
                using AesGcmEncryption aes = new(aesKey);
                CryptoResult<byte[]> decryptResult = aes.Decrypt(groupMessage.EncryptedMessage);
                if (decryptResult.IsFailure)
                {
                    throw new InvalidOperationException($"Decryption failed: {decryptResult.Error}");
                }

                return CryptoHelpers.GetUtf8String(decryptResult.Value);
            }
            finally
            {
                // Securely clear the AES key
                CryptoHelpers.SecureClear(aesKey);
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _rsa?.Dispose();
            _disposed = true;
        }
    }
}
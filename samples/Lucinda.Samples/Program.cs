// <copyright file="Program.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Abstractions;
using Lucinda.KeyDerivation;
using Lucinda.Symmetric;
using Lucinda.Utilities;
using System.Text;

namespace Lucinda.Samples
{
    class Program
    {
        static async Task Main()
        {
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;

            Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║              Lucinda E2EE Library - Sample Application           ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
            Console.WriteLine();

            // Run all demonstrations
            DemonstrateSymmetricEncryption();
            DemonstrateEndToEndEncryption();
            DemonstrateDigitalSignatures();
            DemonstrateKeyDerivation();
            DemonstrateEncryptAndSign();
            DemonstrateUtilityFunctions();

            Console.WriteLine("\n✅ All demonstrations completed successfully!");

            // Only wait for key press if running interactively
            if (!Console.IsInputRedirected)
            {
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }

        // ============================================================================
        // DEMONSTRATION METHODS
        // ============================================================================

        static void DemonstrateSymmetricEncryption()
        {
            PrintHeader("1. Symmetric Encryption (AES-GCM)");

            // Create AES-GCM encryption with 256-bit key
            using AesGcmEncryption aes = new(256);

            string originalMessage = "Hello, this is a secret message!";
            byte[] plaintext = CryptoHelpers.GetUtf8Bytes(originalMessage);

            Console.WriteLine($"Original Message: {originalMessage}");
            Console.WriteLine($"Key Size: {aes.KeySizeInBits} bits");
            Console.WriteLine($"Algorithm: {aes.AlgorithmName}");

            // Encrypt
            CryptoResult<byte[]> encryptResult = aes.Encrypt(plaintext);
            if (encryptResult.IsSuccess)
            {
                Console.WriteLine($"Encrypted (Base64): {CryptoHelpers.ToBase64(encryptResult.Value)[..50]}...");

                // Decrypt
                CryptoResult<byte[]> decryptResult = aes.Decrypt(encryptResult.Value);
                if (decryptResult.IsSuccess)
                {
                    string decryptedMessage = CryptoHelpers.GetUtf8String(decryptResult.Value);
                    Console.WriteLine($"Decrypted Message: {decryptedMessage}");
                    Console.WriteLine($"✓ Encryption/Decryption successful!");
                }
            }

            // With Associated Data (AAD)
            Console.WriteLine("\n--- With Associated Data (AAD) ---");
            byte[] metadata = CryptoHelpers.GetUtf8Bytes("user-id:12345");
            CryptoResult<byte[]> encryptWithAad = aes.Encrypt(plaintext, metadata);
            if (encryptWithAad.IsSuccess)
            {
                CryptoResult<byte[]> decryptWithAad = aes.Decrypt(encryptWithAad.Value, metadata);
                Console.WriteLine($"✓ AAD encryption/decryption successful!");

                // Try decrypting with wrong AAD (should fail)
                byte[] wrongAad = CryptoHelpers.GetUtf8Bytes("wrong-metadata");
                CryptoResult<byte[]> failedDecrypt = aes.Decrypt(encryptWithAad.Value, wrongAad);
                Console.WriteLine($"✓ Wrong AAD correctly rejected: {failedDecrypt.IsFailure}");
            }
        }

        static void DemonstrateEndToEndEncryption()
        {
            PrintHeader("2. End-to-End Encryption (Alice & Bob)");

            using EndToEndEncryption e2ee = new();

            // Generate key pairs for Alice and Bob
            Console.WriteLine("Generating key pairs for Alice and Bob...");
            CryptoResult<AsymmetricKeyPair> aliceKeyPair = e2ee.GenerateKeyPair();
            CryptoResult<AsymmetricKeyPair> bobKeyPair = e2ee.GenerateKeyPair();

            Console.WriteLine($"Alice's Public Key: {CryptoHelpers.ToBase64(aliceKeyPair.Value.PublicKey)[..30]}...");
            Console.WriteLine($"Bob's Public Key: {CryptoHelpers.ToBase64(bobKeyPair.Value.PublicKey)[..30]}...");

            // Alice sends a message to Bob
            string secretMessage = "Hello Bob! This message is encrypted just for you. 🔐";
            Console.WriteLine($"\nAlice's Message: {secretMessage}");

            // Alice encrypts for Bob (using Bob's public key)
            CryptoResult<byte[]> encrypted = e2ee.EncryptMessage(secretMessage, bobKeyPair.Value.PublicKey);
            if (encrypted.IsSuccess)
            {
                Console.WriteLine($"Encrypted (Base64): {CryptoHelpers.ToBase64(encrypted.Value)[..50]}...");

                // Bob decrypts (using his private key)
                CryptoResult<string> decrypted = e2ee.DecryptMessage(encrypted.Value, bobKeyPair.Value.PrivateKey);
                if (decrypted.IsSuccess)
                {
                    Console.WriteLine($"Bob decrypts: {decrypted.Value}");
                    Console.WriteLine("✓ End-to-end encryption successful!");
                }

                // Alice tries to decrypt (should fail - she doesn't have Bob's private key)
                CryptoResult<string> aliceFails = e2ee.DecryptMessage(encrypted.Value, aliceKeyPair.Value.PrivateKey);
                Console.WriteLine($"✓ Alice cannot decrypt (correct): {aliceFails.IsFailure}");
            }

            // Binary data encryption
            Console.WriteLine("\n--- Binary Data Encryption ---");
            byte[] binaryData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE, 0xFD };
            CryptoResult<byte[]> encryptedData = e2ee.EncryptData(binaryData, aliceKeyPair.Value.PublicKey);
            if (encryptedData.IsSuccess)
            {
                CryptoResult<byte[]> decryptedData = e2ee.DecryptData(encryptedData.Value, aliceKeyPair.Value.PrivateKey);
                Console.WriteLine($"Original bytes: {BitConverter.ToString(binaryData)}");
                Console.WriteLine($"Decrypted bytes: {BitConverter.ToString(decryptedData.Value)}");
                Console.WriteLine("✓ Binary data encryption successful!");
            }
        }

        static void DemonstrateDigitalSignatures()
        {
            PrintHeader("3. Digital Signatures (ECDSA)");

            using EndToEndEncryption e2ee = new();

            // Generate signing key pair
            CryptoResult<AsymmetricKeyPair> signingKeyPair = e2ee.GenerateSigningKeyPair();
            Console.WriteLine($"Signing Public Key: {CryptoHelpers.ToBase64(signingKeyPair.Value.PublicKey)[..30]}...");

            // Sign a document
            byte[] document = CryptoHelpers.GetUtf8Bytes("This is an important contract that needs to be signed.");

            CryptoResult<byte[]> signature = e2ee.SignData(document, signingKeyPair.Value.PrivateKey);
            if (signature.IsSuccess)
            {
                Console.WriteLine($"Document signed!");
                Console.WriteLine($"Signature (Base64): {CryptoHelpers.ToBase64(signature.Value)[..40]}...");

                // Verify signature
                CryptoResult<bool> isValid = e2ee.VerifySignature(document, signature.Value, signingKeyPair.Value.PublicKey);
                Console.WriteLine($"Signature valid: {isValid.Value}");
                Console.WriteLine("✓ Digital signature verification successful!");

                // Tamper with document and verify again
                byte[] tamperedDocument = CryptoHelpers.GetUtf8Bytes("This contract has been tampered with!");
                CryptoResult<bool> isTamperedValid = e2ee.VerifySignature(tamperedDocument, signature.Value, signingKeyPair.Value.PublicKey);
                Console.WriteLine($"✓ Tampered document correctly rejected: {!isTamperedValid.Value}");
            }
        }

        static void DemonstrateKeyDerivation()
        {
            PrintHeader("4. Key Derivation (PBKDF2)");

            using EndToEndEncryption e2ee = new();

            string password = "MySecurePassword123!";
            byte[] salt = SecureRandom.GenerateSalt(32);

            Console.WriteLine($"Password: {password}");
            Console.WriteLine($"Salt (Base64): {CryptoHelpers.ToBase64(salt)}");

            // Derive key from password
            CryptoResult<(byte[] Key, byte[] Salt)> derivedKey = e2ee.DeriveKeyFromPassword(password, salt);
            if (derivedKey.IsSuccess)
            {
                Console.WriteLine($"Derived Key (Base64): {CryptoHelpers.ToBase64(derivedKey.Value.Key)}");
                Console.WriteLine($"Key Salt (Base64): {CryptoHelpers.ToBase64(derivedKey.Value.Salt)}");

                // Derive again with same inputs - should get same key
                CryptoResult<(byte[] Key, byte[] Salt)> derivedKey2 = e2ee.DeriveKeyFromPassword(password, salt);
                bool keysMatch = CryptoHelpers.ConstantTimeEquals(derivedKey.Value.Key, derivedKey2.Value.Key);
                Console.WriteLine($"✓ Same password + salt = Same key: {keysMatch}");

                // Different salt = different key
                byte[] differentSalt = SecureRandom.GenerateSalt(32);
                CryptoResult<(byte[] Key, byte[] Salt)> derivedKey3 = e2ee.DeriveKeyFromPassword(password, differentSalt);
                bool keysDiffer = !CryptoHelpers.ConstantTimeEquals(derivedKey.Value.Key, derivedKey3.Value.Key);
                Console.WriteLine($"✓ Different salt = Different key: {keysDiffer}");
            }

            // HKDF demonstration
            Console.WriteLine("\n--- HKDF Key Derivation ---");
            using HkdfKeyDerivation hkdf = new();
            byte[] sharedSecret = SecureRandom.GenerateSalt(32); // Simulated shared secret from key exchange
            byte[] hkdfSalt = SecureRandom.GenerateSalt(32);
            byte[] info = CryptoHelpers.GetUtf8Bytes("encryption-key-v1");

            CryptoResult<byte[]> encryptionKey = hkdf.DeriveKey(sharedSecret, hkdfSalt, info, 32);
            Console.WriteLine($"Derived Encryption Key (32 bytes): {CryptoHelpers.ToBase64(encryptionKey.Value)}");

            // Derive a different key for authentication
            byte[] authInfo = CryptoHelpers.GetUtf8Bytes("authentication-key-v1");
            CryptoResult<byte[]> authKey = hkdf.DeriveKey(sharedSecret, hkdfSalt, authInfo, 32);
            Console.WriteLine($"Derived Auth Key (32 bytes): {CryptoHelpers.ToBase64(authKey.Value)}");
            Console.WriteLine("✓ HKDF key derivation successful!");
        }

        static void DemonstrateEncryptAndSign()
        {
            PrintHeader("5. Encrypt and Sign (Complete E2EE)");

            using EndToEndEncryption e2ee = new();

            // Alice (sender) has signing keys
            CryptoResult<AsymmetricKeyPair> aliceSigningKeyPair = e2ee.GenerateSigningKeyPair();

            // Bob (recipient) has encryption keys
            CryptoResult<AsymmetricKeyPair> bobKeyPair = e2ee.GenerateKeyPair();

            byte[] message = CryptoHelpers.GetUtf8Bytes("This message is both encrypted AND signed by Alice!");

            Console.WriteLine("Alice encrypts and signs a message for Bob...");

            // Alice encrypts for Bob and signs with her key
            CryptoResult<SignedEncryptedData> signedEncrypted = e2ee.EncryptAndSign(
                message,
                bobKeyPair.Value.PublicKey,
                aliceSigningKeyPair.Value.PrivateKey);

            if (signedEncrypted.IsSuccess)
            {
                Console.WriteLine($"Encrypted Data Length: {signedEncrypted.Value.EncryptedData.Length} bytes");
                Console.WriteLine($"Signature Length: {signedEncrypted.Value.Signature.Length} bytes");

                // Bob verifies Alice's signature and decrypts
                CryptoResult<byte[]> decrypted = e2ee.VerifyAndDecrypt(
                    signedEncrypted.Value,
                    bobKeyPair.Value.PrivateKey,
                    aliceSigningKeyPair.Value.PublicKey);

                if (decrypted.IsSuccess)
                {
                    Console.WriteLine($"Bob decrypts: {CryptoHelpers.GetUtf8String(decrypted.Value)}");
                    Console.WriteLine("✓ Message verified as from Alice and decrypted by Bob!");
                }

                // Try with wrong signing key (should fail)
                CryptoResult<AsymmetricKeyPair> eveSigningKeyPair = e2ee.GenerateSigningKeyPair();
                CryptoResult<byte[]> eveVerify = e2ee.VerifyAndDecrypt(
                    signedEncrypted.Value,
                    bobKeyPair.Value.PrivateKey,
                    eveSigningKeyPair.Value.PublicKey);
                Console.WriteLine($"✓ Wrong signer (Eve) correctly rejected: {eveVerify.IsFailure}");
            }
        }

        static void DemonstrateUtilityFunctions()
        {
            PrintHeader("6. Utility Functions");

            // Secure random generation
            Console.WriteLine("--- Secure Random ---");
            byte[] randomBytes = SecureRandom.GenerateBytes(16);
            Console.WriteLine($"Random bytes (16): {CryptoHelpers.ToHexString(randomBytes)}");

            byte[] randomSalt = SecureRandom.GenerateSalt(32);
            Console.WriteLine($"Random salt (32): {CryptoHelpers.ToHexString(randomSalt)}");

            // Encoding helpers
            Console.WriteLine("\n--- Encoding Helpers ---");
            string originalText = "Hello, World! 🌍";
            byte[] utf8Bytes = CryptoHelpers.GetUtf8Bytes(originalText);
            string backToText = CryptoHelpers.GetUtf8String(utf8Bytes);
            Console.WriteLine($"UTF-8 roundtrip: '{originalText}' → bytes → '{backToText}'");

            // Base64
            string base64 = CryptoHelpers.ToBase64(utf8Bytes);
            byte[] fromBase64 = CryptoHelpers.FromBase64(base64);
            Console.WriteLine($"Base64: {base64}");
            Console.WriteLine($"✓ Base64 roundtrip successful: {CryptoHelpers.ConstantTimeEquals(utf8Bytes, fromBase64)}");

            // Hex
            string hex = CryptoHelpers.ToHexString(utf8Bytes);
            byte[] fromHex = CryptoHelpers.FromHexString(hex);
            Console.WriteLine($"Hex: {hex}");
            Console.WriteLine($"✓ Hex roundtrip successful: {CryptoHelpers.ConstantTimeEquals(utf8Bytes, fromHex)}");

            // Hash functions
            Console.WriteLine("\n--- Hash Functions ---");
            byte[] data = CryptoHelpers.GetUtf8Bytes("Data to hash");
            Console.WriteLine($"SHA-256: {CryptoHelpers.ToHexString(CryptoHelpers.ComputeSha256(data))}");
            Console.WriteLine($"SHA-384: {CryptoHelpers.ToHexString(CryptoHelpers.ComputeSha384(data))[..60]}...");
            Console.WriteLine($"SHA-512: {CryptoHelpers.ToHexString(CryptoHelpers.ComputeSha512(data))[..60]}...");

            // HMAC
            Console.WriteLine("\n--- HMAC ---");
            byte[] key = SecureRandom.GenerateBytes(32);
            byte[] hmac = CryptoHelpers.ComputeHmacSha256(key, data);
            Console.WriteLine($"HMAC-SHA256: {CryptoHelpers.ToHexString(hmac)}");

            // Constant-time comparison
            Console.WriteLine("\n--- Constant-Time Comparison ---");
            byte[] a = new byte[] { 1, 2, 3, 4, 5 };
            byte[] b = new byte[] { 1, 2, 3, 4, 5 };
            byte[] c = new byte[] { 1, 2, 3, 4, 6 };
            Console.WriteLine($"a == b: {CryptoHelpers.ConstantTimeEquals(a, b)}");
            Console.WriteLine($"a == c: {CryptoHelpers.ConstantTimeEquals(a, c)}");
            Console.WriteLine("✓ Constant-time comparison prevents timing attacks!");
        }

        static void PrintHeader(string title)
        {
            Console.WriteLine();
            Console.WriteLine($"╔{'═'.ToString().PadRight(title.Length + 4, '═')}╗");
            Console.WriteLine($"║  {title}  ║");
            Console.WriteLine($"╚{'═'.ToString().PadRight(title.Length + 4, '═')}╝");
            Console.WriteLine();
        }
    }
}
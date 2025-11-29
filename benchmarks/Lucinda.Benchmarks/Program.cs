// <copyright file="Program.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using System.Text;

namespace Lucinda.Benchmarks
{
    /// <summary>
    /// Entry point for Lucinda cryptographic benchmarks.
    /// </summary>
    internal static class Program
    {
        /// <summary>
        /// Main entry point for the benchmark application.
        /// </summary>
        /// <param name="args">Command line arguments.</param>
        private static void Main(string[] args)
        {
            // Ensure UTF-8 encoding for console
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;

            // Configure benchmarks with optimization validator disabled for development
            ManualConfig config = DefaultConfig.Instance
                .WithOptions(ConfigOptions.DisableOptimizationsValidator);

            Console.WriteLine("╔════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║           Lucinda Cryptographic Library Benchmarks          ║");
            Console.WriteLine("╚════════════════════════════════════════════════════════════╝");
            Console.WriteLine();
            Console.WriteLine("Available benchmark suites:");
            Console.WriteLine("  1. Symmetric Encryption (AES-GCM, AES-CBC)");
            Console.WriteLine("  2. Asymmetric Encryption (RSA, Hybrid RSA+AES)");
            Console.WriteLine("  3. Key Derivation (PBKDF2, HKDF)");
            Console.WriteLine("  4. Digital Signatures (ECDSA, RSA-PSS)");
            Console.WriteLine("  5. End-to-End Encryption (High-level API)");
            Console.WriteLine("  6. Utility Operations (Hashing, HMAC, Random)");
            Console.WriteLine("  7. Secure Messaging (X3DH, Double Ratchet)");
            Console.WriteLine("  8. All Benchmarks");
            Console.WriteLine();

            if (args.Length > 0)
            {
                // Command-line mode: run specific benchmark or all
                RunBenchmark(args[0], config);
            }
            else
            {
                // Interactive mode
                Console.Write("Select benchmark suite (1-8): ");
                string? input = Console.ReadLine();

                if (string.IsNullOrEmpty(input))
                {
                    Console.WriteLine("No selection made. Running all benchmarks...");
                    input = "8";
                }

                RunBenchmark(input, config);
            }

            Console.WriteLine();
            Console.WriteLine("Benchmarks completed.");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        private static void RunBenchmark(string selection, ManualConfig config)
        {
            switch (selection.Trim())
            {
                case "1":
                case "symmetric":
                    Console.WriteLine("\nRunning Symmetric Encryption Benchmarks...\n");
                    BenchmarkRunner.Run<SymmetricEncryptionBenchmarks>(config);
                    break;

                case "2":
                case "asymmetric":
                    Console.WriteLine("\nRunning Asymmetric Encryption Benchmarks...\n");
                    BenchmarkRunner.Run<AsymmetricEncryptionBenchmarks>(config);
                    break;

                case "3":
                case "kdf":
                case "keyderivation":
                    Console.WriteLine("\nRunning Key Derivation Benchmarks...\n");
                    BenchmarkRunner.Run<KeyDerivationBenchmarks>(config);
                    break;

                case "4":
                case "signature":
                case "signatures":
                    Console.WriteLine("\nRunning Signature Benchmarks...\n");
                    BenchmarkRunner.Run<SignatureBenchmarks>(config);
                    break;

                case "5":
                case "e2ee":
                case "e2e":
                    Console.WriteLine("\nRunning End-to-End Encryption Benchmarks...\n");
                    BenchmarkRunner.Run<EndToEndEncryptionBenchmarks>(config);
                    break;

                case "6":
                case "utility":
                case "utils":
                    Console.WriteLine("\nRunning Utility Benchmarks...\n");
                    BenchmarkRunner.Run<UtilityBenchmarks>(config);
                    break;

                case "7":
                case "secure":
                case "messaging":
                case "signal":
                    Console.WriteLine("\nRunning Secure Messaging Benchmarks...\n");
                    BenchmarkRunner.Run<SecureMessagingBenchmarks>(config);
                    break;

                case "8":
                case "all":
                default:
                    Console.WriteLine("\nRunning All Benchmarks...\n");
                    BenchmarkRunner.Run(
                    [
                        typeof(SymmetricEncryptionBenchmarks),
                        typeof(AsymmetricEncryptionBenchmarks),
                        typeof(KeyDerivationBenchmarks),
                        typeof(SignatureBenchmarks),
                        typeof(EndToEndEncryptionBenchmarks),
                        typeof(UtilityBenchmarks),
                        typeof(SecureMessagingBenchmarks)
                    ], config);
                    break;
            }
        }
    }
}
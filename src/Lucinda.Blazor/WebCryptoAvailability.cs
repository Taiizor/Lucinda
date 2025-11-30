// -----------------------------------------------------------------------
// <copyright file="WebCryptoAvailability.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Blazor.Interop;

namespace Lucinda.Blazor
{
    /// <summary>
    /// Service to check Web Crypto API availability and supported algorithms.
    /// </summary>
    public class WebCryptoAvailability
    {
        private readonly WebCryptoInterop _webCrypto;

        /// <summary>
        /// Initializes a new instance of the <see cref="WebCryptoAvailability"/> class.
        /// </summary>
        /// <param name="webCrypto">The Web Crypto interop service.</param>
        public WebCryptoAvailability(WebCryptoInterop webCrypto)
        {
            _webCrypto = webCrypto ?? throw new ArgumentNullException(nameof(webCrypto));
        }

        /// <summary>
        /// Checks if the Web Crypto API is available in the current browser.
        /// </summary>
        /// <returns>True if Web Crypto API is available; otherwise, false.</returns>
        public async Task<bool> IsAvailableAsync()
        {
            return await _webCrypto.IsWebCryptoAvailableAsync();
        }

        /// <summary>
        /// Gets the list of supported algorithms in the current browser.
        /// </summary>
        /// <returns>A SupportedAlgorithms object containing all supported algorithms.</returns>
        public async Task<SupportedAlgorithms> GetSupportedAlgorithmsAsync()
        {
            return await _webCrypto.GetSupportedAlgorithmsAsync();
        }

        /// <summary>
        /// Checks if a specific algorithm is supported.
        /// </summary>
        /// <param name="algorithmName">The algorithm name (e.g., "AES-GCM", "RSA-OAEP", "ECDH").</param>
        /// <returns>True if the algorithm is supported; otherwise, false.</returns>
        public async Task<bool> IsAlgorithmSupportedAsync(string algorithmName)
        {
            SupportedAlgorithms supported = await GetSupportedAlgorithmsAsync();

            return algorithmName.ToUpperInvariant() switch
            {
                "AES-GCM" => supported.Symmetric.Contains("AES-GCM"),
                "AES-CBC" => supported.Symmetric.Contains("AES-CBC"),
                "RSA-OAEP" => supported.Asymmetric.Contains("RSA-OAEP"),
                "ECDH" => supported.KeyExchange.Contains("ECDH"),
                "ECDSA" => supported.Signatures.Contains("ECDSA"),
                "RSA-PSS" => supported.Signatures.Contains("RSA-PSS"),
                "HKDF" => supported.KeyDerivation.Contains("HKDF"),
                "PBKDF2" => supported.KeyDerivation.Contains("PBKDF2"),
                "SHA-256" or "SHA-384" or "SHA-512" => supported.Hashes.Contains(algorithmName.ToUpperInvariant()),
                _ => false
            };
        }

        /// <summary>
        /// Performs a comprehensive check of all crypto capabilities.
        /// </summary>
        /// <returns>A diagnostic result with detailed information.</returns>
        public async Task<CryptoDiagnostics> RunDiagnosticsAsync()
        {
            CryptoDiagnostics diagnostics = new()
            {
                IsWebCryptoAvailable = await IsAvailableAsync()
            };

            if (!diagnostics.IsWebCryptoAvailable)
            {
                return diagnostics;
            }

            SupportedAlgorithms supported = await GetSupportedAlgorithmsAsync();

            diagnostics.SupportedEncryption = supported.Symmetric.Concat(supported.Asymmetric).ToArray();
            diagnostics.SupportedKeyExchange = supported.KeyExchange;
            diagnostics.SupportedSignature = supported.Signatures;
            diagnostics.SupportedKeyDerivation = supported.KeyDerivation;
            diagnostics.SupportedHash = supported.Hashes;

            // Test basic functionality
            try
            {
                byte[] randomBytes = await _webCrypto.GetRandomBytesAsync(32);
                diagnostics.CanGenerateRandomBytes = randomBytes.Length == 32;
            }
            catch
            {
                diagnostics.CanGenerateRandomBytes = false;
            }

            return diagnostics;
        }
    }

    /// <summary>
    /// Contains diagnostic information about Web Crypto API capabilities.
    /// </summary>
    public class CryptoDiagnostics
    {
        /// <summary>
        /// Gets or sets whether Web Crypto API is available.
        /// </summary>
        public bool IsWebCryptoAvailable { get; set; }

        /// <summary>
        /// Gets or sets whether random byte generation works.
        /// </summary>
        public bool CanGenerateRandomBytes { get; set; }

        /// <summary>
        /// Gets or sets the list of supported encryption algorithms.
        /// </summary>
        public string[] SupportedEncryption { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Gets or sets the list of supported key exchange algorithms.
        /// </summary>
        public string[] SupportedKeyExchange { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Gets or sets the list of supported signature algorithms.
        /// </summary>
        public string[] SupportedSignature { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Gets or sets the list of supported key derivation algorithms.
        /// </summary>
        public string[] SupportedKeyDerivation { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Gets or sets the list of supported hash algorithms.
        /// </summary>
        public string[] SupportedHash { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Gets whether all expected algorithms are available.
        /// </summary>
        public bool AllAlgorithmsSupported =>
            IsWebCryptoAvailable &&
            SupportedEncryption.Contains("AES-GCM") &&
            SupportedKeyExchange.Contains("ECDH") &&
            SupportedSignature.Contains("ECDSA") &&
            SupportedKeyDerivation.Contains("HKDF") &&
            SupportedHash.Contains("SHA-256");
    }
}

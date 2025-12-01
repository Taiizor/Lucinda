// <copyright file="CryptoProviderFactory.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Abstractions;
using Lucinda.Platform.Native;

#if NET7_0_OR_GREATER
using Lucinda.Platform.Browser;
#endif

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Platform
{
    /// <summary>
    /// Factory for creating platform-appropriate <see cref="ICryptoProvider"/> instances.
    /// Automatically selects the correct implementation based on the current runtime environment.
    /// </summary>
    public static class CryptoProviderFactory
    {
        private static ICryptoProvider? _defaultProvider;

#if NET9_0_OR_GREATER
        private static readonly Lock _lock = new();
#else
        private static readonly object _lock = new();
#endif

        /// <summary>
        /// Gets or creates the default crypto provider for the current platform.
        /// </summary>
        /// <returns>An <see cref="ICryptoProvider"/> appropriate for the current platform.</returns>
        /// <remarks>
        /// <para>
        /// This method returns a cached singleton instance. For browser environments (Blazor WebAssembly),
        /// it returns a BrowserCryptoProvider that uses the Web Crypto API.
        /// For native environments, it returns a <see cref="NativeCryptoProvider"/> that uses
        /// the standard .NET cryptography APIs.
        /// </para>
        /// <para>
        /// The provider instance is thread-safe and can be used concurrently.
        /// </para>
        /// </remarks>
        public static ICryptoProvider GetProvider()
        {
            if (_defaultProvider != null)
            {
                return _defaultProvider;
            }

            lock (_lock)
            {
                if (_defaultProvider != null)
                {
                    return _defaultProvider;
                }

                _defaultProvider = CreateProvider();
                return _defaultProvider;
            }
        }

        /// <summary>
        /// Creates a new crypto provider for the current platform.
        /// </summary>
        /// <returns>A new <see cref="ICryptoProvider"/> instance appropriate for the current platform.</returns>
        /// <remarks>
        /// Unlike <see cref="GetProvider"/>, this method always creates a new instance.
        /// Use this when you need a dedicated provider instance with its own lifecycle.
        /// </remarks>
        public static ICryptoProvider CreateProvider()
        {
#if NET7_0_OR_GREATER
            if (CryptoPlatform.IsBrowser)
            {
#pragma warning disable CA1416 // Validate platform compatibility
                return new BrowserCryptoProvider();
#pragma warning restore CA1416
            }
#endif
            return new NativeCryptoProvider();
        }

        /// <summary>
        /// Creates a crypto provider for the specified platform type.
        /// </summary>
        /// <param name="platformType">The platform type to create the provider for.</param>
        /// <returns>
        /// A <see cref="CryptoResult{T}"/> containing the provider on success,
        /// or an error message if the platform is not supported.
        /// </returns>
        public static CryptoResult<ICryptoProvider> CreateProvider(CryptoPlatformType platformType)
        {
            try
            {
                return platformType switch
                {
                    CryptoPlatformType.Native => CryptoResult<ICryptoProvider>.Success(new NativeCryptoProvider()),
#if NET7_0_OR_GREATER
#pragma warning disable CA1416 // Validate platform compatibility
                    CryptoPlatformType.Browser => CryptoResult<ICryptoProvider>.Success(new BrowserCryptoProvider()),
#pragma warning restore CA1416
#else
                    CryptoPlatformType.Browser => CryptoResult<ICryptoProvider>.Failure(
                        "Browser crypto provider is only available in .NET 7.0 or later."),
#endif
                    CryptoPlatformType.Wasi => CryptoResult<ICryptoProvider>.Failure(
                        "WASI crypto provider is not yet implemented."),
                    _ => CryptoResult<ICryptoProvider>.Failure($"Unknown platform type: {platformType}")
                };
            }
            catch (Exception ex)
            {
                return CryptoResult<ICryptoProvider>.Failure($"Failed to create crypto provider: {ex.Message}");
            }
        }

        /// <summary>
        /// Checks whether the specified platform type is supported in the current runtime.
        /// </summary>
        /// <param name="platformType">The platform type to check.</param>
        /// <returns><c>true</c> if the platform is supported; otherwise, <c>false</c>.</returns>
        public static bool IsPlatformSupported(CryptoPlatformType platformType)
        {
            return platformType switch
            {
                CryptoPlatformType.Native => true,
#if NET5_0_OR_GREATER
                CryptoPlatformType.Browser => true,
#else
                CryptoPlatformType.Browser => false,
#endif
                CryptoPlatformType.Wasi => false,
                _ => false
            };
        }

        /// <summary>
        /// Resets the default provider. Used primarily for testing.
        /// </summary>
        internal static void Reset()
        {
            lock (_lock)
            {
                _defaultProvider?.Dispose();
                _defaultProvider = null;
            }
        }
    }
}
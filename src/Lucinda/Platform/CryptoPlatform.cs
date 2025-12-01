// <copyright file="CryptoPlatform.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Platform
{
    /// <summary>
    /// Provides platform detection utilities for determining the current runtime environment.
    /// Used to select appropriate cryptographic implementations based on platform capabilities.
    /// </summary>
    public static class CryptoPlatform
    {
        private static bool? _isBrowser;
        private static bool? _isWasi;
        private static CryptoPlatformType? _platformType;

        /// <summary>
        /// Gets a value indicating whether the current runtime is a browser environment (Blazor WebAssembly).
        /// </summary>
        /// <value><c>true</c> if running in a browser; otherwise, <c>false</c>.</value>
        public static bool IsBrowser
        {
            get
            {
                if (_isBrowser.HasValue)
                {
                    return _isBrowser.Value;
                }

#if NET5_0_OR_GREATER
                _isBrowser = OperatingSystem.IsBrowser();
#else
                // For older frameworks, browser is never supported
                _isBrowser = false;
#endif
                return _isBrowser.Value;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the current runtime is WebAssembly System Interface (WASI).
        /// </summary>
        /// <value><c>true</c> if running in WASI; otherwise, <c>false</c>.</value>
        public static bool IsWasi
        {
            get
            {
                if (_isWasi.HasValue)
                {
                    return _isWasi.Value;
                }

#if NET8_0_OR_GREATER
                _isWasi = OperatingSystem.IsWasi();
#else
                _isWasi = false;
#endif
                return _isWasi.Value;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the current runtime is a WebAssembly environment (Browser or WASI).
        /// </summary>
        /// <value><c>true</c> if running in WebAssembly; otherwise, <c>false</c>.</value>
        public static bool IsWebAssembly => IsBrowser || IsWasi;

        /// <summary>
        /// Gets a value indicating whether native .NET cryptography APIs are fully supported.
        /// </summary>
        /// <value><c>true</c> if native crypto is available; otherwise, <c>false</c>.</value>
        /// <remarks>
        /// Native cryptography APIs are NOT supported in Blazor WebAssembly environments.
        /// In those environments, only limited APIs (SHA256, SHA384, SHA512, RandomNumberGenerator) are available.
        /// </remarks>
        public static bool IsNativeCryptoSupported => !IsWebAssembly;

        /// <summary>
        /// Gets the current platform type for cryptographic operations.
        /// </summary>
        /// <value>The <see cref="CryptoPlatformType"/> for the current runtime.</value>
        public static CryptoPlatformType PlatformType
        {
            get
            {
                if (_platformType.HasValue)
                {
                    return _platformType.Value;
                }

                if (IsBrowser)
                {
                    _platformType = CryptoPlatformType.Browser;
                }
                else if (IsWasi)
                {
                    _platformType = CryptoPlatformType.Wasi;
                }
                else
                {
                    _platformType = CryptoPlatformType.Native;
                }

                return _platformType.Value;
            }
        }

        /// <summary>
        /// Throws a <see cref="PlatformNotSupportedException"/> if running in a browser environment.
        /// </summary>
        /// <param name="featureName">The name of the feature that is not supported.</param>
        /// <exception cref="PlatformNotSupportedException">Thrown when running in a browser environment.</exception>
        public static void ThrowIfBrowser(string featureName)
        {
            if (IsBrowser)
            {
                throw new PlatformNotSupportedException(
                    $"{featureName} is not supported in Blazor WebAssembly. " +
                    "Use the browser-compatible implementation via ICryptoProvider or Web Crypto API interop.");
            }
        }

        /// <summary>
        /// Throws a <see cref="PlatformNotSupportedException"/> if native crypto is not supported.
        /// </summary>
        /// <param name="featureName">The name of the feature that requires native crypto.</param>
        /// <exception cref="PlatformNotSupportedException">Thrown when native crypto is not available.</exception>
        public static void ThrowIfNativeCryptoNotSupported(string featureName)
        {
            if (!IsNativeCryptoSupported)
            {
                throw new PlatformNotSupportedException(
                    $"{featureName} requires native cryptography APIs which are not available in this environment. " +
                    "Use browser-compatible alternatives when running in Blazor WebAssembly.");
            }
        }

        /// <summary>
        /// Resets the cached platform detection values. Used primarily for testing.
        /// </summary>
        internal static void ResetCache()
        {
            _isBrowser = null;
            _isWasi = null;
            _platformType = null;
        }
    }
}
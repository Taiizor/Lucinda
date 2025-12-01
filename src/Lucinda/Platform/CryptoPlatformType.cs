// <copyright file="CryptoPlatformType.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Platform
{
    /// <summary>
    /// Defines the types of platforms for cryptographic operations.
    /// </summary>
    public enum CryptoPlatformType
    {
        /// <summary>
        /// Native .NET runtime with full cryptography API support.
        /// Includes desktop, server, and mobile platforms (Windows, Linux, macOS, iOS, Android).
        /// </summary>
        Native = 0,

        /// <summary>
        /// Browser environment (Blazor WebAssembly).
        /// Limited .NET cryptography APIs; requires Web Crypto API for most operations.
        /// </summary>
        Browser = 1,

        /// <summary>
        /// WebAssembly System Interface (WASI) environment.
        /// May have limited cryptography support depending on the runtime.
        /// </summary>
        Wasi = 2
    }
}
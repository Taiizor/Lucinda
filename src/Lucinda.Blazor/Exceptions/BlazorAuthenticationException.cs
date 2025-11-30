// <copyright file="BlazorAuthenticationException.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor.Exceptions
{
    /// <summary>
    /// Exception thrown when cryptographic authentication fails in Blazor
    /// (e.g., MAC verification, signature verification).
    /// </summary>
    [Serializable]
    public class BlazorAuthenticationException : BlazorLucindaException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorAuthenticationException"/> class.
        /// </summary>
        public BlazorAuthenticationException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorAuthenticationException"/> class
        /// with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public BlazorAuthenticationException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorAuthenticationException"/> class
        /// with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public BlazorAuthenticationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
// <copyright file="BlazorDecryptionException.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor.Exceptions
{
    /// <summary>
    /// Exception thrown when a decryption operation fails in Blazor.
    /// </summary>
    [Serializable]
    public class BlazorDecryptionException : BlazorLucindaException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorDecryptionException"/> class.
        /// </summary>
        public BlazorDecryptionException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorDecryptionException"/> class
        /// with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public BlazorDecryptionException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorDecryptionException"/> class
        /// with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public BlazorDecryptionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
// <copyright file="BlazorLucindaException.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor.Exceptions
{
    /// <summary>
    /// The base exception class for all Lucinda.Blazor cryptographic exceptions.
    /// </summary>
    [Serializable]
    public class BlazorLucindaException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorLucindaException"/> class.
        /// </summary>
        public BlazorLucindaException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorLucindaException"/> class
        /// with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public BlazorLucindaException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorLucindaException"/> class
        /// with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public BlazorLucindaException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
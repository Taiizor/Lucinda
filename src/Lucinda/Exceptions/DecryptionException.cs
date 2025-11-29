// <copyright file="DecryptionException.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
using System.Runtime.Serialization;
#endif

namespace Lucinda.Exceptions
{
    /// <summary>
    /// Exception thrown when a decryption operation fails.
    /// </summary>
    [Serializable]
    public class DecryptionException : LucindaException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptionException"/> class.
        /// </summary>
        public DecryptionException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptionException"/> class
        /// with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public DecryptionException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptionException"/> class
        /// with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public DecryptionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NETFRAMEWORK || NETSTANDARD2_0
        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptionException"/> class
        /// with serialized data.
        /// </summary>
        /// <param name="info">The serialization info.</param>
        /// <param name="context">The streaming context.</param>
        protected DecryptionException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
#endif
    }
}
// <copyright file="LucindaException.cs" company="Lucinda">
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
    /// The base exception class for all Lucinda cryptographic exceptions.
    /// </summary>
    [Serializable]
    public class LucindaException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="LucindaException"/> class.
        /// </summary>
        public LucindaException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LucindaException"/> class
        /// with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public LucindaException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LucindaException"/> class
        /// with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public LucindaException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NETFRAMEWORK || NETSTANDARD2_0
        /// <summary>
        /// Initializes a new instance of the <see cref="LucindaException"/> class
        /// with serialized data.
        /// </summary>
        /// <param name="info">The serialization info.</param>
        /// <param name="context">The streaming context.</param>
        protected LucindaException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
#endif
    }
}
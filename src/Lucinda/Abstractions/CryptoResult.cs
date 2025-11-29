// <copyright file="CryptoResult.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NETFRAMEWORK || NETSTANDARD
using System;
#endif

namespace Lucinda.Abstractions
{
    /// <summary>
    /// Represents the result of a cryptographic operation, encapsulating either a successful result or an error.
    /// This type follows the Result pattern for safe error handling without exceptions.
    /// </summary>
    /// <typeparam name="T">The type of the successful result value.</typeparam>
    public sealed class CryptoResult<T>
    {
        private readonly T? _value;
        private readonly string? _error;

        private CryptoResult(T? value, string? error, bool isSuccess)
        {
            _value = value;
            _error = error;
            IsSuccess = isSuccess;
        }

        /// <summary>
        /// Gets a value indicating whether the operation was successful.
        /// </summary>
        /// <value><c>true</c> if the operation succeeded; otherwise, <c>false</c>.</value>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets a value indicating whether the operation failed.
        /// </summary>
        /// <value><c>true</c> if the operation failed; otherwise, <c>false</c>.</value>
        public bool IsFailure => !IsSuccess;

        /// <summary>
        /// Gets the result value if the operation was successful.
        /// </summary>
        /// <value>The result value.</value>
        /// <exception cref="InvalidOperationException">Thrown when accessing the value of a failed result.</exception>
        public T Value
        {
            get
            {
                if (!IsSuccess)
                {
                    throw new InvalidOperationException($"Cannot access value of a failed result. Error: {_error}");
                }
                return _value!;
            }
        }

        /// <summary>
        /// Gets the error message if the operation failed.
        /// </summary>
        /// <value>The error message.</value>
        /// <exception cref="InvalidOperationException">Thrown when accessing the error of a successful result.</exception>
        public string Error
        {
            get
            {
                if (IsSuccess)
                {
                    throw new InvalidOperationException("Cannot access error of a successful result.");
                }
                return _error!;
            }
        }

        /// <summary>
        /// Creates a successful result with the specified value.
        /// </summary>
        /// <param name="value">The result value.</param>
        /// <returns>A successful <see cref="CryptoResult{T}"/> containing the value.</returns>
        public static CryptoResult<T> Success(T value)
        {
            return new CryptoResult<T>(value, null, true);
        }

        /// <summary>
        /// Creates a failed result with the specified error message.
        /// </summary>
        /// <param name="error">The error message describing the failure.</param>
        /// <returns>A failed <see cref="CryptoResult{T}"/> containing the error.</returns>
        public static CryptoResult<T> Failure(string error)
        {
            return new CryptoResult<T>(default, error, false);
        }

        /// <summary>
        /// Gets the value if successful, or the specified default value if failed.
        /// </summary>
        /// <param name="defaultValue">The default value to return if the operation failed.</param>
        /// <returns>The result value if successful; otherwise, the default value.</returns>
        public T GetValueOrDefault(T defaultValue)
        {
            return IsSuccess ? _value! : defaultValue;
        }

        /// <summary>
        /// Matches the result to one of two functions based on success or failure.
        /// </summary>
        /// <typeparam name="TResult">The type of the match result.</typeparam>
        /// <param name="onSuccess">The function to execute if the operation was successful.</param>
        /// <param name="onFailure">The function to execute if the operation failed.</param>
        /// <returns>The result of the executed function.</returns>
        public TResult Match<TResult>(Func<T, TResult> onSuccess, Func<string, TResult> onFailure)
        {
            if (onSuccess == null)
            {
                throw new ArgumentNullException(nameof(onSuccess));
            }

            if (onFailure == null)
            {
                throw new ArgumentNullException(nameof(onFailure));
            }

            return IsSuccess ? onSuccess(_value!) : onFailure(_error!);
        }
    }
}
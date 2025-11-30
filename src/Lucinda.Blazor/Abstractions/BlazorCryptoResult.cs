// <copyright file="BlazorCryptoResult.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

namespace Lucinda.Blazor.Abstractions
{
    /// <summary>
    /// Represents the result of a cryptographic operation in Blazor,
    /// encapsulating either a successful result or an error.
    /// This type follows the Result pattern for safe error handling without exceptions.
    /// </summary>
    /// <typeparam name="T">The type of the successful result value.</typeparam>
    public sealed class BlazorCryptoResult<T>
    {
        private readonly T? _value;
        private readonly string? _error;

        private BlazorCryptoResult(T? value, string? error, bool isSuccess)
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
        /// <returns>A successful <see cref="BlazorCryptoResult{T}"/> containing the value.</returns>
        public static BlazorCryptoResult<T> Success(T value)
        {
            return new BlazorCryptoResult<T>(value, null, true);
        }

        /// <summary>
        /// Creates a failed result with the specified error message.
        /// </summary>
        /// <param name="error">The error message describing the failure.</param>
        /// <returns>A failed <see cref="BlazorCryptoResult{T}"/> containing the error.</returns>
        public static BlazorCryptoResult<T> Failure(string error)
        {
            return new BlazorCryptoResult<T>(default, error, false);
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
        /// Tries to get the value if successful.
        /// </summary>
        /// <param name="value">The value if successful.</param>
        /// <returns>True if successful; otherwise, false.</returns>
        public bool TryGetValue(out T? value)
        {
            if (IsSuccess)
            {
                value = _value;
                return true;
            }
            value = default;
            return false;
        }

        /// <summary>
        /// Maps the result to a new type using the specified function.
        /// </summary>
        /// <typeparam name="TResult">The type of the new result.</typeparam>
        /// <param name="mapper">The function to transform the value.</param>
        /// <returns>A new result with the transformed value, or the same error if failed.</returns>
        public BlazorCryptoResult<TResult> Map<TResult>(Func<T, TResult> mapper)
        {
            if (IsSuccess)
            {
                return BlazorCryptoResult<TResult>.Success(mapper(_value!));
            }
            return BlazorCryptoResult<TResult>.Failure(_error!);
        }

        /// <summary>
        /// Executes the specified action if the result is successful.
        /// </summary>
        /// <param name="action">The action to execute.</param>
        /// <returns>The current result for chaining.</returns>
        public BlazorCryptoResult<T> OnSuccess(Action<T> action)
        {
            if (IsSuccess)
            {
                action(_value!);
            }
            return this;
        }

        /// <summary>
        /// Executes the specified action if the result is a failure.
        /// </summary>
        /// <param name="action">The action to execute with the error message.</param>
        /// <returns>The current result for chaining.</returns>
        public BlazorCryptoResult<T> OnFailure(Action<string> action)
        {
            if (IsFailure)
            {
                action(_error!);
            }
            return this;
        }
    }
}
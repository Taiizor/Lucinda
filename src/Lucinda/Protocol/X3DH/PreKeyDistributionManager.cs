// <copyright file="PreKeyDistributionManager.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

#if NET6_0_OR_GREATER
namespace Lucinda.Protocol.X3DH
{
    /// <summary>
    /// Thread-safe manager for one-time pre-key distribution in server-side scenarios.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class wraps a <see cref="PreKeyBundleWithPrivateKeys"/> and provides atomic,
    /// thread-safe operations for consuming one-time pre-key pairs. It is designed for
    /// server-side use where multiple concurrent requests may need to consume keys.
    /// </para>
    /// <para>
    /// Unlike the <see cref="PreKeyBundle.ConsumeOneTimePreKey"/> method which requires
    /// external synchronization, this manager handles all locking internally.
    /// </para>
    /// <para>
    /// <b>Note:</b> This class does not support key replenishment. Once keys are consumed,
    /// they cannot be added back. The <see cref="KeysRunningLow"/> event fires only once
    /// when the threshold is first crossed. To reset this behavior, create a new manager
    /// instance with a fresh bundle.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var manager = new PreKeyDistributionManager(bundleWithPrivates);
    /// manager.LowKeyThreshold = 5;
    /// manager.KeysRunningLow += count => Console.WriteLine($"Warning: Only {count} keys remaining!");
    /// 
    /// // Thread-safe consumption
    /// var keyPair = manager.ConsumeKeyPair();
    /// if (keyPair.HasValue)
    /// {
    ///     // Use keyPair.Value.Id, keyPair.Value.PublicKey, keyPair.Value.PrivateKey
    /// }
    /// </code>
    /// </example>
    /// <param name="bundleWithPrivates">The pre-key bundle with private keys to manage.</param>
    /// <exception cref="ArgumentNullException">Thrown when bundleWithPrivates is null.</exception>
    public sealed class PreKeyDistributionManager(PreKeyBundleWithPrivateKeys bundleWithPrivates)
    {
        private readonly object _lock = new();
        private readonly PreKeyBundleWithPrivateKeys _bundleWithPrivates = bundleWithPrivates ?? throw new ArgumentNullException(nameof(bundleWithPrivates));
        private bool _lowKeyEventFired = false;

        /// <summary>
        /// Gets or sets the threshold at which the <see cref="KeysRunningLow"/> event is raised.
        /// </summary>
        /// <value>The number of remaining keys that triggers the low key warning. Default is 10.</value>
        public int LowKeyThreshold { get; set; } = 10;

        /// <summary>
        /// Occurs when the number of remaining keys falls to or below the <see cref="LowKeyThreshold"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The event handler receives the current remaining key count as a parameter.
        /// Use this event to trigger key replenishment workflows.
        /// </para>
        /// <para>
        /// This event fires only once when the count first drops to or below the threshold.
        /// It will not fire again for subsequent consumptions. To reset this behavior,
        /// create a new manager instance with a fresh bundle containing replenished keys.
        /// </para>
        /// </remarks>
        public event Action<int>? KeysRunningLow;

        /// <summary>
        /// Occurs when all one-time pre-keys have been consumed.
        /// </summary>
        public event Action? KeysExhausted;

        /// <summary>
        /// Gets the number of remaining one-time pre-keys (thread-safe snapshot).
        /// </summary>
        /// <value>The current count of available one-time pre-keys.</value>
        public int RemainingKeyCount
        {
            get
            {
                lock (_lock)
                {
                    return _bundleWithPrivates.Bundle.OneTimePreKeysCount;
                }
            }
        }

        /// <summary>
        /// Gets a value indicating whether there are any one-time pre-keys remaining.
        /// </summary>
        /// <value><c>true</c> if keys are available; otherwise, <c>false</c>.</value>
        public bool HasKeysAvailable
        {
            get
            {
                lock (_lock)
                {
                    return _bundleWithPrivates.Bundle.HasOneTimePreKey;
                }
            }
        }

        /// <summary>
        /// Gets the underlying public pre-key bundle.
        /// </summary>
        /// <value>The public pre-key bundle (identity key, signed pre-key, etc.).</value>
        /// <remarks>
        /// <para>
        /// This provides access only to the non-consumable parts of the bundle (identity key,
        /// signed pre-key, etc.). For one-time pre-key access, always use
        /// <see cref="ConsumeKeyPair"/> instead of calling
        /// <see cref="PreKeyBundle.ConsumeOneTimePreKey"/> or manipulating
        /// <see cref="PreKeyBundle.OneTimePreKeys"/> directly.
        /// </para>
        /// <para>
        /// The underlying <see cref="PreKeyBundle"/> type is not thread-safe for consuming
        /// one-time pre-keys. Invoking its mutating members (such as consuming or modifying
        /// one-time pre-keys) from multiple threads can bypass the synchronization provided by
        /// <see cref="PreKeyDistributionManager"/> and lead to race conditions or duplicate
        /// key consumption. If you must use such members, you are responsible for providing
        /// appropriate external synchronization.
        /// </para>
        /// </remarks>
        public PreKeyBundle Bundle => _bundleWithPrivates.Bundle;

        /// <summary>
        /// Atomically consumes and returns a one-time pre-key pair (public + private).
        /// </summary>
        /// <returns>
        /// A tuple containing the key ID, public key, and private key; or <c>null</c> if no keys are available.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method is thread-safe. Multiple threads can call this method concurrently
        /// without risk of race conditions or duplicate key consumption.
        /// </para>
        /// <para>
        /// The method automatically fires the <see cref="KeysRunningLow"/> event when the
        /// remaining key count falls below <see cref="LowKeyThreshold"/>, and the
        /// <see cref="KeysExhausted"/> event when all keys have been consumed.
        /// </para>
        /// </remarks>
        public (int Id, byte[] PublicKey, byte[] PrivateKey)? ConsumeKeyPair()
        {
            (int Id, byte[] PublicKey, byte[] PrivateKey)? result = null;
            int remainingCount;
            bool wasLastKey = false;
            bool shouldFireLowKeyEvent = false;

            lock (_lock)
            {
                (int Id, byte[] Key)? consumed = _bundleWithPrivates.Bundle.ConsumeOneTimePreKey();
                if (consumed is null)
                {
                    return null;
                }

                byte[]? privateKey = _bundleWithPrivates.ConsumeOneTimePreKeyPrivate(consumed.Value.Id);
                if (privateKey is null)
                {
                    // This indicates a programming error or data corruption - the public and private
                    // key collections are out of sync. This should never happen under normal operation
                    // when the bundle is created through proper APIs.
                    throw new InvalidOperationException(
                        $"Bundle state inconsistency detected: Private key not found for public key ID {consumed.Value.Id}. " +
                        "This may indicate data corruption or improper bundle manipulation.");
                }

                result = (consumed.Value.Id, consumed.Value.Key, privateKey);
                remainingCount = _bundleWithPrivates.Bundle.OneTimePreKeysCount;
                wasLastKey = remainingCount == 0;

                // Check if we should fire the low key event (only once when threshold is first crossed)
                if (!_lowKeyEventFired && remainingCount <= LowKeyThreshold && remainingCount > 0)
                {
                    _lowKeyEventFired = true;
                    shouldFireLowKeyEvent = true;
                }
            }

            // Fire events outside the lock to prevent deadlocks
            if (wasLastKey)
            {
                KeysExhausted?.Invoke();
            }
            else if (shouldFireLowKeyEvent)
            {
                KeysRunningLow?.Invoke(remainingCount);
            }

            return result;
        }

        /// <summary>
        /// Gets a specific one-time pre-key pair by ID without consuming it.
        /// </summary>
        /// <param name="id">The one-time pre-key ID.</param>
        /// <returns>
        /// A tuple containing the public key and private key; or <c>null</c> if the key ID is not found.
        /// </returns>
        /// <remarks>
        /// This method does not remove the key from the bundle. Use <see cref="ConsumeKeyPair"/>
        /// for atomic consumption.
        /// </remarks>
        public (byte[] PublicKey, byte[] PrivateKey)? GetKeyPair(int id)
        {
            lock (_lock)
            {
                byte[]? publicKey = _bundleWithPrivates.Bundle.GetOneTimePreKey(id);
                if (publicKey is null)
                {
                    return null;
                }

                byte[]? privateKey = _bundleWithPrivates.GetOneTimePreKeyPrivate(id);
                if (privateKey is null)
                {
                    return null;
                }

                return (publicKey, privateKey);
            }
        }

        /// <summary>
        /// Consumes a specific one-time pre-key pair by ID.
        /// </summary>
        /// <param name="id">The one-time pre-key ID to consume.</param>
        /// <returns>
        /// A tuple containing the public key and private key; or <c>null</c> if the key ID is not found.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method is useful when a specific key ID has already been allocated to a client
        /// and needs to be consumed on subsequent message processing.
        /// </para>
        /// <para>
        /// This method is thread-safe and fires appropriate events.
        /// </para>
        /// </remarks>
        public (byte[] PublicKey, byte[] PrivateKey)? ConsumeKeyPairById(int id)
        {
            (byte[] PublicKey, byte[] PrivateKey)? result = null;
            int remainingCount;
            bool wasLastKey = false;
            bool shouldFireLowKeyEvent = false;

            lock (_lock)
            {
                // First, retrieve both keys before any mutations to ensure atomicity
                byte[]? publicKey = _bundleWithPrivates.Bundle.GetOneTimePreKey(id);
                if (publicKey is null)
                {
                    return null;
                }

                byte[]? privateKey = _bundleWithPrivates.GetOneTimePreKeyPrivate(id);
                if (privateKey is null)
                {
                    return null;
                }

                // Now remove both keys atomically
                _bundleWithPrivates.Bundle.RemoveOneTimePreKey(id);
                _bundleWithPrivates.OneTimePreKeyPrivates.Remove(id);

                result = (publicKey, privateKey);
                remainingCount = _bundleWithPrivates.Bundle.OneTimePreKeysCount;
                wasLastKey = remainingCount == 0;

                // Check if we should fire the low key event (only once when threshold is first crossed)
                if (!_lowKeyEventFired && remainingCount <= LowKeyThreshold && remainingCount > 0)
                {
                    _lowKeyEventFired = true;
                    shouldFireLowKeyEvent = true;
                }
            }

            // Fire events outside the lock
            if (wasLastKey)
            {
                KeysExhausted?.Invoke();
            }
            else if (shouldFireLowKeyEvent)
            {
                KeysRunningLow?.Invoke(remainingCount);
            }

            return result;
        }
    }
}
#endif
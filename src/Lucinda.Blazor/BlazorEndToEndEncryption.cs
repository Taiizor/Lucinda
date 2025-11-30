// <copyright file="BlazorEndToEndEncryption.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>

using Lucinda.Abstractions;
using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Asymmetric;
using Lucinda.Blazor.Interop;
using Lucinda.Blazor.KeyDerivation;
using Lucinda.Blazor.Signatures;
using System.Text;

namespace Lucinda.Blazor;

/// <summary>
/// Provides high-level end-to-end encryption operations combining multiple cryptographic primitives
/// for Blazor WebAssembly applications.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="BlazorEndToEndEncryption"/> class provides:
/// <list type="bullet">
/// <item><description>Simplified API for common E2EE scenarios in the browser</description></item>
/// <item><description>Secure defaults using Web Crypto API</description></item>
/// <item><description>RSA-OAEP + AES-GCM hybrid encryption</description></item>
/// <item><description>ECDSA message signing and verification</description></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Inject BlazorEndToEndEncryption via DI
/// @inject BlazorEndToEndEncryption E2EE
/// 
/// // Generate key pairs for Alice and Bob
/// var aliceKeyPair = await E2EE.GenerateKeyPairAsync();
/// var bobKeyPair = await E2EE.GenerateKeyPairAsync();
/// 
/// // Alice encrypts a message for Bob
/// var encrypted = await E2EE.EncryptMessageAsync("Hello, Bob!", bobKeyPair.PublicKey);
/// 
/// // Bob decrypts the message
/// var decrypted = await E2EE.DecryptMessageAsync(encrypted, bobKeyPair.PrivateKey);
/// </code>
/// </example>
public sealed class BlazorEndToEndEncryption : IAsyncDisposable
{
    private readonly BlazorRsaAesHybridEncryption _hybridEncryption;
    private readonly BlazorEcdsaSignature? _signature;
    private readonly BlazorHkdfKeyDerivation _hkdf;
    private readonly BlazorEndToEndEncryptionOptions _options;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorEndToEndEncryption"/> class.
    /// </summary>
    /// <param name="interop">The Web Crypto interop service.</param>
    public BlazorEndToEndEncryption(WebCryptoInterop interop)
        : this(interop, new BlazorEndToEndEncryptionOptions())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorEndToEndEncryption"/> class with the specified options.
    /// </summary>
    /// <param name="interop">The Web Crypto interop service.</param>
    /// <param name="options">The configuration options for E2EE operations.</param>
    /// <exception cref="ArgumentNullException">Thrown when parameters are null.</exception>
    public BlazorEndToEndEncryption(WebCryptoInterop interop, BlazorEndToEndEncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(interop);
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _hybridEncryption = new BlazorRsaAesHybridEncryption(interop);

        if (options.EnableSignatures)
        {
            _signature = new BlazorEcdsaSignature(interop, options.SignatureCurve, options.HashAlgorithm);
        }

        _hkdf = new BlazorHkdfKeyDerivation(interop, options.HashAlgorithm);
    }

    /// <summary>
    /// Gets a value indicating whether signatures are enabled.
    /// </summary>
    public bool SignaturesEnabled => _options.EnableSignatures;

    /// <summary>
    /// Generates a new RSA key pair for encryption and decryption.
    /// </summary>
    /// <returns>The generated key pair as a tuple of (PublicKey, PrivateKey).</returns>
    public async Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateKeyPairAsync()
    {
        ThrowIfDisposed();
        return await _hybridEncryption.GenerateKeyPairAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Generates a new ECDSA key pair for digital signatures.
    /// </summary>
    /// <returns>The generated signing key pair as a tuple of (PublicKey, PrivateKey).</returns>
    /// <exception cref="InvalidOperationException">Thrown when signatures are not enabled.</exception>
    public async Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateSigningKeyPairAsync()
    {
        ThrowIfDisposed();

        if (_signature == null)
        {
            throw new InvalidOperationException("Signatures are not enabled.");
        }

        CryptoResult<AsymmetricKeyPair> result = await _signature.GenerateKeyPairAsync().ConfigureAwait(false);
        if (result.IsFailure)
        {
            throw new InvalidOperationException($"Failed to generate signing key pair: {result.Error}");
        }

        return (result.Value.PublicKey, result.Value.PrivateKey);
    }

    /// <summary>
    /// Encrypts a string message for a recipient.
    /// </summary>
    /// <param name="message">The plaintext message to encrypt.</param>
    /// <param name="recipientPublicKey">The recipient's RSA public key.</param>
    /// <returns>The encrypted data as bytes.</returns>
    /// <exception cref="ArgumentException">Thrown when message is null or empty.</exception>
    public async Task<byte[]> EncryptMessageAsync(string message, byte[] recipientPublicKey)
    {
        ThrowIfDisposed();

        if (string.IsNullOrEmpty(message))
        {
            throw new ArgumentException("Message cannot be null or empty.", nameof(message));
        }

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        return await EncryptDataAsync(messageBytes, recipientPublicKey).ConfigureAwait(false);
    }

    /// <summary>
    /// Encrypts binary data for a recipient.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="recipientPublicKey">The recipient's RSA public key.</param>
    /// <returns>The encrypted data as bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when parameters are null.</exception>
    public async Task<byte[]> EncryptDataAsync(byte[] data, byte[] recipientPublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        BlazorHybridEncryptedData encryptedData = await _hybridEncryption.EncryptAsync(data, recipientPublicKey)
            .ConfigureAwait(false);

        return encryptedData.ToBytes();
    }

    /// <summary>
    /// Encrypts data with additional authenticated data.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="recipientPublicKey">The recipient's RSA public key.</param>
    /// <param name="associatedData">Additional data to authenticate but not encrypt.</param>
    /// <returns>The encrypted data as bytes.</returns>
    public async Task<byte[]> EncryptDataAsync(byte[] data, byte[] recipientPublicKey, byte[] associatedData)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(associatedData);

        BlazorHybridEncryptedData encryptedData = await _hybridEncryption.EncryptAsync(data, recipientPublicKey, associatedData)
            .ConfigureAwait(false);

        return encryptedData.ToBytes();
    }

    /// <summary>
    /// Decrypts a message using the recipient's private key.
    /// </summary>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <param name="recipientPrivateKey">The recipient's RSA private key.</param>
    /// <returns>The decrypted message string.</returns>
    public async Task<string> DecryptMessageAsync(byte[] encryptedData, byte[] recipientPrivateKey)
    {
        ThrowIfDisposed();

        byte[] decryptedBytes = await DecryptDataAsync(encryptedData, recipientPrivateKey).ConfigureAwait(false);
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    /// <summary>
    /// Decrypts binary data using the recipient's private key.
    /// </summary>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <param name="recipientPrivateKey">The recipient's RSA private key.</param>
    /// <returns>The decrypted data.</returns>
    public async Task<byte[]> DecryptDataAsync(byte[] encryptedData, byte[] recipientPrivateKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(encryptedData);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);

        BlazorHybridEncryptedData hybridData = BlazorHybridEncryptedData.FromBytes(encryptedData);
        return await _hybridEncryption.DecryptAsync(hybridData, recipientPrivateKey).ConfigureAwait(false);
    }

    /// <summary>
    /// Decrypts data with additional authenticated data verification.
    /// </summary>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <param name="recipientPrivateKey">The recipient's RSA private key.</param>
    /// <param name="associatedData">Additional data to verify.</param>
    /// <returns>The decrypted data.</returns>
    public async Task<byte[]> DecryptDataAsync(byte[] encryptedData, byte[] recipientPrivateKey, byte[] associatedData)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(encryptedData);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ArgumentNullException.ThrowIfNull(associatedData);

        BlazorHybridEncryptedData hybridData = BlazorHybridEncryptedData.FromBytes(encryptedData);
        return await _hybridEncryption.DecryptAsync(hybridData, recipientPrivateKey, associatedData).ConfigureAwait(false);
    }

    /// <summary>
    /// Signs data with the sender's private key.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="senderPrivateKey">The sender's ECDSA private key.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="InvalidOperationException">Thrown when signatures are not enabled.</exception>
    public async Task<byte[]> SignDataAsync(byte[] data, byte[] senderPrivateKey)
    {
        ThrowIfDisposed();

        if (_signature == null)
        {
            throw new InvalidOperationException("Signatures are not enabled.");
        }

        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(senderPrivateKey);

        CryptoResult<byte[]> result = await _signature.SignAsync(data, senderPrivateKey).ConfigureAwait(false);
        if (result.IsFailure)
        {
            throw new InvalidOperationException($"Signing failed: {result.Error}");
        }

        return result.Value;
    }

    /// <summary>
    /// Verifies a signature on data.
    /// </summary>
    /// <param name="data">The original data.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="senderPublicKey">The sender's ECDSA public key.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    /// <exception cref="InvalidOperationException">Thrown when signatures are not enabled.</exception>
    public async Task<bool> VerifySignatureAsync(byte[] data, byte[] signature, byte[] senderPublicKey)
    {
        ThrowIfDisposed();

        if (_signature == null)
        {
            throw new InvalidOperationException("Signatures are not enabled.");
        }

        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(senderPublicKey);

        CryptoResult<bool> result = await _signature.VerifyAsync(data, signature, senderPublicKey).ConfigureAwait(false);
        if (result.IsFailure)
        {
            throw new InvalidOperationException($"Verification failed: {result.Error}");
        }

        return result.Value;
    }

    /// <summary>
    /// Encrypts and signs data for a recipient.
    /// </summary>
    /// <param name="data">The data to encrypt and sign.</param>
    /// <param name="recipientPublicKey">The recipient's RSA public key.</param>
    /// <param name="senderPrivateKey">The sender's ECDSA private key for signing.</param>
    /// <returns>The signed and encrypted data.</returns>
    /// <exception cref="InvalidOperationException">Thrown when signatures are not enabled.</exception>
    public async Task<BlazorSignedEncryptedData> EncryptAndSignAsync(
        byte[] data,
        byte[] recipientPublicKey,
        byte[] senderPrivateKey)
    {
        ThrowIfDisposed();

        if (_signature == null)
        {
            throw new InvalidOperationException("Signatures are not enabled.");
        }

        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(senderPrivateKey);

        // Encrypt the data
        byte[] encryptedData = await EncryptDataAsync(data, recipientPublicKey).ConfigureAwait(false);

        // Sign the encrypted data
        CryptoResult<byte[]> signResult = await _signature.SignAsync(encryptedData, senderPrivateKey).ConfigureAwait(false);
        if (signResult.IsFailure)
        {
            throw new InvalidOperationException($"Signing failed: {signResult.Error}");
        }

        return new BlazorSignedEncryptedData(encryptedData, signResult.Value);
    }

    /// <summary>
    /// Verifies and decrypts signed encrypted data.
    /// </summary>
    /// <param name="signedEncryptedData">The signed encrypted data.</param>
    /// <param name="recipientPrivateKey">The recipient's RSA private key.</param>
    /// <param name="senderPublicKey">The sender's ECDSA public key for verification.</param>
    /// <returns>The decrypted data if signature is valid.</returns>
    /// <exception cref="InvalidOperationException">Thrown when signatures are not enabled or signature is invalid.</exception>
    public async Task<byte[]> VerifyAndDecryptAsync(
        BlazorSignedEncryptedData signedEncryptedData,
        byte[] recipientPrivateKey,
        byte[] senderPublicKey)
    {
        ThrowIfDisposed();

        if (_signature == null)
        {
            throw new InvalidOperationException("Signatures are not enabled.");
        }

        ArgumentNullException.ThrowIfNull(signedEncryptedData);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ArgumentNullException.ThrowIfNull(senderPublicKey);

        // Verify the signature first
        CryptoResult<bool> verifyResult = await _signature.VerifyAsync(
            signedEncryptedData.EncryptedData,
            signedEncryptedData.Signature,
            senderPublicKey).ConfigureAwait(false);

        if (verifyResult.IsFailure)
        {
            throw new InvalidOperationException($"Signature verification failed: {verifyResult.Error}");
        }

        if (!verifyResult.Value)
        {
            throw new InvalidOperationException("Signature verification failed: Invalid signature.");
        }

        // Decrypt the data
        return await DecryptDataAsync(signedEncryptedData.EncryptedData, recipientPrivateKey).ConfigureAwait(false);
    }

    /// <summary>
    /// Derives a key from a shared secret and additional info.
    /// </summary>
    /// <param name="inputKeyMaterial">The shared secret or input key material.</param>
    /// <param name="salt">Optional salt value.</param>
    /// <param name="info">Optional context/application-specific info.</param>
    /// <param name="outputLength">The desired output key length in bytes.</param>
    /// <returns>The derived key bytes.</returns>
    public async Task<byte[]> DeriveKeyAsync(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int outputLength)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(inputKeyMaterial);

        CryptoResult<byte[]> result = await _hkdf.DeriveKeyAsync(
            inputKeyMaterial,
            salt ?? [],
            info ?? [],
            outputLength).ConfigureAwait(false);

        if (result.IsFailure)
        {
            throw new InvalidOperationException($"Key derivation failed: {result.Error}");
        }

        return result.Value;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Dispose managed resources
        if (_hybridEncryption is IAsyncDisposable hybridDisposable)
        {
            await hybridDisposable.DisposeAsync().ConfigureAwait(false);
        }

        if (_signature is IAsyncDisposable signatureDisposable)
        {
            await signatureDisposable.DisposeAsync().ConfigureAwait(false);
        }

        if (_hkdf is IAsyncDisposable hkdfDisposable)
        {
            await hkdfDisposable.DisposeAsync().ConfigureAwait(false);
        }
    }
}

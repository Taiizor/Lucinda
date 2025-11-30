// Copyright (c) 2025 Lucinda. All rights reserved.
// Licensed under the MIT License.

namespace Lucinda.Blazor.Protocol.X3DH;

/// <summary>
/// Represents an asymmetric key pair for Blazor X3DH operations.
/// </summary>
public sealed class BlazorAsymmetricKeyPair
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BlazorAsymmetricKeyPair"/> class.
    /// </summary>
    /// <param name="publicKey">The public key.</param>
    /// <param name="privateKey">The private key.</param>
    public BlazorAsymmetricKeyPair(byte[] publicKey, byte[] privateKey)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
    }

    /// <summary>
    /// Gets the public key (SPKI format).
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Gets the private key (PKCS8 format).
    /// </summary>
    public byte[] PrivateKey { get; }
}

// -----------------------------------------------------------------------
// <copyright file="ServiceCollectionExtensions.cs" company="Lucinda">
// Copyright (c) Lucinda. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

using Lucinda.Blazor.Abstractions;
using Lucinda.Blazor.Asymmetric;
using Lucinda.Blazor.Interop;
using Lucinda.Blazor.KeyDerivation;
using Lucinda.Blazor.KeyExchange;
using Lucinda.Blazor.KeyManagement;
using Lucinda.Blazor.Signatures;
using Lucinda.Blazor.Symmetric;
using Lucinda.Blazor.Utilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Lucinda.Blazor
{
    /// <summary>
    /// Extension methods for configuring Lucinda Blazor services.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Adds Lucinda Blazor crypto services to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaBlazor(this IServiceCollection services)
        {
            return services.AddLucindaBlazor(new LucindaBlazorOptions());
        }

        /// <summary>
        /// Adds Lucinda Blazor crypto services to the specified <see cref="IServiceCollection"/> with configuration.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="options">The configuration options.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaBlazor(this IServiceCollection services, LucindaBlazorOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);

            // Register the WebCryptoInterop service (singleton for module caching)
            services.TryAddSingleton<WebCryptoInterop>();

            // Register symmetric encryption
            if (options.UseAesGcm)
            {
                services.TryAddScoped<IBlazorSymmetricEncryption>(sp =>
                    new BlazorAesGcmEncryption(sp.GetRequiredService<WebCryptoInterop>(), options.AesKeySize));
            }
            else
            {
                services.TryAddScoped<IBlazorSymmetricEncryption>(sp =>
                    new BlazorAesCbcEncryption(sp.GetRequiredService<WebCryptoInterop>(), options.AesKeySize));
            }

            // Register asymmetric encryption
            services.TryAddScoped<IBlazorAsymmetricEncryption>(sp =>
                new BlazorRsaEncryption(sp.GetRequiredService<WebCryptoInterop>(), options.RsaKeySize, options.RsaHashAlgorithm));

            // Register key exchange
            services.TryAddScoped<IBlazorKeyExchange>(sp =>
                new BlazorEcdhKeyExchange(sp.GetRequiredService<WebCryptoInterop>(), options.EcdhCurve));

            // Register signatures
            if (options.UseEcdsaSignature)
            {
                services.TryAddScoped<IBlazorSignature>(sp =>
                    new BlazorEcdsaSignature(sp.GetRequiredService<WebCryptoInterop>(), options.EcdsaCurve, options.EcdsaHashAlgorithm));
            }
            else
            {
                services.TryAddScoped<IBlazorSignature>(sp =>
                    new BlazorRsaPssSignature(sp.GetRequiredService<WebCryptoInterop>(), options.RsaKeySize, options.RsaPssHashAlgorithm, options.RsaPssSaltLength));
            }

            // Register key derivation
            services.TryAddScoped<IBlazorKeyDerivation>(sp =>
                new BlazorHkdfKeyDerivation(sp.GetRequiredService<WebCryptoInterop>(), options.HkdfHashAlgorithm));

            services.TryAddScoped<IBlazorPasswordKeyDerivation>(sp =>
                new BlazorPbkdf2KeyDerivation(sp.GetRequiredService<WebCryptoInterop>(), options.Pbkdf2HashAlgorithm, options.Pbkdf2Iterations));

            // Register utilities
            services.TryAddScoped<IBlazorSecureRandom>(sp =>
                new BlazorSecureRandom(sp.GetRequiredService<WebCryptoInterop>()));

            services.TryAddScoped<IBlazorHash>(sp =>
                new BlazorHash(sp.GetRequiredService<WebCryptoInterop>(), options.DefaultHashAlgorithm));

            // Register hybrid encryption
            services.TryAddScoped<IBlazorHybridEncryption>(sp =>
                new BlazorRsaAesHybridEncryption(sp.GetRequiredService<WebCryptoInterop>()));

            // Register key management
            services.TryAddScoped<IBlazorSecureKeyStorage>(sp =>
                new BlazorIndexedDbKeyStorage(sp.GetRequiredService<WebCryptoInterop>()));

            services.TryAddScoped<IBlazorSessionStorage>(sp =>
                new BlazorIndexedDbSessionStorage(sp.GetRequiredService<WebCryptoInterop>()));

            return services;
        }

        /// <summary>
        /// Adds Lucinda Blazor crypto services to the specified <see cref="IServiceCollection"/> with configuration action.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="configure">The action to configure options.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaBlazor(this IServiceCollection services, Action<LucindaBlazorOptions> configure)
        {
            LucindaBlazorOptions options = new();
            configure?.Invoke(options);
            return services.AddLucindaBlazor(options);
        }

        /// <summary>
        /// Adds only AES-GCM encryption service to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="keySize">The key size in bits (128, 192, or 256). Default is 256.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaAesGcm(this IServiceCollection services, int keySize = 256)
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped<IBlazorSymmetricEncryption>(sp =>
                new BlazorAesGcmEncryption(sp.GetRequiredService<WebCryptoInterop>(), keySize));
            return services;
        }

        /// <summary>
        /// Adds only RSA encryption service to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="keySize">The key size in bits. Default is 2048.</param>
        /// <param name="hashAlgorithm">The hash algorithm for OAEP. Default is SHA-256.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaRsa(this IServiceCollection services, int keySize = 2048, string hashAlgorithm = "SHA-256")
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped<IBlazorAsymmetricEncryption>(sp =>
                new BlazorRsaEncryption(sp.GetRequiredService<WebCryptoInterop>(), keySize, hashAlgorithm));
            return services;
        }

        /// <summary>
        /// Adds only ECDH key exchange service to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="curve">The elliptic curve (P-256, P-384, or P-521). Default is P-256.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaEcdh(this IServiceCollection services, string curve = "P-256")
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped<IBlazorKeyExchange>(sp =>
                new BlazorEcdhKeyExchange(sp.GetRequiredService<WebCryptoInterop>(), curve));
            return services;
        }

        /// <summary>
        /// Adds only ECDSA signature service to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="curve">The elliptic curve (P-256, P-384, or P-521). Default is P-256.</param>
        /// <param name="hashAlgorithm">The hash algorithm. Default is SHA-256.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaEcdsa(this IServiceCollection services, string curve = "P-256", string hashAlgorithm = "SHA-256")
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped<IBlazorSignature>(sp =>
                new BlazorEcdsaSignature(sp.GetRequiredService<WebCryptoInterop>(), curve, hashAlgorithm));
            return services;
        }

        /// <summary>
        /// Adds only HKDF key derivation service to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="hashAlgorithm">The hash algorithm. Default is SHA-256.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaHkdf(this IServiceCollection services, string hashAlgorithm = "SHA-256")
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped<IBlazorKeyDerivation>(sp =>
                new BlazorHkdfKeyDerivation(sp.GetRequiredService<WebCryptoInterop>(), hashAlgorithm));
            return services;
        }

        /// <summary>
        /// Adds only PBKDF2 key derivation service to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="hashAlgorithm">The hash algorithm. Default is SHA-256.</param>
        /// <param name="iterations">The number of iterations. Default is 600000 (OWASP recommendation).</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaPbkdf2(this IServiceCollection services, string hashAlgorithm = "SHA-256", int iterations = 600000)
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped<IBlazorPasswordKeyDerivation>(sp =>
                new BlazorPbkdf2KeyDerivation(sp.GetRequiredService<WebCryptoInterop>(), hashAlgorithm, iterations));
            return services;
        }

        /// <summary>
        /// Adds only RSA-AES hybrid encryption service to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaHybridEncryption(this IServiceCollection services)
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped<IBlazorHybridEncryption>(sp =>
                new BlazorRsaAesHybridEncryption(sp.GetRequiredService<WebCryptoInterop>()));
            return services;
        }

        /// <summary>
        /// Adds End-to-End Encryption service to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaEndToEndEncryption(this IServiceCollection services)
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped(sp =>
                new BlazorEndToEndEncryption(sp.GetRequiredService<WebCryptoInterop>()));
            return services;
        }

        /// <summary>
        /// Adds End-to-End Encryption service to the specified <see cref="IServiceCollection"/> with options.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="options">The configuration options.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaEndToEndEncryption(this IServiceCollection services, BlazorEndToEndEncryptionOptions options)
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped(sp =>
                new BlazorEndToEndEncryption(sp.GetRequiredService<WebCryptoInterop>(), options));
            return services;
        }

        /// <summary>
        /// Adds End-to-End Encryption service to the specified <see cref="IServiceCollection"/> with configuration action.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="configure">The action to configure options.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaEndToEndEncryption(this IServiceCollection services, Action<BlazorEndToEndEncryptionOptions> configure)
        {
            BlazorEndToEndEncryptionOptions options = new();
            configure?.Invoke(options);
            return services.AddLucindaEndToEndEncryption(options);
        }

        /// <summary>
        /// Adds Secure Messaging service (Signal Protocol) to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaSecureMessaging(this IServiceCollection services)
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped<IBlazorSessionStorage>(sp =>
                new BlazorIndexedDbSessionStorage(sp.GetRequiredService<WebCryptoInterop>()));
            services.TryAddScoped(sp =>
                new BlazorSecureMessaging(
                    sp.GetRequiredService<WebCryptoInterop>(),
                    new BlazorSecureMessagingOptions(),
                    sp.GetService<IBlazorSessionStorage>()));
            return services;
        }

        /// <summary>
        /// Adds Secure Messaging service (Signal Protocol) to the specified <see cref="IServiceCollection"/> with options.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="options">The configuration options.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaSecureMessaging(this IServiceCollection services, BlazorSecureMessagingOptions options)
        {
            services.TryAddSingleton<WebCryptoInterop>();
            services.TryAddScoped<IBlazorSessionStorage>(sp =>
                new BlazorIndexedDbSessionStorage(sp.GetRequiredService<WebCryptoInterop>()));
            services.TryAddScoped(sp =>
                new BlazorSecureMessaging(
                    sp.GetRequiredService<WebCryptoInterop>(),
                    options,
                    sp.GetService<IBlazorSessionStorage>()));
            return services;
        }

        /// <summary>
        /// Adds Secure Messaging service (Signal Protocol) to the specified <see cref="IServiceCollection"/> with configuration action.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="configure">The action to configure options.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddLucindaSecureMessaging(this IServiceCollection services, Action<BlazorSecureMessagingOptions> configure)
        {
            BlazorSecureMessagingOptions options = new();
            configure?.Invoke(options);
            return services.AddLucindaSecureMessaging(options);
        }
    }
}

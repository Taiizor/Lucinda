/**
 * Lucinda Crypto - Web Crypto API JavaScript Module
 * 
 * This module provides cryptographic operations using the Web Crypto API
 * for Blazor WebAssembly applications.
 * 
 * @module LucindaCrypto
 */

// Ensure crypto is available
const crypto = globalThis.crypto || window.crypto;
const subtle = crypto.subtle;

/**
 * Encrypts data using AES-GCM.
 * @param {Uint8Array} key - The encryption key (16, 24, or 32 bytes)
 * @param {Uint8Array} nonce - The nonce/IV (12 bytes recommended)
 * @param {Uint8Array} plaintext - The data to encrypt
 * @param {Uint8Array|null} associatedData - Additional authenticated data (optional)
 * @returns {Promise<Uint8Array>} The ciphertext with authentication tag appended
 */
export async function aesGcmEncrypt(key, nonce, plaintext, associatedData) {
    const cryptoKey = await subtle.importKey(
        'raw',
        key,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );

    const algorithm = {
        name: 'AES-GCM',
        iv: nonce,
        tagLength: 128 // 16 bytes
    };

    if (associatedData && associatedData.length > 0) {
        algorithm.additionalData = associatedData;
    }

    const ciphertext = await subtle.encrypt(algorithm, cryptoKey, plaintext);
    return new Uint8Array(ciphertext);
}

/**
 * Decrypts data using AES-GCM.
 * @param {Uint8Array} key - The encryption key
 * @param {Uint8Array} nonce - The nonce/IV used during encryption
 * @param {Uint8Array} ciphertext - The ciphertext with authentication tag
 * @param {Uint8Array|null} associatedData - Additional authenticated data (optional)
 * @returns {Promise<Uint8Array>} The decrypted plaintext
 */
export async function aesGcmDecrypt(key, nonce, ciphertext, associatedData) {
    const cryptoKey = await subtle.importKey(
        'raw',
        key,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    const algorithm = {
        name: 'AES-GCM',
        iv: nonce,
        tagLength: 128
    };

    if (associatedData && associatedData.length > 0) {
        algorithm.additionalData = associatedData;
    }

    const plaintext = await subtle.decrypt(algorithm, cryptoKey, ciphertext);
    return new Uint8Array(plaintext);
}

/**
 * Encrypts data using AES-CBC.
 * @param {Uint8Array} key - The encryption key
 * @param {Uint8Array} iv - The initialization vector (16 bytes)
 * @param {Uint8Array} plaintext - The data to encrypt
 * @returns {Promise<Uint8Array>} The ciphertext
 */
export async function aesCbcEncrypt(key, iv, plaintext) {
    const cryptoKey = await subtle.importKey(
        'raw',
        key,
        { name: 'AES-CBC' },
        false,
        ['encrypt']
    );

    // Apply PKCS7 padding
    const paddedPlaintext = pkcs7Pad(plaintext, 16);

    const ciphertext = await subtle.encrypt(
        { name: 'AES-CBC', iv: iv },
        cryptoKey,
        paddedPlaintext
    );

    return new Uint8Array(ciphertext);
}

/**
 * Decrypts data using AES-CBC.
 * @param {Uint8Array} key - The encryption key
 * @param {Uint8Array} iv - The initialization vector
 * @param {Uint8Array} ciphertext - The ciphertext
 * @returns {Promise<Uint8Array>} The decrypted plaintext
 */
export async function aesCbcDecrypt(key, iv, ciphertext) {
    const cryptoKey = await subtle.importKey(
        'raw',
        key,
        { name: 'AES-CBC' },
        false,
        ['decrypt']
    );

    const plaintext = await subtle.decrypt(
        { name: 'AES-CBC', iv: iv },
        cryptoKey,
        ciphertext
    );

    // Remove PKCS7 padding
    return pkcs7Unpad(new Uint8Array(plaintext));
}

/**
 * Generates an RSA key pair.
 * @param {number} keySizeInBits - The key size (2048, 3072, or 4096)
 * @returns {Promise<Uint8Array[]>} Array containing [publicKey, privateKey] in SPKI and PKCS8 format
 */
export async function rsaGenerateKeyPair(keySizeInBits) {
    const keyPair = await subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: keySizeInBits,
            publicExponent: new Uint8Array([1, 0, 1]), // 65537
            hash: 'SHA-256'
        },
        true,
        ['encrypt', 'decrypt']
    );

    const publicKey = await subtle.exportKey('spki', keyPair.publicKey);
    const privateKey = await subtle.exportKey('pkcs8', keyPair.privateKey);

    return [new Uint8Array(publicKey), new Uint8Array(privateKey)];
}

/**
 * Generates an RSA key pair and returns as pipe-separated Base64 string.
 * @param {number} keySizeInBits - The key size (2048, 3072, or 4096)
 * @returns {Promise<string>} Base64(publicKey)|Base64(privateKey)
 */
export async function rsaGenerateKeyPairJson(keySizeInBits) {
    const [publicKey, privateKey] = await rsaGenerateKeyPair(keySizeInBits);
    return arrayToBase64(publicKey) + '|' + arrayToBase64(privateKey);
}

/**
 * Encrypts data using RSA-OAEP.
 * @param {Uint8Array} publicKey - The public key in SPKI format
 * @param {Uint8Array} plaintext - The data to encrypt
 * @returns {Promise<Uint8Array>} The ciphertext
 */
export async function rsaEncrypt(publicKey, plaintext) {
    const cryptoKey = await subtle.importKey(
        'spki',
        publicKey,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
    );

    const ciphertext = await subtle.encrypt(
        { name: 'RSA-OAEP' },
        cryptoKey,
        plaintext
    );

    return new Uint8Array(ciphertext);
}

/**
 * Decrypts data using RSA-OAEP.
 * @param {Uint8Array} privateKey - The private key in PKCS8 format
 * @param {Uint8Array} ciphertext - The ciphertext
 * @returns {Promise<Uint8Array>} The plaintext
 */
export async function rsaDecrypt(privateKey, ciphertext) {
    const cryptoKey = await subtle.importKey(
        'pkcs8',
        privateKey,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt']
    );

    const plaintext = await subtle.decrypt(
        { name: 'RSA-OAEP' },
        cryptoKey,
        ciphertext
    );

    return new Uint8Array(plaintext);
}

/**
 * Signs data using RSA-PSS.
 * @param {Uint8Array} privateKey - The private key in PKCS8 format
 * @param {Uint8Array} data - The data to sign
 * @param {string} hashAlgorithm - The hash algorithm (SHA-256, SHA-384, SHA-512)
 * @returns {Promise<Uint8Array>} The signature
 */
export async function rsaSign(privateKey, data, hashAlgorithm) {
    const cryptoKey = await subtle.importKey(
        'pkcs8',
        privateKey,
        { name: 'RSA-PSS', hash: hashAlgorithm },
        false,
        ['sign']
    );

    const signature = await subtle.sign(
        { name: 'RSA-PSS', saltLength: 32 },
        cryptoKey,
        data
    );

    return new Uint8Array(signature);
}

/**
 * Verifies an RSA-PSS signature.
 * @param {Uint8Array} publicKey - The public key in SPKI format
 * @param {Uint8Array} data - The original data
 * @param {Uint8Array} signature - The signature to verify
 * @param {string} hashAlgorithm - The hash algorithm
 * @returns {Promise<boolean>} True if the signature is valid
 */
export async function rsaVerify(publicKey, data, signature, hashAlgorithm) {
    const cryptoKey = await subtle.importKey(
        'spki',
        publicKey,
        { name: 'RSA-PSS', hash: hashAlgorithm },
        false,
        ['verify']
    );

    return await subtle.verify(
        { name: 'RSA-PSS', saltLength: 32 },
        cryptoKey,
        signature,
        data
    );
}

/**
 * Generates an ECDH key pair.
 * @param {string} curveName - The curve name (P-256, P-384, P-521)
 * @returns {Promise<Uint8Array[]>} Array containing [publicKey, privateKey] in raw and PKCS8 format
 */
export async function ecdhGenerateKeyPair(curveName) {
    const keyPair = await subtle.generateKey(
        { name: 'ECDH', namedCurve: curveName },
        true,
        ['deriveBits', 'deriveKey']
    );

    const publicKey = await subtle.exportKey('raw', keyPair.publicKey);
    const privateKey = await subtle.exportKey('pkcs8', keyPair.privateKey);

    return [new Uint8Array(publicKey), new Uint8Array(privateKey)];
}

/**
 * Generates an ECDH key pair and returns as pipe-separated Base64 string.
 * @param {string} curveName - The curve name (P-256, P-384, P-521)
 * @returns {Promise<string>} Base64(publicKey)|Base64(privateKey)
 */
export async function ecdhGenerateKeyPairJson(curveName) {
    const [publicKey, privateKey] = await ecdhGenerateKeyPair(curveName);
    return arrayToBase64(publicKey) + '|' + arrayToBase64(privateKey);
}

/**
 * Derives a shared secret using ECDH.
 * @param {Uint8Array} privateKey - The local private key in PKCS8 format
 * @param {Uint8Array} publicKey - The remote public key in raw format
 * @param {string} curveName - The curve name
 * @returns {Promise<Uint8Array>} The shared secret
 */
export async function ecdhDeriveSharedSecret(privateKey, publicKey, curveName) {
    const privateKeyObj = await subtle.importKey(
        'pkcs8',
        privateKey,
        { name: 'ECDH', namedCurve: curveName },
        false,
        ['deriveBits']
    );

    const publicKeyObj = await subtle.importKey(
        'raw',
        publicKey,
        { name: 'ECDH', namedCurve: curveName },
        false,
        []
    );

    const bitLength = curveName === 'P-521' ? 528 : (curveName === 'P-384' ? 384 : 256);
    const sharedSecret = await subtle.deriveBits(
        { name: 'ECDH', public: publicKeyObj },
        privateKeyObj,
        bitLength
    );

    return new Uint8Array(sharedSecret);
}

/**
 * Generates an ECDSA key pair.
 * @param {string} curveName - The curve name (P-256, P-384, P-521)
 * @returns {Promise<Uint8Array[]>} Array containing [publicKey, privateKey]
 */
export async function ecdsaGenerateKeyPair(curveName) {
    const keyPair = await subtle.generateKey(
        { name: 'ECDSA', namedCurve: curveName },
        true,
        ['sign', 'verify']
    );

    const publicKey = await subtle.exportKey('raw', keyPair.publicKey);
    const privateKey = await subtle.exportKey('pkcs8', keyPair.privateKey);

    return [new Uint8Array(publicKey), new Uint8Array(privateKey)];
}

/**
 * Generates an ECDSA key pair and returns as pipe-separated Base64 string.
 * @param {string} curveName - The curve name (P-256, P-384, P-521)
 * @returns {Promise<string>} Base64(publicKey)|Base64(privateKey)
 */
export async function ecdsaGenerateKeyPairJson(curveName) {
    const [publicKey, privateKey] = await ecdsaGenerateKeyPair(curveName);
    return arrayToBase64(publicKey) + '|' + arrayToBase64(privateKey);
}

/**
 * Signs data using ECDSA.
 * @param {Uint8Array} privateKey - The private key in PKCS8 format
 * @param {Uint8Array} data - The data to sign
 * @param {string} curveName - The curve name
 * @param {string} hashAlgorithm - The hash algorithm
 * @returns {Promise<Uint8Array>} The signature
 */
export async function ecdsaSign(privateKey, data, curveName, hashAlgorithm) {
    const cryptoKey = await subtle.importKey(
        'pkcs8',
        privateKey,
        { name: 'ECDSA', namedCurve: curveName },
        false,
        ['sign']
    );

    const signature = await subtle.sign(
        { name: 'ECDSA', hash: hashAlgorithm },
        cryptoKey,
        data
    );

    return new Uint8Array(signature);
}

/**
 * Verifies an ECDSA signature.
 * @param {Uint8Array} publicKey - The public key in raw format
 * @param {Uint8Array} data - The original data
 * @param {Uint8Array} signature - The signature to verify
 * @param {string} curveName - The curve name
 * @param {string} hashAlgorithm - The hash algorithm
 * @returns {Promise<boolean>} True if the signature is valid
 */
export async function ecdsaVerify(publicKey, data, signature, curveName, hashAlgorithm) {
    const cryptoKey = await subtle.importKey(
        'raw',
        publicKey,
        { name: 'ECDSA', namedCurve: curveName },
        false,
        ['verify']
    );

    return await subtle.verify(
        { name: 'ECDSA', hash: hashAlgorithm },
        cryptoKey,
        signature,
        data
    );
}

/**
 * Derives a key using HKDF.
 * @param {Uint8Array} inputKeyMaterial - The input key material
 * @param {Uint8Array|null} salt - Optional salt
 * @param {Uint8Array|null} info - Optional context info
 * @param {number} outputLength - The desired output length in bytes
 * @param {string} hashAlgorithm - The hash algorithm
 * @returns {Promise<Uint8Array>} The derived key
 */
export async function hkdfDerive(inputKeyMaterial, salt, info, outputLength, hashAlgorithm) {
    const baseKey = await subtle.importKey(
        'raw',
        inputKeyMaterial,
        'HKDF',
        false,
        ['deriveBits']
    );

    const derivedBits = await subtle.deriveBits(
        {
            name: 'HKDF',
            hash: hashAlgorithm,
            salt: salt || new Uint8Array(0),
            info: info || new Uint8Array(0)
        },
        baseKey,
        outputLength * 8
    );

    return new Uint8Array(derivedBits);
}

/**
 * Derives a key using PBKDF2.
 * @param {Uint8Array} password - The password as bytes
 * @param {Uint8Array} salt - The salt
 * @param {number} iterations - The number of iterations
 * @param {number} outputLength - The desired output length in bytes
 * @param {string} hashAlgorithm - The hash algorithm
 * @returns {Promise<Uint8Array>} The derived key
 */
export async function pbkdf2Derive(password, salt, iterations, outputLength, hashAlgorithm) {
    const baseKey = await subtle.importKey(
        'raw',
        password,
        'PBKDF2',
        false,
        ['deriveBits']
    );

    const derivedBits = await subtle.deriveBits(
        {
            name: 'PBKDF2',
            hash: hashAlgorithm,
            salt: salt,
            iterations: iterations
        },
        baseKey,
        outputLength * 8
    );

    return new Uint8Array(derivedBits);
}

/**
 * Computes HMAC.
 * @param {Uint8Array} key - The HMAC key
 * @param {Uint8Array} data - The data to authenticate
 * @param {string} hashAlgorithm - The hash algorithm
 * @returns {Promise<Uint8Array>} The HMAC
 */
export async function hmacCompute(key, data, hashAlgorithm) {
    const cryptoKey = await subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: hashAlgorithm },
        false,
        ['sign']
    );

    const signature = await subtle.sign('HMAC', cryptoKey, data);
    return new Uint8Array(signature);
}

// PKCS7 padding helpers
function pkcs7Pad(data, blockSize) {
    const padding = blockSize - (data.length % blockSize);
    const padded = new Uint8Array(data.length + padding);
    padded.set(data);
    for (let i = data.length; i < padded.length; i++) {
        padded[i] = padding;
    }
    return padded;
}

function pkcs7Unpad(data) {
    const padding = data[data.length - 1];
    if (padding > data.length || padding === 0) {
        throw new Error('Invalid PKCS7 padding');
    }
    for (let i = data.length - padding; i < data.length; i++) {
        if (data[i] !== padding) {
            throw new Error('Invalid PKCS7 padding');
        }
    }
    return data.slice(0, data.length - padding);
}

/**
 * Converts Uint8Array to Base64 string.
 * @param {Uint8Array} array - The byte array
 * @returns {string} Base64 encoded string
 */
function arrayToBase64(array) {
    let binary = '';
    for (let i = 0; i < array.length; i++) {
        binary += String.fromCharCode(array[i]);
    }
    return btoa(binary);
}
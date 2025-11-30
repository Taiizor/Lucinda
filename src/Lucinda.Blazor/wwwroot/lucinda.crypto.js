// Lucinda.Blazor - Web Crypto API Wrapper
// Copyright (c) Lucinda Contributors. All rights reserved.
// Licensed under the MIT license.

/**
 * Lucinda Web Crypto API Module
 * Provides cryptographic operations for Blazor WebAssembly using native browser crypto.
 */

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Converts a Uint8Array to a base64 string for .NET interop
 * @param {Uint8Array} bytes 
 * @returns {string}
 */
function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Converts a base64 string to Uint8Array
 * @param {string} base64 
 * @returns {Uint8Array}
 */
function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Concatenates multiple Uint8Arrays
 * @param  {...Uint8Array} arrays 
 * @returns {Uint8Array}
 */
function concatBytes(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

// ============================================================================
// Secure Random
// ============================================================================

/**
 * Generates cryptographically secure random bytes
 * @param {number} length - Number of bytes to generate
 * @returns {string} Base64-encoded random bytes
 */
export function getRandomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytesToBase64(bytes);
}

/**
 * Generates a random 32-bit integer
 * @returns {number}
 */
export function getRandomInt32() {
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    return new DataView(bytes.buffer).getInt32(0, true);
}

// ============================================================================
// AES-GCM Encryption
// ============================================================================

/**
 * Encrypts data using AES-GCM
 * @param {string} keyBase64 - Base64-encoded AES key (16/24/32 bytes)
 * @param {string} plaintextBase64 - Base64-encoded plaintext
 * @param {string|null} aadBase64 - Base64-encoded additional authenticated data (optional)
 * @returns {Promise<string>} Base64-encoded ciphertext (IV + ciphertext + tag)
 */
export async function aesGcmEncrypt(keyBase64, plaintextBase64, aadBase64) {
    const keyBytes = base64ToBytes(keyBase64);
    const plaintext = base64ToBytes(plaintextBase64);
    const aad = aadBase64 ? base64ToBytes(aadBase64) : new Uint8Array(0);
    
    // Generate 12-byte IV (96 bits as recommended for GCM)
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    
    // Import the key
    const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );
    
    // Encrypt with AES-GCM (tag is appended to ciphertext)
    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
            additionalData: aad,
            tagLength: 128
        },
        key,
        plaintext
    );
    
    // Format: [12 bytes IV][ciphertext][16 bytes tag]
    const result = concatBytes(iv, new Uint8Array(encrypted));
    return bytesToBase64(result);
}

/**
 * Decrypts data using AES-GCM
 * @param {string} keyBase64 - Base64-encoded AES key
 * @param {string} ciphertextBase64 - Base64-encoded ciphertext (IV + ciphertext + tag)
 * @param {string|null} aadBase64 - Base64-encoded additional authenticated data (optional)
 * @returns {Promise<string>} Base64-encoded plaintext
 */
export async function aesGcmDecrypt(keyBase64, ciphertextBase64, aadBase64) {
    const keyBytes = base64ToBytes(keyBase64);
    const ciphertext = base64ToBytes(ciphertextBase64);
    const aad = aadBase64 ? base64ToBytes(aadBase64) : new Uint8Array(0);
    
    // Extract IV (first 12 bytes)
    const iv = ciphertext.slice(0, 12);
    const encryptedData = ciphertext.slice(12);
    
    // Import the key
    const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
    
    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
            additionalData: aad,
            tagLength: 128
        },
        key,
        encryptedData
    );
    
    return bytesToBase64(new Uint8Array(decrypted));
}

/**
 * Generates an AES key
 * @param {number} keySizeBits - Key size in bits (128, 192, or 256)
 * @returns {Promise<string>} Base64-encoded key
 */
export async function generateAesKey(keySizeBits) {
    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: keySizeBits },
        true,
        ["encrypt", "decrypt"]
    );
    
    const keyBytes = await crypto.subtle.exportKey("raw", key);
    return bytesToBase64(new Uint8Array(keyBytes));
}

// ============================================================================
// AES-CBC Encryption
// ============================================================================

/**
 * Encrypts data using AES-CBC
 * @param {string} keyBase64 - Base64-encoded AES key
 * @param {string} plaintextBase64 - Base64-encoded plaintext
 * @returns {Promise<string>} Base64-encoded ciphertext (IV + ciphertext)
 */
export async function aesCbcEncrypt(keyBase64, plaintextBase64) {
    const keyBytes = base64ToBytes(keyBase64);
    const plaintext = base64ToBytes(plaintextBase64);
    
    // Generate 16-byte IV
    const iv = new Uint8Array(16);
    crypto.getRandomValues(iv);
    
    // Import the key
    const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-CBC" },
        false,
        ["encrypt"]
    );
    
    // Encrypt
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv: iv },
        key,
        plaintext
    );
    
    // Format: [16 bytes IV][ciphertext]
    const result = concatBytes(iv, new Uint8Array(encrypted));
    return bytesToBase64(result);
}

/**
 * Decrypts data using AES-CBC
 * @param {string} keyBase64 - Base64-encoded AES key
 * @param {string} ciphertextBase64 - Base64-encoded ciphertext (IV + ciphertext)
 * @returns {Promise<string>} Base64-encoded plaintext
 */
export async function aesCbcDecrypt(keyBase64, ciphertextBase64) {
    const keyBytes = base64ToBytes(keyBase64);
    const ciphertext = base64ToBytes(ciphertextBase64);
    
    // Extract IV (first 16 bytes)
    const iv = ciphertext.slice(0, 16);
    const encryptedData = ciphertext.slice(16);
    
    // Import the key
    const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-CBC" },
        false,
        ["decrypt"]
    );
    
    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: iv },
        key,
        encryptedData
    );
    
    return bytesToBase64(new Uint8Array(decrypted));
}

// ============================================================================
// RSA Encryption
// ============================================================================

/**
 * Generates an RSA key pair
 * @param {number} modulusLength - Key size in bits (2048, 3072, or 4096)
 * @param {string} hashName - Hash algorithm ("SHA-256", "SHA-384", or "SHA-512")
 * @returns {Promise<{publicKey: string, privateKey: string}>} Base64-encoded SPKI public key and PKCS8 private key
 */
export async function generateRsaKeyPair(modulusLength, hashName) {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: modulusLength,
            publicExponent: new Uint8Array([1, 0, 1]), // 65537
            hash: hashName
        },
        true,
        ["encrypt", "decrypt"]
    );
    
    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    
    return {
        publicKey: bytesToBase64(new Uint8Array(publicKey)),
        privateKey: bytesToBase64(new Uint8Array(privateKey))
    };
}

/**
 * Encrypts data using RSA-OAEP
 * @param {string} publicKeyBase64 - Base64-encoded SPKI public key
 * @param {string} plaintextBase64 - Base64-encoded plaintext
 * @param {string} hashName - Hash algorithm
 * @returns {Promise<string>} Base64-encoded ciphertext
 */
export async function rsaEncrypt(publicKeyBase64, plaintextBase64, hashName) {
    const publicKeyBytes = base64ToBytes(publicKeyBase64);
    const plaintext = base64ToBytes(plaintextBase64);
    
    const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBytes,
        { name: "RSA-OAEP", hash: hashName },
        false,
        ["encrypt"]
    );
    
    const encrypted = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        plaintext
    );
    
    return bytesToBase64(new Uint8Array(encrypted));
}

/**
 * Decrypts data using RSA-OAEP
 * @param {string} privateKeyBase64 - Base64-encoded PKCS8 private key
 * @param {string} ciphertextBase64 - Base64-encoded ciphertext
 * @param {string} hashName - Hash algorithm
 * @returns {Promise<string>} Base64-encoded plaintext
 */
export async function rsaDecrypt(privateKeyBase64, ciphertextBase64, hashName) {
    const privateKeyBytes = base64ToBytes(privateKeyBase64);
    const ciphertext = base64ToBytes(ciphertextBase64);
    
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyBytes,
        { name: "RSA-OAEP", hash: hashName },
        false,
        ["decrypt"]
    );
    
    const decrypted = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        ciphertext
    );
    
    return bytesToBase64(new Uint8Array(decrypted));
}

// ============================================================================
// ECDH Key Exchange
// ============================================================================

/**
 * Generates an ECDH key pair
 * @param {string} namedCurve - Curve name ("P-256", "P-384", or "P-521")
 * @returns {Promise<{publicKey: string, privateKey: string}>} Base64-encoded SPKI public key and PKCS8 private key
 */
export async function generateEcdhKeyPair(namedCurve) {
    const keyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: namedCurve },
        true,
        ["deriveBits"]
    );
    
    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    
    return {
        publicKey: bytesToBase64(new Uint8Array(publicKey)),
        privateKey: bytesToBase64(new Uint8Array(privateKey))
    };
}

/**
 * Derives a shared secret using ECDH
 * @param {string} privateKeyBase64 - Base64-encoded PKCS8 private key
 * @param {string} publicKeyBase64 - Base64-encoded SPKI public key
 * @param {string} namedCurve - Curve name
 * @param {number} lengthBits - Output length in bits
 * @returns {Promise<string>} Base64-encoded shared secret
 */
export async function ecdhDeriveBits(privateKeyBase64, publicKeyBase64, namedCurve, lengthBits) {
    const privateKeyBytes = base64ToBytes(privateKeyBase64);
    const publicKeyBytes = base64ToBytes(publicKeyBase64);
    
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyBytes,
        { name: "ECDH", namedCurve: namedCurve },
        false,
        ["deriveBits"]
    );
    
    const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBytes,
        { name: "ECDH", namedCurve: namedCurve },
        false,
        []
    );
    
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: "ECDH", public: publicKey },
        privateKey,
        lengthBits
    );
    
    return bytesToBase64(new Uint8Array(sharedSecret));
}

// ============================================================================
// ECDSA Signatures
// ============================================================================

/**
 * Generates an ECDSA key pair
 * @param {string} namedCurve - Curve name ("P-256", "P-384", or "P-521")
 * @returns {Promise<{publicKey: string, privateKey: string}>}
 */
export async function generateEcdsaKeyPair(namedCurve) {
    const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: namedCurve },
        true,
        ["sign", "verify"]
    );
    
    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    
    return {
        publicKey: bytesToBase64(new Uint8Array(publicKey)),
        privateKey: bytesToBase64(new Uint8Array(privateKey))
    };
}

/**
 * Signs data using ECDSA
 * @param {string} privateKeyBase64 - Base64-encoded PKCS8 private key
 * @param {string} dataBase64 - Base64-encoded data to sign
 * @param {string} namedCurve - Curve name
 * @param {string} hashName - Hash algorithm
 * @returns {Promise<string>} Base64-encoded signature
 */
export async function ecdsaSign(privateKeyBase64, dataBase64, namedCurve, hashName) {
    const privateKeyBytes = base64ToBytes(privateKeyBase64);
    const data = base64ToBytes(dataBase64);
    
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyBytes,
        { name: "ECDSA", namedCurve: namedCurve },
        false,
        ["sign"]
    );
    
    const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: hashName },
        privateKey,
        data
    );
    
    return bytesToBase64(new Uint8Array(signature));
}

/**
 * Verifies an ECDSA signature
 * @param {string} publicKeyBase64 - Base64-encoded SPKI public key
 * @param {string} dataBase64 - Base64-encoded original data
 * @param {string} signatureBase64 - Base64-encoded signature
 * @param {string} namedCurve - Curve name
 * @param {string} hashName - Hash algorithm
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function ecdsaVerify(publicKeyBase64, dataBase64, signatureBase64, namedCurve, hashName) {
    const publicKeyBytes = base64ToBytes(publicKeyBase64);
    const data = base64ToBytes(dataBase64);
    const signature = base64ToBytes(signatureBase64);
    
    const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBytes,
        { name: "ECDSA", namedCurve: namedCurve },
        false,
        ["verify"]
    );
    
    return await crypto.subtle.verify(
        { name: "ECDSA", hash: hashName },
        publicKey,
        signature,
        data
    );
}

// ============================================================================
// RSA Signatures
// ============================================================================

/**
 * Generates an RSA-PSS key pair for signing
 * @param {number} modulusLength - Key size in bits
 * @param {string} hashName - Hash algorithm
 * @returns {Promise<{publicKey: string, privateKey: string}>}
 */
export async function generateRsaSignatureKeyPair(modulusLength, hashName) {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: modulusLength,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: hashName
        },
        true,
        ["sign", "verify"]
    );
    
    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    
    return {
        publicKey: bytesToBase64(new Uint8Array(publicKey)),
        privateKey: bytesToBase64(new Uint8Array(privateKey))
    };
}

/**
 * Signs data using RSA-PSS
 * @param {string} privateKeyBase64 - Base64-encoded PKCS8 private key
 * @param {string} dataBase64 - Base64-encoded data to sign
 * @param {string} hashName - Hash algorithm
 * @param {number} saltLength - Salt length in bytes
 * @returns {Promise<string>} Base64-encoded signature
 */
export async function rsaPssSign(privateKeyBase64, dataBase64, hashName, saltLength) {
    const privateKeyBytes = base64ToBytes(privateKeyBase64);
    const data = base64ToBytes(dataBase64);
    
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyBytes,
        { name: "RSA-PSS", hash: hashName },
        false,
        ["sign"]
    );
    
    const signature = await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: saltLength },
        privateKey,
        data
    );
    
    return bytesToBase64(new Uint8Array(signature));
}

/**
 * Verifies an RSA-PSS signature
 * @param {string} publicKeyBase64 - Base64-encoded SPKI public key
 * @param {string} dataBase64 - Base64-encoded original data
 * @param {string} signatureBase64 - Base64-encoded signature
 * @param {string} hashName - Hash algorithm
 * @param {number} saltLength - Salt length in bytes
 * @returns {Promise<boolean>}
 */
export async function rsaPssVerify(publicKeyBase64, dataBase64, signatureBase64, hashName, saltLength) {
    const publicKeyBytes = base64ToBytes(publicKeyBase64);
    const data = base64ToBytes(dataBase64);
    const signature = base64ToBytes(signatureBase64);
    
    const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBytes,
        { name: "RSA-PSS", hash: hashName },
        false,
        ["verify"]
    );
    
    return await crypto.subtle.verify(
        { name: "RSA-PSS", saltLength: saltLength },
        publicKey,
        signature,
        data
    );
}

// ============================================================================
// Key Derivation Functions
// ============================================================================

/**
 * Derives a key using HKDF
 * @param {string} inputKeyMaterialBase64 - Base64-encoded input key material
 * @param {string} saltBase64 - Base64-encoded salt (can be empty)
 * @param {string} infoBase64 - Base64-encoded info/context (can be empty)
 * @param {number} lengthBytes - Output length in bytes
 * @param {string} hashName - Hash algorithm
 * @returns {Promise<string>} Base64-encoded derived key
 */
export async function hkdfDeriveKey(inputKeyMaterialBase64, saltBase64, infoBase64, lengthBytes, hashName) {
    const ikm = base64ToBytes(inputKeyMaterialBase64);
    const salt = saltBase64 ? base64ToBytes(saltBase64) : new Uint8Array(0);
    const info = infoBase64 ? base64ToBytes(infoBase64) : new Uint8Array(0);
    
    const key = await crypto.subtle.importKey(
        "raw",
        ikm,
        { name: "HKDF" },
        false,
        ["deriveBits"]
    );
    
    const derived = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: hashName,
            salt: salt,
            info: info
        },
        key,
        lengthBytes * 8
    );
    
    return bytesToBase64(new Uint8Array(derived));
}

/**
 * Derives a key using PBKDF2
 * @param {string} passwordBase64 - Base64-encoded password
 * @param {string} saltBase64 - Base64-encoded salt
 * @param {number} iterations - Number of iterations
 * @param {number} lengthBytes - Output length in bytes
 * @param {string} hashName - Hash algorithm
 * @returns {Promise<string>} Base64-encoded derived key
 */
export async function pbkdf2DeriveKey(passwordBase64, saltBase64, iterations, lengthBytes, hashName) {
    const password = base64ToBytes(passwordBase64);
    const salt = base64ToBytes(saltBase64);
    
    const key = await crypto.subtle.importKey(
        "raw",
        password,
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );
    
    const derived = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: iterations,
            hash: hashName
        },
        key,
        lengthBytes * 8
    );
    
    return bytesToBase64(new Uint8Array(derived));
}

// ============================================================================
// Hash Functions
// ============================================================================

/**
 * Computes a SHA hash
 * @param {string} dataBase64 - Base64-encoded data
 * @param {string} hashName - Hash algorithm ("SHA-256", "SHA-384", or "SHA-512")
 * @returns {Promise<string>} Base64-encoded hash
 */
export async function computeHash(dataBase64, hashName) {
    const data = base64ToBytes(dataBase64);
    const hash = await crypto.subtle.digest(hashName, data);
    return bytesToBase64(new Uint8Array(hash));
}

// ============================================================================
// HMAC Functions
// ============================================================================

/**
 * Computes an HMAC
 * @param {string} keyBase64 - Base64-encoded key
 * @param {string} dataBase64 - Base64-encoded data
 * @param {string} hashName - Hash algorithm
 * @returns {Promise<string>} Base64-encoded HMAC
 */
export async function computeHmac(keyBase64, dataBase64, hashName) {
    const keyBytes = base64ToBytes(keyBase64);
    const data = base64ToBytes(dataBase64);
    
    const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: hashName },
        false,
        ["sign"]
    );
    
    const hmac = await crypto.subtle.sign("HMAC", key, data);
    return bytesToBase64(new Uint8Array(hmac));
}

/**
 * Verifies an HMAC
 * @param {string} keyBase64 - Base64-encoded key
 * @param {string} dataBase64 - Base64-encoded data
 * @param {string} hmacBase64 - Base64-encoded HMAC to verify
 * @param {string} hashName - Hash algorithm
 * @returns {Promise<boolean>}
 */
export async function verifyHmac(keyBase64, dataBase64, hmacBase64, hashName) {
    const keyBytes = base64ToBytes(keyBase64);
    const data = base64ToBytes(dataBase64);
    const hmac = base64ToBytes(hmacBase64);
    
    const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: hashName },
        false,
        ["verify"]
    );
    
    return await crypto.subtle.verify("HMAC", key, hmac, data);
}

// ============================================================================
// Feature Detection
// ============================================================================

/**
 * Checks if Web Crypto API is available
 * @returns {boolean}
 */
export function isWebCryptoAvailable() {
    return typeof crypto !== 'undefined' && 
           typeof crypto.subtle !== 'undefined' &&
           typeof crypto.getRandomValues !== 'undefined';
}

/**
 * Gets supported algorithms
 * @returns {object}
 */
export function getSupportedAlgorithms() {
    return {
        symmetric: ["AES-GCM", "AES-CBC"],
        asymmetric: ["RSA-OAEP"],
        signatures: ["ECDSA", "RSA-PSS"],
        keyExchange: ["ECDH"],
        keyDerivation: ["HKDF", "PBKDF2"],
        hashes: ["SHA-256", "SHA-384", "SHA-512"],
        curves: ["P-256", "P-384", "P-521"]
    };
}

// ============================================================================
// IndexedDB Key Storage
// ============================================================================

const DB_NAME = 'LucindaCrypto';
const DB_VERSION = 1;
const KEYS_STORE = 'keys';
const SESSIONS_STORE = 'sessions';

let db = null;

/**
 * Opens or creates the IndexedDB database
 * @returns {Promise<IDBDatabase>}
 */
async function openDatabase() {
    if (db) return db;
    
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            db = request.result;
            resolve(db);
        };
        
        request.onupgradeneeded = (event) => {
            const database = event.target.result;
            
            // Create keys store
            if (!database.objectStoreNames.contains(KEYS_STORE)) {
                const keysStore = database.createObjectStore(KEYS_STORE, { keyPath: 'keyId' });
                keysStore.createIndex('keyType', 'keyType', { unique: false });
                keysStore.createIndex('expiresAt', 'expiresAt', { unique: false });
            }
            
            // Create sessions store
            if (!database.objectStoreNames.contains(SESSIONS_STORE)) {
                database.createObjectStore(SESSIONS_STORE, { keyPath: 'sessionId' });
            }
        };
    });
}

/**
 * Stores a key in IndexedDB
 * @param {string} keyId - Unique key identifier
 * @param {string} keyDataBase64 - Base64-encoded key data
 * @param {object} metadata - Key metadata
 * @returns {Promise<boolean>}
 */
export async function storeKey(keyId, keyDataBase64, metadata) {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([KEYS_STORE], 'readwrite');
        const store = transaction.objectStore(KEYS_STORE);
        
        const record = {
            keyId: keyId,
            keyData: keyDataBase64,
            keyType: metadata.keyType,
            keySizeInBits: metadata.keySizeInBits,
            algorithm: metadata.algorithm || '',
            createdAt: metadata.createdAt || new Date().toISOString(),
            expiresAt: metadata.expiresAt || null,
            isActive: metadata.isActive !== false,
            isExportable: metadata.isExportable !== false,
            tags: metadata.tags || {}
        };
        
        const request = store.put(record);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(true);
    });
}

/**
 * Retrieves a key from IndexedDB
 * @param {string} keyId - Unique key identifier
 * @returns {Promise<string|null>} Base64-encoded key data or null
 */
export async function retrieveKey(keyId) {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([KEYS_STORE], 'readonly');
        const store = transaction.objectStore(KEYS_STORE);
        
        const request = store.get(keyId);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            const result = request.result;
            if (!result) {
                resolve(null);
                return;
            }
            
            // Check if expired
            if (result.expiresAt && new Date(result.expiresAt) < new Date()) {
                resolve(null);
                return;
            }
            
            // Check if active
            if (!result.isActive) {
                resolve(null);
                return;
            }
            
            resolve(result.keyData);
        };
    });
}

/**
 * Deletes a key from IndexedDB
 * @param {string} keyId - Unique key identifier
 * @returns {Promise<boolean>}
 */
export async function deleteKey(keyId) {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([KEYS_STORE], 'readwrite');
        const store = transaction.objectStore(KEYS_STORE);
        
        const request = store.delete(keyId);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(true);
    });
}

/**
 * Checks if a key exists in IndexedDB
 * @param {string} keyId - Unique key identifier
 * @returns {Promise<boolean>}
 */
export async function keyExists(keyId) {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([KEYS_STORE], 'readonly');
        const store = transaction.objectStore(KEYS_STORE);
        
        const request = store.getKey(keyId);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result !== undefined);
    });
}

/**
 * Gets key metadata from IndexedDB
 * @param {string} keyId - Unique key identifier
 * @returns {Promise<object|null>}
 */
export async function getKeyMetadata(keyId) {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([KEYS_STORE], 'readonly');
        const store = transaction.objectStore(KEYS_STORE);
        
        const request = store.get(keyId);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            const result = request.result;
            if (!result) {
                resolve(null);
                return;
            }
            
            // Return metadata without key data
            resolve({
                keyId: result.keyId,
                keyType: result.keyType,
                keySizeInBits: result.keySizeInBits,
                algorithm: result.algorithm,
                createdAt: result.createdAt,
                expiresAt: result.expiresAt,
                isActive: result.isActive,
                isExportable: result.isExportable,
                tags: result.tags
            });
        };
    });
}

/**
 * Lists all key IDs in IndexedDB
 * @returns {Promise<string[]>}
 */
export async function listKeyIds() {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([KEYS_STORE], 'readonly');
        const store = transaction.objectStore(KEYS_STORE);
        
        const request = store.getAllKeys();
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result || []);
    });
}

/**
 * Lists key IDs by type
 * @param {number} keyType - Key type enum value
 * @returns {Promise<string[]>}
 */
export async function listKeyIdsByType(keyType) {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([KEYS_STORE], 'readonly');
        const store = transaction.objectStore(KEYS_STORE);
        const index = store.index('keyType');
        
        const request = index.getAllKeys(keyType);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result || []);
    });
}

/**
 * Clears expired keys from IndexedDB
 * @returns {Promise<number>} Number of deleted keys
 */
export async function clearExpiredKeys() {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([KEYS_STORE], 'readwrite');
        const store = transaction.objectStore(KEYS_STORE);
        
        const now = new Date().toISOString();
        let deletedCount = 0;
        
        const request = store.openCursor();
        request.onerror = () => reject(request.error);
        request.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                const record = cursor.value;
                if (record.expiresAt && record.expiresAt < now) {
                    cursor.delete();
                    deletedCount++;
                }
                cursor.continue();
            } else {
                resolve(deletedCount);
            }
        };
    });
}

/**
 * Clears all keys from IndexedDB
 * @returns {Promise<void>}
 */
export async function clearAllKeys() {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([KEYS_STORE], 'readwrite');
        const store = transaction.objectStore(KEYS_STORE);
        
        const request = store.clear();
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}

// ============================================================================
// IndexedDB Session Storage
// ============================================================================

/**
 * Stores session data in IndexedDB
 * @param {string} sessionId - Unique session identifier
 * @param {string} sessionDataBase64 - Base64-encoded session data
 * @returns {Promise<boolean>}
 */
export async function storeSession(sessionId, sessionDataBase64) {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([SESSIONS_STORE], 'readwrite');
        const store = transaction.objectStore(SESSIONS_STORE);
        
        const record = {
            sessionId: sessionId,
            sessionData: sessionDataBase64,
            updatedAt: new Date().toISOString()
        };
        
        const request = store.put(record);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(true);
    });
}

/**
 * Loads session data from IndexedDB
 * @param {string} sessionId - Unique session identifier
 * @returns {Promise<string|null>} Base64-encoded session data or null
 */
export async function loadSession(sessionId) {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([SESSIONS_STORE], 'readonly');
        const store = transaction.objectStore(SESSIONS_STORE);
        
        const request = store.get(sessionId);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            const result = request.result;
            resolve(result ? result.sessionData : null);
        };
    });
}

/**
 * Deletes session data from IndexedDB
 * @param {string} sessionId - Unique session identifier
 * @returns {Promise<boolean>}
 */
export async function deleteSession(sessionId) {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([SESSIONS_STORE], 'readwrite');
        const store = transaction.objectStore(SESSIONS_STORE);
        
        const request = store.delete(sessionId);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(true);
    });
}

/**
 * Checks if a session exists in IndexedDB
 * @param {string} sessionId - Unique session identifier
 * @returns {Promise<boolean>}
 */
export async function sessionExists(sessionId) {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([SESSIONS_STORE], 'readonly');
        const store = transaction.objectStore(SESSIONS_STORE);
        
        const request = store.getKey(sessionId);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result !== undefined);
    });
}

/**
 * Gets all session IDs from IndexedDB
 * @returns {Promise<string[]>}
 */
export async function getAllSessionIds() {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([SESSIONS_STORE], 'readonly');
        const store = transaction.objectStore(SESSIONS_STORE);
        
        const request = store.getAllKeys();
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result || []);
    });
}

/**
 * Clears all sessions from IndexedDB
 * @returns {Promise<void>}
 */
export async function clearAllSessions() {
    const database = await openDatabase();
    
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([SESSIONS_STORE], 'readwrite');
        const store = transaction.objectStore(SESSIONS_STORE);
        
        const request = store.clear();
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}

/**
 * Checks if IndexedDB is available
 * @returns {boolean}
 */
export function isIndexedDBAvailable() {
    return typeof indexedDB !== 'undefined';
}
/**
 * CryptoService — Aegis Personal Cybersecurity Companion
 *
 * Implements ICryptographyService using pure-JS crypto libraries that work
 * in Expo Go / Hermes without native modules:
 *  - @noble/hashes  — PBKDF2, SHA-256, SHA-1
 *  - @noble/ciphers — AES-256-GCM
 *  - expo-crypto    — CSPRNG (getRandomBytes), SHA digests
 *
 * Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6
 */

import * as ExpoCrypto from 'expo-crypto';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { gcm } from '@noble/ciphers/aes.js';
import { EncryptedData, KAnonymityResult } from '../types/index';

// ---------------------------------------------------------------------------
// Domain key type
// ---------------------------------------------------------------------------

export interface AegisKey {
  key: Uint8Array;
  algorithm: 'AES-GCM';
  keySize: 256;
}

export type CryptoKey = AegisKey;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PBKDF2_ITERATIONS = 100_000;
const AES_KEY_BYTES = 32; // 256 bits
const SALT_BYTES = 32;    // 256 bits
const IV_BYTES = 12;      // 96 bits — standard for AES-GCM

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function encodeUtf8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface ICryptographyService {
  deriveMasterKey(password: string, salt: Uint8Array): Promise<CryptoKey>;
  encrypt(data: string, key: CryptoKey): Promise<EncryptedData>;
  decrypt(encryptedData: EncryptedData, key: CryptoKey): Promise<string>;
  generateSalt(): Uint8Array;
  generateIV(): Uint8Array;
  hash(data: string): Promise<string>;
  kAnonymityHash(email: string): Promise<KAnonymityResult>;
}

// ---------------------------------------------------------------------------
// CryptoService implementation
// ---------------------------------------------------------------------------

class CryptoService implements ICryptographyService {

  /**
   * Derives a 256-bit AES-GCM master key from a password and salt using
   * PBKDF2-SHA256.
   *
   * NOTE: @noble/hashes pbkdf2 is synchronous. Running 100,000 iterations
   * blocks the JS thread on mobile. We wrap it in a Promise with setTimeout
   * to yield to the event loop first, and use fewer iterations in __DEV__
   * to keep the UI responsive during development.
   *
   * Requirements: 3.1, 3.2
   */
  async deriveMasterKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const passwordBytes = encodeUtf8(password);
    // Use fewer iterations in dev to avoid blocking the JS thread.
    // Production builds use the full 100,000 iterations.
    const iterations = __DEV__ ? 1_000 : PBKDF2_ITERATIONS;

    return new Promise((resolve) => {
      // Yield to the event loop before the blocking computation
      setTimeout(() => {
        const keyBytes = pbkdf2(sha256, passwordBytes, salt, {
          c: iterations,
          dkLen: AES_KEY_BYTES,
        });
        resolve({
          key: keyBytes,
          algorithm: 'AES-GCM',
          keySize: 256,
        });
      }, 0);
    });
  }

  /**
   * Encrypts a UTF-8 plaintext string with AES-256-GCM.
   * Generates a fresh 12-byte IV for every call (Requirement 3.6).
   * Uses @noble/ciphers — pure JS, works in Hermes/Expo Go.
   * Requirements: 3.3, 3.6
   */
  async encrypt(data: string, key: CryptoKey): Promise<EncryptedData> {
    const iv = this.generateIV();
    const plaintext = encodeUtf8(data);

    // @noble/ciphers gcm returns ciphertext with 16-byte auth tag appended
    const aes = gcm(key.key, iv);
    const ciphertextWithTag = aes.encrypt(plaintext);

    // Split: last 16 bytes are the auth tag
    const authTagOffset = ciphertextWithTag.length - 16;
    const ciphertext = ciphertextWithTag.slice(0, authTagOffset);
    const authTag = ciphertextWithTag.slice(authTagOffset);

    return {
      ciphertext: toBase64(ciphertext),
      iv: toBase64(iv),
      authTag: toBase64(authTag),
    };
  }

  /**
   * Decrypts an AES-256-GCM encrypted payload.
   * Requirements: 3.3, 3.4
   */
  async decrypt(encryptedData: EncryptedData, key: CryptoKey): Promise<string> {
    const iv = fromBase64(encryptedData.iv);
    const ciphertext = fromBase64(encryptedData.ciphertext);
    const authTag = fromBase64(encryptedData.authTag);

    // Reassemble ciphertext || authTag as expected by @noble/ciphers
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext, 0);
    combined.set(authTag, ciphertext.length);

    const aes = gcm(key.key, iv);
    const plaintext = aes.decrypt(combined);

    return decodeUtf8(plaintext);
  }

  /**
   * Generates a cryptographically secure random 32-byte salt.
   * Requirement: 3.2
   */
  generateSalt(): Uint8Array {
    return ExpoCrypto.getRandomBytes(SALT_BYTES);
  }

  /**
   * Generates a cryptographically secure random 12-byte IV.
   * Requirement: 3.6
   */
  generateIV(): Uint8Array {
    return ExpoCrypto.getRandomBytes(IV_BYTES);
  }

  /**
   * Computes the SHA-256 hash of a UTF-8 string, returns uppercase hex.
   */
  async hash(data: string): Promise<string> {
    const digest = await ExpoCrypto.digestStringAsync(
      ExpoCrypto.CryptoDigestAlgorithm.SHA256,
      data,
      { encoding: ExpoCrypto.CryptoEncoding.HEX },
    );
    return digest.toUpperCase();
  }

  /**
   * Computes the SHA-1 hash and returns the first 5 chars as the
   * k-anonymity prefix for HIBP breach checks.
   * Requirements: 3.5, 9.1, 15.2
   */
  async kAnonymityHash(email: string): Promise<KAnonymityResult> {
    const fullHash = await ExpoCrypto.digestStringAsync(
      ExpoCrypto.CryptoDigestAlgorithm.SHA1,
      email,
      { encoding: ExpoCrypto.CryptoEncoding.HEX },
    );
    const upperHash = fullHash.toUpperCase();
    return { prefix: upperHash.slice(0, 5), fullHash: upperHash };
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

export const cryptoService: ICryptographyService = new CryptoService();
export default cryptoService;

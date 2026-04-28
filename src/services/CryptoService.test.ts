/**
 * CryptoService tests — Aegis Personal Cybersecurity Companion
 *
 * Covers:
 *  - PBKDF2 master key derivation (Req 3.1, 3.2)
 *  - AES-256-GCM encrypt / decrypt round-trip (Req 3.3, 3.4)
 *  - Unique IV per encryption call (Req 3.6)
 *  - Wrong-key decryption throws (Req 3.4)
 *  - Salt generation (Req 3.2)
 *  - SHA-256 hash (uppercase hex)
 *  - k-anonymity hash: 5-char prefix, full SHA-1 (Req 3.5, 9.1, 15.2)
 */

// ---------------------------------------------------------------------------
// Mock expo-crypto — use Node's built-in crypto for CSPRNG + digests
// ---------------------------------------------------------------------------

jest.mock('expo-crypto', () => {
  const { webcrypto } = require('crypto') as typeof import('crypto');
  return {
    getRandomBytes: (size: number) => {
      const bytes = new Uint8Array(size);
      webcrypto.getRandomValues(bytes);
      return bytes;
    },
    digestStringAsync: async (
      algorithm: string,
      data: string,
      options?: { encoding?: string },
    ) => {
      const algoMap: Record<string, string> = {
        SHA1: 'SHA-1',
        SHA256: 'SHA-256',
        SHA512: 'SHA-512',
      };
      const webAlgo = algoMap[algorithm] ?? algorithm;
      const encoded = new TextEncoder().encode(data);
      const hashBuffer = await webcrypto.subtle.digest(webAlgo, encoded);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
      if (options?.encoding === 'hex') return hex;
      return Buffer.from(hashArray).toString('base64');
    },
    CryptoDigestAlgorithm: { SHA1: 'SHA1', SHA256: 'SHA256', SHA512: 'SHA512' },
    CryptoEncoding: { HEX: 'hex', BASE64: 'base64' },
  };
});

import { cryptoService, CryptoKey } from './CryptoService';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeKey(password = 'test-password'): Promise<CryptoKey> {
  const salt = cryptoService.generateSalt();
  return cryptoService.deriveMasterKey(password, salt);
}

// ---------------------------------------------------------------------------
// deriveMasterKey
// ---------------------------------------------------------------------------

describe('CryptoService.deriveMasterKey', () => {
  it('returns a CryptoKey with algorithm AES-GCM and keySize 256', async () => {
    const key = await makeKey();
    expect(key.algorithm).toBe('AES-GCM');
    expect(key.keySize).toBe(256);
  });

  it('key.key is a 32-byte Uint8Array', async () => {
    const key = await makeKey();
    expect(key.key).toBeInstanceOf(Uint8Array);
    expect(key.key.length).toBe(32);
  });

  it('same password + same salt produces the same key (deterministic)', async () => {
    const salt = cryptoService.generateSalt();
    const k1 = await cryptoService.deriveMasterKey('password', salt);
    const k2 = await cryptoService.deriveMasterKey('password', salt);
    expect(Buffer.from(k1.key).toString('hex')).toBe(Buffer.from(k2.key).toString('hex'));
  });

  it('different passwords produce different keys', async () => {
    const salt = cryptoService.generateSalt();
    const k1 = await cryptoService.deriveMasterKey('password-A', salt);
    const k2 = await cryptoService.deriveMasterKey('password-B', salt);
    expect(Buffer.from(k1.key).toString('hex')).not.toBe(Buffer.from(k2.key).toString('hex'));
  });

  it('different salts produce different keys for the same password', async () => {
    const s1 = cryptoService.generateSalt();
    const s2 = cryptoService.generateSalt();
    const k1 = await cryptoService.deriveMasterKey('same-password', s1);
    const k2 = await cryptoService.deriveMasterKey('same-password', s2);
    expect(Buffer.from(k1.key).toString('hex')).not.toBe(Buffer.from(k2.key).toString('hex'));
  });
});

// ---------------------------------------------------------------------------
// generateSalt
// ---------------------------------------------------------------------------

describe('CryptoService.generateSalt', () => {
  it('returns a 32-byte Uint8Array', () => {
    const salt = cryptoService.generateSalt();
    expect(salt).toBeInstanceOf(Uint8Array);
    expect(salt.length).toBe(32);
  });

  it('two calls produce different salts (CSPRNG)', () => {
    const s1 = cryptoService.generateSalt();
    const s2 = cryptoService.generateSalt();
    expect(Buffer.from(s1).toString('hex')).not.toBe(Buffer.from(s2).toString('hex'));
  });
});

// ---------------------------------------------------------------------------
// generateIV
// ---------------------------------------------------------------------------

describe('CryptoService.generateIV', () => {
  it('returns a 12-byte Uint8Array', () => {
    const iv = cryptoService.generateIV();
    expect(iv).toBeInstanceOf(Uint8Array);
    expect(iv.length).toBe(12);
  });

  it('two calls produce different IVs', () => {
    const iv1 = cryptoService.generateIV();
    const iv2 = cryptoService.generateIV();
    expect(Buffer.from(iv1).toString('hex')).not.toBe(Buffer.from(iv2).toString('hex'));
  });
});

// ---------------------------------------------------------------------------
// encrypt / decrypt round-trip
// ---------------------------------------------------------------------------

describe('CryptoService encrypt / decrypt', () => {
  it('decrypts to the original plaintext', async () => {
    const key = await makeKey();
    const plaintext = 'my-super-secret-password';
    const encrypted = await cryptoService.encrypt(plaintext, key);
    const decrypted = await cryptoService.decrypt(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('works with empty string', async () => {
    const key = await makeKey();
    const encrypted = await cryptoService.encrypt('', key);
    const decrypted = await cryptoService.decrypt(encrypted, key);
    expect(decrypted).toBe('');
  });

  it('works with unicode / emoji content', async () => {
    const key = await makeKey();
    const plaintext = '🔐 Sécurité — パスワード';
    const encrypted = await cryptoService.encrypt(plaintext, key);
    const decrypted = await cryptoService.decrypt(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('works with long strings (1000 chars)', async () => {
    const key = await makeKey();
    const plaintext = 'A'.repeat(1000);
    const encrypted = await cryptoService.encrypt(plaintext, key);
    const decrypted = await cryptoService.decrypt(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('encrypted output has ciphertext, iv, and authTag fields', async () => {
    const key = await makeKey();
    const encrypted = await cryptoService.encrypt('test', key);
    expect(typeof encrypted.ciphertext).toBe('string');
    expect(typeof encrypted.iv).toBe('string');
    expect(typeof encrypted.authTag).toBe('string');
    expect(encrypted.ciphertext.length).toBeGreaterThan(0);
    expect(encrypted.iv.length).toBeGreaterThan(0);
    expect(encrypted.authTag.length).toBeGreaterThan(0);
  });

  it('ciphertext does not contain the plaintext (Req 3.3)', async () => {
    const key = await makeKey();
    const plaintext = 'plaintext-secret-value';
    const encrypted = await cryptoService.encrypt(plaintext, key);
    expect(encrypted.ciphertext).not.toContain(plaintext);
    expect(encrypted.iv).not.toContain(plaintext);
    expect(encrypted.authTag).not.toContain(plaintext);
  });

  it('two encryptions of the same plaintext produce different ciphertexts (unique IVs, Req 3.6)', async () => {
    const key = await makeKey();
    const e1 = await cryptoService.encrypt('same-value', key);
    const e2 = await cryptoService.encrypt('same-value', key);
    expect(e1.iv).not.toBe(e2.iv);
    expect(e1.ciphertext).not.toBe(e2.ciphertext);
  });

  it('decryption with wrong key throws (Req 3.4)', async () => {
    const key1 = await makeKey('password-1');
    const key2 = await makeKey('password-2');
    const encrypted = await cryptoService.encrypt('secret', key1);
    await expect(cryptoService.decrypt(encrypted, key2)).rejects.toThrow();
  });

  it('decryption with tampered ciphertext throws (Req 3.4)', async () => {
    const key = await makeKey();
    const encrypted = await cryptoService.encrypt('secret', key);
    // Tamper with the ciphertext
    const tampered = { ...encrypted, ciphertext: encrypted.ciphertext.slice(0, -4) + 'XXXX' };
    await expect(cryptoService.decrypt(tampered, key)).rejects.toThrow();
  });

  it('decryption with tampered authTag throws (Req 3.4)', async () => {
    const key = await makeKey();
    const encrypted = await cryptoService.encrypt('secret', key);
    const tampered = { ...encrypted, authTag: 'AAAAAAAAAAAAAAAAAAAAAA==' };
    await expect(cryptoService.decrypt(tampered, key)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// hash (SHA-256)
// ---------------------------------------------------------------------------

describe('CryptoService.hash', () => {
  it('returns a non-empty uppercase hex string', async () => {
    const result = await cryptoService.hash('test');
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    expect(result).toBe(result.toUpperCase());
    expect(/^[0-9A-F]+$/.test(result)).toBe(true);
  });

  it('same input always produces the same hash (deterministic)', async () => {
    const h1 = await cryptoService.hash('hello');
    const h2 = await cryptoService.hash('hello');
    expect(h1).toBe(h2);
  });

  it('different inputs produce different hashes', async () => {
    const h1 = await cryptoService.hash('hello');
    const h2 = await cryptoService.hash('world');
    expect(h1).not.toBe(h2);
  });

  it('SHA-256 output is 64 hex characters (256 bits)', async () => {
    const result = await cryptoService.hash('test');
    expect(result.length).toBe(64);
  });
});

// ---------------------------------------------------------------------------
// kAnonymityHash (SHA-1 prefix for HIBP)
// ---------------------------------------------------------------------------

describe('CryptoService.kAnonymityHash', () => {
  it('returns a prefix of exactly 5 characters (Req 15.2)', async () => {
    const result = await cryptoService.kAnonymityHash('test@example.com');
    expect(result.prefix.length).toBe(5);
  });

  it('prefix is uppercase hex', async () => {
    const result = await cryptoService.kAnonymityHash('test@example.com');
    expect(/^[0-9A-F]{5}$/.test(result.prefix)).toBe(true);
  });

  it('fullHash is 40 uppercase hex characters (SHA-1)', async () => {
    const result = await cryptoService.kAnonymityHash('test@example.com');
    expect(result.fullHash.length).toBe(40);
    expect(/^[0-9A-F]{40}$/.test(result.fullHash)).toBe(true);
  });

  it('prefix is the first 5 chars of fullHash', async () => {
    const result = await cryptoService.kAnonymityHash('test@example.com');
    expect(result.fullHash.startsWith(result.prefix)).toBe(true);
  });

  it('same email always produces the same prefix (deterministic)', async () => {
    const r1 = await cryptoService.kAnonymityHash('alice@example.com');
    const r2 = await cryptoService.kAnonymityHash('alice@example.com');
    expect(r1.prefix).toBe(r2.prefix);
    expect(r1.fullHash).toBe(r2.fullHash);
  });

  it('different emails produce different prefixes', async () => {
    const r1 = await cryptoService.kAnonymityHash('alice@example.com');
    const r2 = await cryptoService.kAnonymityHash('bob@example.com');
    expect(r1.fullHash).not.toBe(r2.fullHash);
  });

  it('prefix does not contain the original email (Req 9.1, 15.2)', async () => {
    const email = 'alice@example.com';
    const result = await cryptoService.kAnonymityHash(email);
    expect(result.prefix).not.toContain(email);
    expect(result.prefix).not.toContain('@');
  });
});

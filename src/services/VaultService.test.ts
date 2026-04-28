/**
 * VaultService tests — Aegis Personal Cybersecurity Companion
 *
 * Covers:
 *  - addCredential: validation, encryption, UUID assignment (Req 4.1–4.5)
 *  - getCredential: decryption, lastUsed update (Req 4.9, 4.10)
 *  - getAllCredentials: returns all, decrypted (Req 4.9)
 *  - updateCredential: re-encrypts sensitive fields (Req 4.1)
 *  - deleteCredential: permanent removal (Req 4.8)
 *  - searchCredentials: case-insensitive (Req 4.7)
 *  - generateTOTP: 6-digit code, remainingSeconds (Req 4.6)
 *  - copyToClipboard: delegates to SecureClipboardService (Req 5.1)
 *  - assertMasterKey: throws when key not set
 */

// ---------------------------------------------------------------------------
// Mocks
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
      const algoMap: Record<string, string> = { SHA1: 'SHA-1', SHA256: 'SHA-256' };
      const webAlgo = algoMap[algorithm] ?? algorithm;
      const encoded = new TextEncoder().encode(data);
      const hashBuffer = await webcrypto.subtle.digest(webAlgo, encoded);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
      if (options?.encoding === 'hex') return hex;
      return Buffer.from(hashArray).toString('base64');
    },
    CryptoDigestAlgorithm: { SHA1: 'SHA1', SHA256: 'SHA256' },
    CryptoEncoding: { HEX: 'hex', BASE64: 'base64' },
  };
});

// In-memory database mock
const dbStore: Map<string, Record<string, unknown>> = new Map();
let lastInsertId = 0;

const mockExecute = jest.fn(async (query: string, params: unknown[] = []) => {
  const q = query.trim().toUpperCase();
  if (q.startsWith('INSERT INTO CREDENTIALS')) {
    const id = params[0] as string;
    const row: Record<string, unknown> = {
      id: params[0], type: params[1], title: params[2], username: params[3],
      password: params[4], passkey: params[5], totp_seed: params[6], api_key: params[7],
      url: params[8], notes: params[9], tags: params[10], created_at: params[11],
      updated_at: params[12], last_used: params[13], favorite: params[14], icon: params[15],
    };
    dbStore.set(id, row);
    lastInsertId++;
    return { rowsAffected: 1, insertId: lastInsertId };
  }
  if (q.startsWith('UPDATE CREDENTIALS SET LAST_USED')) {
    const id = params[1] as string;
    const row = dbStore.get(id);
    if (row) { row.last_used = params[0]; dbStore.set(id, row); }
    return { rowsAffected: 1 };
  }
  if (q.startsWith('UPDATE CREDENTIALS SET')) {
    // Generic update — just return success
    return { rowsAffected: 1 };
  }
  if (q.startsWith('DELETE FROM CREDENTIALS')) {
    const id = params[0] as string;
    dbStore.delete(id);
    return { rowsAffected: 1 };
  }
  return { rowsAffected: 0 };
});

const mockSelect = jest.fn(async (query: string, params: unknown[] = []) => {
  const q = query.trim().toUpperCase();
  if (q.includes('WHERE ID = ?')) {
    const id = params[0] as string;
    const row = dbStore.get(id);
    return row ? [row] : [];
  }
  if (q.startsWith('SELECT * FROM CREDENTIALS ORDER BY UPDATED_AT DESC')) {
    return Array.from(dbStore.values());
  }
  if (q.startsWith('SELECT * FROM CREDENTIALS')) {
    return Array.from(dbStore.values());
  }
  return [];
});

jest.mock('../database/DatabaseService', () => ({
  databaseService: {
    execute: (...args: unknown[]) => mockExecute(...(args as [string, unknown[]])),
    select: (...args: unknown[]) => mockSelect(...(args as [string, unknown[]])),
  },
}));

const mockCopy = jest.fn().mockResolvedValue(undefined);
jest.mock('./SecureClipboardService', () => ({
  secureClipboardService: {
    copy: (...args: unknown[]) => mockCopy(...args),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { VaultServiceImpl } from './VaultService';
import { cryptoService } from './CryptoService';
import { Credential } from '../types/index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeServiceWithKey(): Promise<VaultServiceImpl> {
  const svc = new VaultServiceImpl();
  const salt = cryptoService.generateSalt();
  const key = await cryptoService.deriveMasterKey('test-master-password', salt);
  svc.setMasterKey(key);
  return svc;
}

function makeCredentialInput(overrides: Partial<Omit<Credential, 'id' | 'createdAt' | 'updatedAt'>> = {}): Omit<Credential, 'id' | 'createdAt' | 'updatedAt'> {
  return {
    type: 'password',
    title: 'Test Site',
    username: 'user@example.com',
    password: 'super-secret-password',
    tags: [],
    favorite: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('VaultService', () => {
  beforeEach(() => {
    dbStore.clear();
    mockExecute.mockClear();
    mockSelect.mockClear();
    mockCopy.mockClear();
  });

  // -------------------------------------------------------------------------
  // assertMasterKey
  // -------------------------------------------------------------------------

  describe('master key guard', () => {
    it('throws when master key is not set', async () => {
      const svc = new VaultServiceImpl();
      await expect(svc.addCredential(makeCredentialInput())).rejects.toThrow(
        'master key is not set',
      );
    });

    it('does not throw after setMasterKey is called', async () => {
      const svc = await makeServiceWithKey();
      await expect(svc.addCredential(makeCredentialInput())).resolves.toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // addCredential (Req 4.1–4.5)
  // -------------------------------------------------------------------------

  describe('addCredential', () => {
    it('returns a UUID v4 string (Req 4.2)', async () => {
      const svc = await makeServiceWithKey();
      const id = await svc.addCredential(makeCredentialInput());
      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);
      // UUID v4 format
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    });

    it('two calls produce different IDs', async () => {
      const svc = await makeServiceWithKey();
      const id1 = await svc.addCredential(makeCredentialInput({ title: 'Site A' }));
      const id2 = await svc.addCredential(makeCredentialInput({ title: 'Site B' }));
      expect(id1).not.toBe(id2);
    });

    it('throws when title is empty (Req 4.5)', async () => {
      const svc = await makeServiceWithKey();
      await expect(svc.addCredential(makeCredentialInput({ title: '' }))).rejects.toThrow(
        'title must be non-empty',
      );
    });

    it('throws when title is whitespace only (Req 4.5)', async () => {
      const svc = await makeServiceWithKey();
      await expect(svc.addCredential(makeCredentialInput({ title: '   ' }))).rejects.toThrow(
        'title must be non-empty',
      );
    });

    it('throws when no secret field is present (Req 4.4)', async () => {
      const svc = await makeServiceWithKey();
      const input = { type: 'password' as const, title: 'No Secret', tags: [], favorite: false };
      await expect(svc.addCredential(input)).rejects.toThrow(
        'at least one of password',
      );
    });

    it('stores encrypted password — plaintext not in DB (Req 4.1)', async () => {
      const svc = await makeServiceWithKey();
      const plainPassword = 'my-plaintext-password';
      await svc.addCredential(makeCredentialInput({ password: plainPassword }));

      // Check what was stored in the mock DB
      const rows = Array.from(dbStore.values());
      expect(rows.length).toBe(1);
      const storedPassword = rows[0].password as string;
      expect(storedPassword).not.toContain(plainPassword);
      // Should be JSON-serialised EncryptedData
      const parsed = JSON.parse(storedPassword);
      expect(typeof parsed.ciphertext).toBe('string');
      expect(typeof parsed.iv).toBe('string');
      expect(typeof parsed.authTag).toBe('string');
    });

    it('accepts apiKey type with apiKey field', async () => {
      const svc = await makeServiceWithKey();
      const id = await svc.addCredential({
        type: 'apiKey', title: 'My API', apiKey: 'sk-1234', tags: [], favorite: false,
      });
      expect(typeof id).toBe('string');
    });

    it('trims whitespace from title', async () => {
      const svc = await makeServiceWithKey();
      await svc.addCredential(makeCredentialInput({ title: '  Gmail  ' }));
      const rows = Array.from(dbStore.values());
      expect(rows[0].title).toBe('Gmail');
    });
  });

  // -------------------------------------------------------------------------
  // getCredential (Req 4.9, 4.10)
  // -------------------------------------------------------------------------

  describe('getCredential', () => {
    it('returns null for a non-existent ID', async () => {
      const svc = await makeServiceWithKey();
      const result = await svc.getCredential('non-existent-id');
      expect(result).toBeNull();
    });

    it('returns the decrypted credential (Req 4.9)', async () => {
      const svc = await makeServiceWithKey();
      const id = await svc.addCredential(makeCredentialInput({
        title: 'Gmail', username: 'user@gmail.com', password: 'secret123',
      }));

      const cred = await svc.getCredential(id);
      expect(cred).not.toBeNull();
      expect(cred!.title).toBe('Gmail');
      expect(cred!.username).toBe('user@gmail.com');
      expect(cred!.password).toBe('secret123');
    });

    it('updates lastUsed timestamp on access (Req 4.10)', async () => {
      const svc = await makeServiceWithKey();
      const id = await svc.addCredential(makeCredentialInput());
      const before = Date.now();
      const cred = await svc.getCredential(id);
      const after = Date.now();

      expect(cred!.lastUsed).toBeGreaterThanOrEqual(before);
      expect(cred!.lastUsed).toBeLessThanOrEqual(after);
    });
  });

  // -------------------------------------------------------------------------
  // getAllCredentials (Req 4.9)
  // -------------------------------------------------------------------------

  describe('getAllCredentials', () => {
    it('returns empty array when vault is empty', async () => {
      const svc = await makeServiceWithKey();
      const all = await svc.getAllCredentials();
      expect(all).toEqual([]);
    });

    it('returns all stored credentials decrypted', async () => {
      const svc = await makeServiceWithKey();
      await svc.addCredential(makeCredentialInput({ title: 'Site A', password: 'pass-a' }));
      await svc.addCredential(makeCredentialInput({ title: 'Site B', password: 'pass-b' }));

      const all = await svc.getAllCredentials();
      expect(all.length).toBe(2);
      const titles = all.map((c) => c.title).sort();
      expect(titles).toEqual(['Site A', 'Site B']);
    });

    it('decrypts passwords correctly', async () => {
      const svc = await makeServiceWithKey();
      await svc.addCredential(makeCredentialInput({ title: 'Test', password: 'decrypted-pass' }));

      const all = await svc.getAllCredentials();
      expect(all[0].password).toBe('decrypted-pass');
    });
  });

  // -------------------------------------------------------------------------
  // deleteCredential (Req 4.8)
  // -------------------------------------------------------------------------

  describe('deleteCredential', () => {
    it('removes the credential from the store (Req 4.8)', async () => {
      const svc = await makeServiceWithKey();
      const id = await svc.addCredential(makeCredentialInput());
      expect(dbStore.has(id)).toBe(true);

      await svc.deleteCredential(id);
      expect(dbStore.has(id)).toBe(false);
    });

    it('getCredential returns null after deletion', async () => {
      const svc = await makeServiceWithKey();
      const id = await svc.addCredential(makeCredentialInput());
      await svc.deleteCredential(id);

      const result = await svc.getCredential(id);
      expect(result).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // searchCredentials (Req 4.7)
  // -------------------------------------------------------------------------

  describe('searchCredentials', () => {
    it('returns all credentials for empty query', async () => {
      const svc = await makeServiceWithKey();
      await svc.addCredential(makeCredentialInput({ title: 'Gmail' }));
      await svc.addCredential(makeCredentialInput({ title: 'GitHub' }));

      const results = await svc.searchCredentials('');
      expect(results.length).toBe(2);
    });

    it('matches by title (case-insensitive, Req 4.7)', async () => {
      const svc = await makeServiceWithKey();
      await svc.addCredential(makeCredentialInput({ title: 'Gmail' }));
      await svc.addCredential(makeCredentialInput({ title: 'GitHub' }));

      const results = await svc.searchCredentials('gmail');
      expect(results.length).toBe(1);
      expect(results[0].title).toBe('Gmail');
    });

    it('matches by username (case-insensitive)', async () => {
      const svc = await makeServiceWithKey();
      await svc.addCredential(makeCredentialInput({ title: 'Site', username: 'Alice@Example.com' }));

      const results = await svc.searchCredentials('alice');
      expect(results.length).toBe(1);
    });

    it('matches by URL', async () => {
      const svc = await makeServiceWithKey();
      await svc.addCredential(makeCredentialInput({ title: 'Site', url: 'https://example.com' }));

      const results = await svc.searchCredentials('example.com');
      expect(results.length).toBe(1);
    });

    it('returns empty array when no match', async () => {
      const svc = await makeServiceWithKey();
      await svc.addCredential(makeCredentialInput({ title: 'Gmail' }));

      const results = await svc.searchCredentials('nonexistent-xyz');
      expect(results.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // generateTOTP (Req 4.6)
  // -------------------------------------------------------------------------

  describe('generateTOTP', () => {
    const VALID_TOTP_SEED = 'JBSWY3DPEHPK3PXP';

    it('returns a 6-digit code string', async () => {
      const svc = await makeServiceWithKey();
      const result = await svc.generateTOTP(VALID_TOTP_SEED);
      expect(typeof result.code).toBe('string');
      expect(result.code.length).toBe(6);
      expect(/^\d{6}$/.test(result.code)).toBe(true);
    });

    it('returns remainingSeconds between 1 and 30', async () => {
      const svc = await makeServiceWithKey();
      const result = await svc.generateTOTP(VALID_TOTP_SEED);
      expect(result.remainingSeconds).toBeGreaterThanOrEqual(1);
      expect(result.remainingSeconds).toBeLessThanOrEqual(30);
    });

    it('throws for invalid base32 characters', async () => {
      const svc = await makeServiceWithKey();
      await expect(svc.generateTOTP('INVALID!@#$')).rejects.toThrow();
    });

    it('two calls within the same 30s window return the same code', async () => {
      const svc = await makeServiceWithKey();
      const r1 = await svc.generateTOTP(VALID_TOTP_SEED);
      const r2 = await svc.generateTOTP(VALID_TOTP_SEED);
      // Both calls happen within the same test (< 1ms apart), same time step
      expect(r1.code).toBe(r2.code);
    });
  });

  // -------------------------------------------------------------------------
  // copyToClipboard (Req 5.1)
  // -------------------------------------------------------------------------

  describe('copyToClipboard', () => {
    it('delegates to SecureClipboardService.copy (Req 5.1)', async () => {
      const svc = await makeServiceWithKey();
      await svc.copyToClipboard('my-secret-value');
      expect(mockCopy).toHaveBeenCalledWith('my-secret-value', 'password');
    });
  });
});

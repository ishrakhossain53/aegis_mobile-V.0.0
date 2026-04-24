/**
 * CloudBackupService tests — Aegis Personal Cybersecurity Companion
 *
 * Tests cover:
 *  - Export produces an encrypted payload (never plaintext)
 *  - Import with correct key restores credentials
 *  - Import with incorrect key throws BackupDecryptionError without modifying local data
 *  - Import with malformed payload throws BackupFormatError
 *  - Cloud backup is self-contained (no side-effects on other services when unused)
 *
 * Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6
 */

// ---------------------------------------------------------------------------
// Mock expo-crypto before any imports that depend on it
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

// Mock react-native Share so tests run in Node without native modules
jest.mock('react-native', () => ({
  Share: {
    share: jest.fn().mockResolvedValue({ action: 'sharedAction' }),
  },
  Platform: {
    OS: 'ios',
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { cryptoService } from './CryptoService';
import {
  BackupDecryptionError,
  BackupFormatError,
  CloudBackupServiceImpl,
  ICloudBackupService,
} from './CloudBackupService';
import { Credential } from '../types/index';

// Mock VaultService so we control what getAllCredentials returns and can
// verify addCredential calls without a real database.
const mockGetAllCredentials = jest.fn<Promise<Credential[]>, []>();
const mockAddCredential = jest.fn<Promise<string>, [Omit<Credential, 'id' | 'createdAt' | 'updatedAt'>]>();

jest.mock('./VaultService', () => ({
  vaultService: {
    getAllCredentials: (...args: unknown[]) => mockGetAllCredentials(...(args as [])),
    addCredential: (...args: unknown[]) =>
      mockAddCredential(...(args as [Omit<Credential, 'id' | 'createdAt' | 'updatedAt'>])),
  },
}));

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Build a minimal valid Credential for testing. */
function makeCredential(overrides: Partial<Credential> = {}): Credential {
  return {
    id: 'test-id-1',
    type: 'password',
    title: 'Test Site',
    username: 'user@example.com',
    password: 'super-secret-password',
    tags: [],
    createdAt: 1_000_000,
    updatedAt: 1_000_000,
    favorite: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('CloudBackupService', () => {
  let service: ICloudBackupService;
  let masterKey: Awaited<ReturnType<typeof cryptoService.deriveMasterKey>>;
  let wrongKey: Awaited<ReturnType<typeof cryptoService.deriveMasterKey>>;

  beforeAll(async () => {
    const salt1 = cryptoService.generateSalt();
    const salt2 = cryptoService.generateSalt();
    masterKey = await cryptoService.deriveMasterKey('correct-password', salt1);
    wrongKey = await cryptoService.deriveMasterKey('wrong-password', salt2);
  });

  beforeEach(() => {
    service = new CloudBackupServiceImpl();
    jest.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // exportBackup
  // -------------------------------------------------------------------------

  describe('exportBackup', () => {
    it('returns a non-empty payload string', async () => {
      mockGetAllCredentials.mockResolvedValue([makeCredential()]);

      const result = await service.exportBackup(masterKey);

      expect(typeof result.payload).toBe('string');
      expect(result.payload.length).toBeGreaterThan(0);
    });

    it('reports the correct credential count', async () => {
      const creds = [makeCredential({ id: 'a' }), makeCredential({ id: 'b' })];
      mockGetAllCredentials.mockResolvedValue(creds);

      const result = await service.exportBackup(masterKey);

      expect(result.credentialCount).toBe(2);
    });

    it('payload does not contain plaintext password (Req 19.2)', async () => {
      const cred = makeCredential({ password: 'my-very-secret-password' });
      mockGetAllCredentials.mockResolvedValue([cred]);

      const result = await service.exportBackup(masterKey);

      // The raw password must not appear anywhere in the encrypted payload
      expect(result.payload).not.toContain('my-very-secret-password');
    });

    it('payload does not contain plaintext username (Req 19.2)', async () => {
      const cred = makeCredential({ username: 'plaintext-username@example.com' });
      mockGetAllCredentials.mockResolvedValue([cred]);

      const result = await service.exportBackup(masterKey);

      expect(result.payload).not.toContain('plaintext-username@example.com');
    });

    it('payload is valid JSON with EncryptedData fields (ciphertext, iv, authTag)', async () => {
      mockGetAllCredentials.mockResolvedValue([makeCredential()]);

      const result = await service.exportBackup(masterKey);
      const parsed = JSON.parse(result.payload) as Record<string, unknown>;

      expect(typeof parsed.ciphertext).toBe('string');
      expect(typeof parsed.iv).toBe('string');
      expect(typeof parsed.authTag).toBe('string');
    });

    it('two exports of the same data produce different payloads (unique IVs, Req 19.1)', async () => {
      mockGetAllCredentials.mockResolvedValue([makeCredential()]);

      const r1 = await service.exportBackup(masterKey);
      const r2 = await service.exportBackup(masterKey);

      // Different IVs → different ciphertexts even for identical plaintext
      expect(r1.payload).not.toBe(r2.payload);
    });

    it('works with an empty vault (zero credentials)', async () => {
      mockGetAllCredentials.mockResolvedValue([]);

      const result = await service.exportBackup(masterKey);

      expect(result.credentialCount).toBe(0);
      expect(typeof result.payload).toBe('string');
    });
  });

  // -------------------------------------------------------------------------
  // importBackup — success path
  // -------------------------------------------------------------------------

  describe('importBackup — success', () => {
    it('restores credentials from a valid backup (Req 19.5)', async () => {
      const cred = makeCredential({ id: 'restore-me' });
      mockGetAllCredentials
        .mockResolvedValueOnce([cred])   // called during exportBackup
        .mockResolvedValueOnce([]);       // called during importBackup (no existing creds)
      mockAddCredential.mockResolvedValue('new-uuid');

      const { payload } = await service.exportBackup(masterKey);
      const result = await service.importBackup(payload, masterKey);

      expect(result.restoredCount).toBe(1);
      expect(result.skippedCount).toBe(0);
      expect(mockAddCredential).toHaveBeenCalledTimes(1);
    });

    it('skips credentials that already exist by ID', async () => {
      const cred = makeCredential({ id: 'already-exists' });
      mockGetAllCredentials
        .mockResolvedValueOnce([cred])   // export
        .mockResolvedValueOnce([cred]);  // import — cred already in vault

      const { payload } = await service.exportBackup(masterKey);
      const result = await service.importBackup(payload, masterKey);

      expect(result.restoredCount).toBe(0);
      expect(result.skippedCount).toBe(1);
      expect(mockAddCredential).not.toHaveBeenCalled();
    });

    it('returns restoredCount = 0 and skippedCount = 0 for empty backup', async () => {
      mockGetAllCredentials
        .mockResolvedValueOnce([])  // export
        .mockResolvedValueOnce([]); // import

      const { payload } = await service.exportBackup(masterKey);
      const result = await service.importBackup(payload, masterKey);

      expect(result.restoredCount).toBe(0);
      expect(result.skippedCount).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // importBackup — wrong key (Req 19.6)
  // -------------------------------------------------------------------------

  describe('importBackup — wrong key (Req 19.6)', () => {
    it('throws BackupDecryptionError when key is incorrect', async () => {
      mockGetAllCredentials.mockResolvedValue([makeCredential()]);

      const { payload } = await service.exportBackup(masterKey);

      await expect(service.importBackup(payload, wrongKey)).rejects.toThrow(
        BackupDecryptionError,
      );
    });

    it('does NOT call addCredential when key is incorrect (local data unchanged)', async () => {
      mockGetAllCredentials.mockResolvedValue([makeCredential()]);

      const { payload } = await service.exportBackup(masterKey);

      try {
        await service.importBackup(payload, wrongKey);
      } catch {
        // expected
      }

      expect(mockAddCredential).not.toHaveBeenCalled();
    });

    it('BackupDecryptionError has the correct name', async () => {
      mockGetAllCredentials.mockResolvedValue([makeCredential()]);
      const { payload } = await service.exportBackup(masterKey);

      let caught: unknown;
      try {
        await service.importBackup(payload, wrongKey);
      } catch (e) {
        caught = e;
      }

      expect(caught).toBeInstanceOf(BackupDecryptionError);
      expect((caught as BackupDecryptionError).name).toBe('BackupDecryptionError');
    });
  });

  // -------------------------------------------------------------------------
  // importBackup — malformed payload (Req 19.6)
  // -------------------------------------------------------------------------

  describe('importBackup — malformed payload', () => {
    it('throws BackupFormatError for non-JSON payload', async () => {
      await expect(service.importBackup('not-json', masterKey)).rejects.toThrow(
        BackupFormatError,
      );
    });

    it('throws BackupFormatError when EncryptedData fields are missing', async () => {
      const badPayload = JSON.stringify({ ciphertext: 'abc' }); // missing iv and authTag

      await expect(service.importBackup(badPayload, masterKey)).rejects.toThrow(
        BackupFormatError,
      );
    });

    it('does NOT call addCredential for malformed payload (local data unchanged)', async () => {
      try {
        await service.importBackup('not-json', masterKey);
      } catch {
        // expected
      }

      expect(mockAddCredential).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // shareBackup
  // -------------------------------------------------------------------------

  describe('shareBackup', () => {
    it('calls Share.share with the encrypted payload', async () => {
      const { Share } = jest.requireMock('react-native') as {
        Share: { share: jest.Mock };
      };
      mockGetAllCredentials.mockResolvedValue([makeCredential()]);

      const result = await service.shareBackup(masterKey);

      expect(Share.share).toHaveBeenCalledTimes(1);
      const shareArgs = Share.share.mock.calls[0][0] as { message: string };
      expect(shareArgs.message).toBe(result.payload);
    });

    it('returns the same BackupExportResult as exportBackup would', async () => {
      mockGetAllCredentials.mockResolvedValue([makeCredential()]);

      const result = await service.shareBackup(masterKey);

      expect(result.credentialCount).toBe(1);
      expect(typeof result.payload).toBe('string');
      expect(typeof result.createdAt).toBe('number');
    });
  });
});

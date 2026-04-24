/**
 * VaultService — Aegis Personal Cybersecurity Companion
 *
 * Implements IVaultService providing:
 *  - AES-256-GCM encryption of sensitive credential fields before persistence
 *  - UUID v4 assignment on credential creation
 *  - Validation: non-empty title, at least one secret field present
 *  - Decryption of all encrypted fields on retrieval
 *  - Case-insensitive search across title, username, URL, and tags
 *  - Permanent deletion of credentials
 *  - lastUsed timestamp update on every access
 *  - RFC 6238 TOTP generation (6-digit, 30-second window, HMAC-SHA1)
 *  - Clipboard copy (stub — wired to SecureClipboardService in task 9)
 *
 * Encrypted fields stored as JSON-serialised EncryptedData in the DB.
 * Tags stored as JSON array string.
 * favorite stored as 0/1 integer.
 *
 * Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10
 */

import * as ExpoCrypto from 'expo-crypto';
import { cryptoService, CryptoKey } from './CryptoService';
import { databaseService } from '../database/DatabaseService';
import { secureClipboardService } from './SecureClipboardService';
import { Credential, EncryptedData, TOTPCode } from '../types/index';

// ---------------------------------------------------------------------------
// IVaultService interface
// ---------------------------------------------------------------------------

export interface IVaultService {
  /** Add a new credential. Returns the assigned UUID v4. */
  addCredential(
    credential: Omit<Credential, 'id' | 'createdAt' | 'updatedAt'>,
  ): Promise<string>;

  /** Retrieve a credential by ID (decrypted). Returns null if not found. */
  getCredential(id: string): Promise<Credential | null>;

  /** Retrieve all credentials (decrypted). */
  getAllCredentials(): Promise<Credential[]>;

  /** Update an existing credential, re-encrypting any sensitive fields. */
  updateCredential(id: string, updates: Partial<Credential>): Promise<void>;

  /** Permanently delete a credential. */
  deleteCredential(id: string): Promise<void>;

  /**
   * Search credentials by query string.
   * Case-insensitive match against title, username, URL, and tags.
   */
  searchCredentials(query: string): Promise<Credential[]>;

  /** Generate a live TOTP code from a base32-encoded seed per RFC 6238. */
  generateTOTP(totpSeed: string): Promise<TOTPCode>;

  /** Copy a value to the clipboard via SecureClipboardService (wired in task 9). */
  copyToClipboard(value: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Raw DB row type (snake_case columns)
// ---------------------------------------------------------------------------

interface CredentialRow {
  id: string;
  type: 'password' | 'passkey' | 'totp' | 'apiKey';
  title: string;
  username: string | null;
  password: string | null;
  passkey: string | null;
  totp_seed: string | null;
  api_key: string | null;
  url: string | null;
  notes: string | null;
  tags: string | null;
  created_at: number;
  updated_at: number;
  last_used: number | null;
  favorite: number;
  icon: string | null;
}

// ---------------------------------------------------------------------------
// UUID v4 generation
// ---------------------------------------------------------------------------

/**
 * Generates a UUID v4 string.
 * Uses `crypto.randomUUID()` when available (Hermes / modern environments),
 * falling back to `expo-crypto`'s `getRandomBytes` for older runtimes.
 */
function generateUUIDv4(): string {
  // crypto.randomUUID is available in Hermes (React Native 0.71+)
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  // Fallback: construct UUID v4 from random bytes
  const bytes = ExpoCrypto.getRandomBytes(16);
  // Set version bits (version 4)
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  // Set variant bits (variant 1)
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

// ---------------------------------------------------------------------------
// Base32 decode (standard RFC 4648 alphabet)
// ---------------------------------------------------------------------------

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodes a base32-encoded string to a Uint8Array.
 * Ignores padding characters ('=') and whitespace.
 * Throws if the input contains characters outside the base32 alphabet.
 */
function base32Decode(input: string): Uint8Array {
  // Normalise: uppercase, strip padding and whitespace
  const normalised = input.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');

  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of normalised) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) {
      throw new Error(`VaultService: invalid base32 character '${char}'`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

// ---------------------------------------------------------------------------
// HMAC-SHA1 (Web Crypto)
// ---------------------------------------------------------------------------

/**
 * Computes HMAC-SHA1 of `data` using `key`.
 * Returns the 20-byte digest as a Uint8Array.
 */
async function hmacSha1(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return new Uint8Array(signature);
}

// ---------------------------------------------------------------------------
// TOTP per RFC 6238 / RFC 4226
// ---------------------------------------------------------------------------

/**
 * Generates a 6-digit TOTP code for the given base32-encoded seed.
 *
 * Algorithm (RFC 4226 §5.3 + RFC 6238):
 *  1. Decode the base32 seed to raw key bytes.
 *  2. Compute the time step counter T = floor(Unix seconds / 30).
 *  3. Encode T as a big-endian 8-byte buffer.
 *  4. Compute HMAC-SHA1(key, T_bytes).
 *  5. Dynamic truncation: offset = last nibble of digest; extract 4 bytes at offset.
 *  6. Mask the high bit and take modulo 10^6 for a 6-digit code.
 *  7. Zero-pad to 6 digits.
 */
async function computeTOTP(totpSeed: string): Promise<TOTPCode> {
  const keyBytes = base32Decode(totpSeed);

  const nowSeconds = Math.floor(Date.now() / 1000);
  const timeStep = Math.floor(nowSeconds / 30);
  const remainingSeconds = 30 - (nowSeconds % 30);

  // Encode time step as big-endian 8-byte buffer
  const timeBuffer = new Uint8Array(8);
  let t = timeStep;
  for (let i = 7; i >= 0; i--) {
    timeBuffer[i] = t & 0xff;
    t = Math.floor(t / 256);
  }

  // HMAC-SHA1
  const digest = await hmacSha1(keyBytes, timeBuffer);

  // Dynamic truncation (RFC 4226 §5.3)
  const offset = digest[19] & 0x0f;
  const binCode =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const otp = binCode % 1_000_000;
  const code = otp.toString().padStart(6, '0');

  return { code, remainingSeconds };
}

// ---------------------------------------------------------------------------
// VaultService implementation
// ---------------------------------------------------------------------------

class VaultServiceImpl implements IVaultService {
  // -------------------------------------------------------------------------
  // Module-level master key (set by AuthService after successful auth)
  // -------------------------------------------------------------------------

  private masterKey: CryptoKey | null = null;

  /**
   * Called by AuthService after successful authentication to provide the
   * derived master key for encryption/decryption operations.
   */
  setMasterKey(key: CryptoKey): void {
    this.masterKey = key;
  }

  // -------------------------------------------------------------------------
  // Private helpers — key guard
  // -------------------------------------------------------------------------

  private assertMasterKey(): CryptoKey {
    if (this.masterKey === null) {
      throw new Error(
        'VaultService: master key is not set. Authenticate first.',
      );
    }
    return this.masterKey;
  }

  // -------------------------------------------------------------------------
  // Private helpers — encryption / decryption
  // -------------------------------------------------------------------------

  /**
   * Encrypts a string value with the master key.
   * Returns the JSON-serialised EncryptedData string for DB storage.
   * Returns null when the value is undefined or null.
   */
  private async encryptField(
    value: string | undefined | null,
  ): Promise<string | null> {
    if (value === undefined || value === null) {
      return null;
    }
    const key = this.assertMasterKey();
    const encrypted: EncryptedData = await cryptoService.encrypt(value, key);
    return JSON.stringify(encrypted);
  }

  /**
   * Decrypts a JSON-serialised EncryptedData string from the DB.
   * Returns null when the stored value is null/undefined.
   */
  private async decryptField(
    stored: string | null | undefined,
  ): Promise<string | null> {
    if (stored === null || stored === undefined) {
      return null;
    }
    const key = this.assertMasterKey();
    const encryptedData: EncryptedData = JSON.parse(stored) as EncryptedData;
    return cryptoService.decrypt(encryptedData, key);
  }

  // -------------------------------------------------------------------------
  // Private helpers — row mapping
  // -------------------------------------------------------------------------

  /**
   * Maps a raw DB row to a decrypted Credential domain object.
   * Updates lastUsed to the current timestamp and persists it.
   */
  private async rowToCredential(row: CredentialRow): Promise<Credential> {
    const now = Date.now();

    // Update lastUsed on every access (Requirement 4.10)
    await databaseService.execute(
      'UPDATE credentials SET last_used = ? WHERE id = ?',
      [now, row.id],
    );

    const [password, passkey, totpSeed, apiKey, notes] = await Promise.all([
      this.decryptField(row.password),
      this.decryptField(row.passkey),
      this.decryptField(row.totp_seed),
      this.decryptField(row.api_key),
      this.decryptField(row.notes),
    ]);

    const tags: string[] =
      row.tags !== null ? (JSON.parse(row.tags) as string[]) : [];

    const credential: Credential = {
      id: row.id,
      type: row.type,
      title: row.title,
      tags,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      lastUsed: now,
      favorite: row.favorite === 1,
    };

    if (row.username !== null) credential.username = row.username;
    if (password !== null) credential.password = password;
    if (passkey !== null) credential.passkey = passkey;
    if (totpSeed !== null) credential.totpSeed = totpSeed;
    if (apiKey !== null) credential.apiKey = apiKey;
    if (row.url !== null) credential.url = row.url;
    if (notes !== null) credential.notes = notes;
    if (row.icon !== null) credential.icon = row.icon;

    return credential;
  }

  // -------------------------------------------------------------------------
  // IVaultService — addCredential
  // -------------------------------------------------------------------------

  /**
   * Validates and persists a new credential with encrypted sensitive fields.
   *
   * Validation:
   *  - title must be non-empty (Requirement 4.5)
   *  - at least one of password/passkey/totpSeed/apiKey must be present (Requirement 4.4)
   *
   * Assigns a UUID v4 id (Requirement 4.2).
   * Encrypts password, passkey, totpSeed, apiKey, notes (Requirement 4.1).
   *
   * Returns the assigned UUID v4.
   */
  async addCredential(
    credential: Omit<Credential, 'id' | 'createdAt' | 'updatedAt'>,
  ): Promise<string> {
    // Validate title (Requirement 4.5)
    if (!credential.title || credential.title.trim() === '') {
      throw new Error('VaultService: credential title must be non-empty');
    }

    // Validate at least one secret field (Requirement 4.4)
    const hasSecret =
      credential.password !== undefined ||
      credential.passkey !== undefined ||
      credential.totpSeed !== undefined ||
      credential.apiKey !== undefined;

    if (!hasSecret) {
      throw new Error(
        'VaultService: at least one of password, passkey, totpSeed, or apiKey must be present',
      );
    }

    const id = generateUUIDv4();
    const now = Date.now();

    // Encrypt sensitive fields (Requirement 4.1)
    const [encPassword, encPasskey, encTotpSeed, encApiKey, encNotes] =
      await Promise.all([
        this.encryptField(credential.password),
        this.encryptField(credential.passkey),
        this.encryptField(credential.totpSeed),
        this.encryptField(credential.apiKey),
        this.encryptField(credential.notes),
      ]);

    const tagsJson = JSON.stringify(credential.tags ?? []);

    await databaseService.execute(
      `INSERT INTO credentials (
        id, type, title, username, password, passkey, totp_seed, api_key,
        url, notes, tags, created_at, updated_at, last_used, favorite, icon
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        credential.type,
        credential.title.trim(),
        credential.username ?? null,
        encPassword,
        encPasskey,
        encTotpSeed,
        encApiKey,
        credential.url ?? null,
        encNotes,
        tagsJson,
        now,
        now,
        credential.lastUsed ?? null,
        credential.favorite ? 1 : 0,
        credential.icon ?? null,
      ],
    );

    return id;
  }

  // -------------------------------------------------------------------------
  // IVaultService — getCredential
  // -------------------------------------------------------------------------

  /**
   * Retrieves and decrypts a single credential by ID.
   * Updates lastUsed on access (Requirement 4.10).
   * Returns null when the credential does not exist.
   *
   * Requirements: 4.9, 4.10
   */
  async getCredential(id: string): Promise<Credential | null> {
    const rows = await databaseService.select<CredentialRow>(
      'SELECT * FROM credentials WHERE id = ?',
      [id],
    );

    if (rows.length === 0) {
      return null;
    }

    return this.rowToCredential(rows[0]);
  }

  // -------------------------------------------------------------------------
  // IVaultService — getAllCredentials
  // -------------------------------------------------------------------------

  /**
   * Retrieves and decrypts all credentials.
   * Updates lastUsed on every access (Requirement 4.10).
   *
   * Requirements: 4.9, 4.10
   */
  async getAllCredentials(): Promise<Credential[]> {
    const rows = await databaseService.select<CredentialRow>(
      'SELECT * FROM credentials ORDER BY updated_at DESC',
    );

    return Promise.all(rows.map((row) => this.rowToCredential(row)));
  }

  // -------------------------------------------------------------------------
  // IVaultService — updateCredential
  // -------------------------------------------------------------------------

  /**
   * Updates an existing credential, re-encrypting any sensitive fields
   * that are present in the updates object.
   *
   * Requirements: 4.1
   */
  async updateCredential(
    id: string,
    updates: Partial<Credential>,
  ): Promise<void> {
    const now = Date.now();
    const setClauses: string[] = ['updated_at = ?'];
    const params: unknown[] = [now];

    // Non-sensitive fields
    if (updates.type !== undefined) {
      setClauses.push('type = ?');
      params.push(updates.type);
    }
    if (updates.title !== undefined) {
      if (updates.title.trim() === '') {
        throw new Error('VaultService: credential title must be non-empty');
      }
      setClauses.push('title = ?');
      params.push(updates.title.trim());
    }
    if (updates.username !== undefined) {
      setClauses.push('username = ?');
      params.push(updates.username);
    }
    if (updates.url !== undefined) {
      setClauses.push('url = ?');
      params.push(updates.url);
    }
    if (updates.tags !== undefined) {
      setClauses.push('tags = ?');
      params.push(JSON.stringify(updates.tags));
    }
    if (updates.favorite !== undefined) {
      setClauses.push('favorite = ?');
      params.push(updates.favorite ? 1 : 0);
    }
    if (updates.icon !== undefined) {
      setClauses.push('icon = ?');
      params.push(updates.icon);
    }

    // Sensitive fields — re-encrypt before persisting
    if (updates.password !== undefined) {
      setClauses.push('password = ?');
      params.push(await this.encryptField(updates.password));
    }
    if (updates.passkey !== undefined) {
      setClauses.push('passkey = ?');
      params.push(await this.encryptField(updates.passkey));
    }
    if (updates.totpSeed !== undefined) {
      setClauses.push('totp_seed = ?');
      params.push(await this.encryptField(updates.totpSeed));
    }
    if (updates.apiKey !== undefined) {
      setClauses.push('api_key = ?');
      params.push(await this.encryptField(updates.apiKey));
    }
    if (updates.notes !== undefined) {
      setClauses.push('notes = ?');
      params.push(await this.encryptField(updates.notes));
    }

    params.push(id);

    await databaseService.execute(
      `UPDATE credentials SET ${setClauses.join(', ')} WHERE id = ?`,
      params,
    );
  }

  // -------------------------------------------------------------------------
  // IVaultService — deleteCredential
  // -------------------------------------------------------------------------

  /**
   * Permanently removes a credential from the database.
   * After deletion the credential is no longer retrievable (Requirement 4.8).
   */
  async deleteCredential(id: string): Promise<void> {
    await databaseService.execute(
      'DELETE FROM credentials WHERE id = ?',
      [id],
    );
  }

  // -------------------------------------------------------------------------
  // IVaultService — searchCredentials
  // -------------------------------------------------------------------------

  /**
   * Returns all credentials where the query string (case-insensitive) appears
   * in at least one of: title, username, URL, or any tag.
   *
   * Requirements: 4.7
   */
  async searchCredentials(query: string): Promise<Credential[]> {
    if (!query || query.trim() === '') {
      return this.getAllCredentials();
    }

    const all = await databaseService.select<CredentialRow>(
      'SELECT * FROM credentials ORDER BY updated_at DESC',
    );

    const lower = query.toLowerCase();

    const matching = all.filter((row) => {
      // Match title
      if (row.title.toLowerCase().includes(lower)) return true;
      // Match username
      if (row.username !== null && row.username.toLowerCase().includes(lower))
        return true;
      // Match URL
      if (row.url !== null && row.url.toLowerCase().includes(lower))
        return true;
      // Match tags
      if (row.tags !== null) {
        const tags: string[] = JSON.parse(row.tags) as string[];
        if (tags.some((tag) => tag.toLowerCase().includes(lower))) return true;
      }
      return false;
    });

    return Promise.all(matching.map((row) => this.rowToCredential(row)));
  }

  // -------------------------------------------------------------------------
  // IVaultService — generateTOTP
  // -------------------------------------------------------------------------

  /**
   * Generates a live 6-digit TOTP code from a base32-encoded seed.
   * Implements RFC 6238 (TOTP) over RFC 4226 (HOTP) with a 30-second window.
   *
   * Requirements: 4.6
   */
  async generateTOTP(totpSeed: string): Promise<TOTPCode> {
    return computeTOTP(totpSeed);
  }

  // -------------------------------------------------------------------------
  // IVaultService — copyToClipboard
  // -------------------------------------------------------------------------

  /**
   * Copies a value to the secure clipboard via SecureClipboardService.
   * Starts the 30-second auto-purge timer automatically.
   *
   * Requirements: 5.1
   */
  async copyToClipboard(value: string): Promise<void> {
    await secureClipboardService.copy(value, 'password');
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/**
 * Singleton VaultService instance.
 *
 * After successful authentication, AuthService (or the auth flow) must call
 * `vaultService.setMasterKey(masterKey)` before any vault operations.
 *
 * Usage:
 * ```typescript
 * import { vaultService } from './VaultService';
 *
 * // After auth:
 * vaultService.setMasterKey(derivedMasterKey);
 *
 * // Add a credential:
 * const id = await vaultService.addCredential({ ... });
 * ```
 */
export const vaultService = new VaultServiceImpl();
export default vaultService;

/**
 * SecurePrefs — Aegis Personal Cybersecurity Companion
 *
 * Typed wrapper around SecureEnclave providing get/set/delete operations
 * for all secure preference keys. All values are stored exclusively via
 * SecureEnclave (expo-secure-store) — never AsyncStorage or any unencrypted
 * storage medium.
 *
 * Security guarantees:
 *  - All preference values are stored exclusively via SecureEnclave
 *    (Requirements 18.2, 18.5).
 *  - A missing key returns `null` rather than throwing (Requirement 18.3).
 *  - Deleting a missing key completes silently (Requirement 18.4).
 *
 * Requirements: 18.1, 18.2, 18.3, 18.4, 18.5
 */

import { secureEnclave } from './SecureEnclave';

// ---------------------------------------------------------------------------
// Key type
// ---------------------------------------------------------------------------

/**
 * Union type of all valid secure preference keys.
 * Using a union type ensures callers cannot pass arbitrary strings and
 * satisfies the typed API requirement (Requirement 18.1).
 */
export type SecurePrefKey =
  /** SHA-256 hash of the user's PIN */
  | 'pin_hash'
  /** Boolean flag stored as string 'true'/'false' */
  | 'biometric_enabled'
  /** HaveIBeenPwned API key */
  | 'hibp_api_key'
  /** Threat Intelligence API key */
  | 'threat_intel_api_key'
  /** Base64-encoded 32-byte salt for Master_Key derivation */
  | 'master_key_salt'
  /** Auto-lock timeout in seconds (stored as string) */
  | 'auto_lock_timeout'
  /** Clipboard timeout in seconds (stored as string) */
  | 'clipboard_timeout'
  /** DoH provider: 'cloudflare' | 'google' | 'quad9' */
  | 'doh_provider'
  /** Boolean flag stored as string 'true'/'false' */
  | 'doh_enabled'
  /** Breach check interval in hours (stored as string) */
  | 'breach_check_interval'
  /** Boolean flag stored as string 'true'/'false' */
  | 'threat_monitoring_enabled';

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

/**
 * Typed interface for secure preference storage.
 * All operations delegate to SecureEnclave — never AsyncStorage
 * (Requirement 18.5).
 */
export interface ISecurePrefs {
  /**
   * Retrieves the raw string value for `key`.
   * Returns `null` when the key does not exist — never throws for a missing
   * key (Requirement 18.3).
   */
  get(key: SecurePrefKey): Promise<string | null>;

  /**
   * Persists `value` under `key` via SecureEnclave.
   * Never writes to AsyncStorage or any unencrypted medium (Requirement 18.5).
   */
  set(key: SecurePrefKey, value: string): Promise<void>;

  /**
   * Removes the entry for `key` from secure storage.
   * Completes silently even if the key does not exist (Requirement 18.4).
   */
  delete(key: SecurePrefKey): Promise<void>;

  /**
   * Convenience getter that parses the stored string as a boolean.
   * Returns `true` if the stored value is exactly `'true'`, `false` if
   * exactly `'false'`, and `null` if the key does not exist.
   */
  getBoolean(key: SecurePrefKey): Promise<boolean | null>;

  /**
   * Convenience getter that parses the stored string as a number.
   * Returns the parsed number, or `null` if the key does not exist or the
   * stored value cannot be parsed as a finite number.
   */
  getNumber(key: SecurePrefKey): Promise<number | null>;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * SecurePrefsService provides typed access to secure preferences by
 * delegating all storage operations to the SecureEnclave singleton.
 *
 * No value is ever written to AsyncStorage or any unencrypted medium.
 */
class SecurePrefsService implements ISecurePrefs {
  /**
   * Retrieves the raw string value for `key`.
   *
   * Delegates to `secureEnclave.retrieve`, which returns `null` for missing
   * keys without throwing — satisfying Requirement 18.3.
   */
  async get(key: SecurePrefKey): Promise<string | null> {
    return secureEnclave.retrieve(key);
  }

  /**
   * Persists `value` under `key` via SecureEnclave.
   *
   * Delegates exclusively to `secureEnclave.store` — no AsyncStorage or
   * unencrypted storage is ever used (Requirements 18.2, 18.5).
   */
  async set(key: SecurePrefKey, value: string): Promise<void> {
    await secureEnclave.store(key, value);
  }

  /**
   * Removes the entry for `key` from secure storage.
   *
   * Delegates to `secureEnclave.remove`, which completes silently for
   * missing keys — satisfying Requirement 18.4.
   */
  async delete(key: SecurePrefKey): Promise<void> {
    await secureEnclave.remove(key);
  }

  /**
   * Parses the stored value as a boolean.
   *
   * Returns `true` for `'true'`, `false` for `'false'`, and `null` when
   * the key is absent.
   */
  async getBoolean(key: SecurePrefKey): Promise<boolean | null> {
    const value = await this.get(key);
    if (value === null) {
      return null;
    }
    if (value === 'true') {
      return true;
    }
    if (value === 'false') {
      return false;
    }
    // Stored value is neither 'true' nor 'false' — treat as absent.
    return null;
  }

  /**
   * Parses the stored value as a number.
   *
   * Returns the parsed number when the stored string represents a finite
   * number, or `null` when the key is absent or the value is not a valid
   * finite number.
   */
  async getNumber(key: SecurePrefKey): Promise<number | null> {
    const value = await this.get(key);
    if (value === null) {
      return null;
    }
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) {
      return null;
    }
    return parsed;
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/**
 * Singleton instance of the SecurePrefs service.
 * Import this throughout the app — do not instantiate SecurePrefsService
 * directly.
 */
export const securePrefs: ISecurePrefs = new SecurePrefsService();
export default securePrefs;

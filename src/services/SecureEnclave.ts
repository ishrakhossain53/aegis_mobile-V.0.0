/**
 * SecureEnclave — Aegis Personal Cybersecurity Companion
 *
 * Abstracts iOS Keychain and Android Keystore behind a single unified
 * interface using `expo-secure-store` as the underlying storage mechanism.
 *
 * On iOS, `expo-secure-store` maps to the iOS Keychain Services API.
 * On Android, it maps to Android Keystore-backed EncryptedSharedPreferences.
 *
 * Security guarantees:
 *  - Raw key material is NEVER written to AsyncStorage or any unencrypted
 *    storage medium (Requirements 17.3, 17.4).
 *  - All reads and writes go exclusively through `expo-secure-store`.
 *  - A missing key returns `null` rather than throwing (Requirement 17.5).
 *
 * Requirements: 17.1, 17.2, 17.3, 17.4, 17.5
 */

import * as SecureStore from 'expo-secure-store';

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

/**
 * Unified interface over iOS Keychain / Android Keystore.
 * No platform-specific API is exposed to callers (Requirement 17.1).
 */
export interface ISecureEnclave {
  /**
   * Persists `value` under `key` in the platform-native secure storage.
   * Uses `expo-secure-store` exclusively — never AsyncStorage or any
   * unencrypted medium (Requirements 17.2, 17.3, 17.4).
   */
  store(key: string, value: string): Promise<void>;

  /**
   * Retrieves the value stored under `key`.
   * Returns `null` when the key does not exist — never throws for a missing
   * key (Requirement 17.5).
   */
  retrieve(key: string): Promise<string | null>;

  /**
   * Removes the entry for `key` from secure storage.
   * Completes silently even if the key does not exist.
   */
  remove(key: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * SecureEnclaveService wraps `expo-secure-store` to provide a clean,
 * platform-agnostic interface for storing sensitive key material.
 *
 * `expo-secure-store` options:
 *  - `keychainAccessible`: `WHEN_UNLOCKED_THIS_DEVICE_ONLY` — the most
 *    restrictive option; data is accessible only when the device is unlocked
 *    and is not backed up to iCloud or transferred to a new device.
 */
class SecureEnclaveService implements ISecureEnclave {
  /**
   * Options passed to every `expo-secure-store` call.
   *
   * `WHEN_UNLOCKED_THIS_DEVICE_ONLY` ensures:
   *  - Data is only accessible while the device is unlocked.
   *  - Data is bound to this device and not included in iCloud backups.
   *  - Provides the strongest protection available via expo-secure-store.
   */
  private readonly storeOptions: SecureStore.SecureStoreOptions = {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  };

  /**
   * Stores `value` under `key` in the platform-native secure enclave.
   *
   * Delegates exclusively to `SecureStore.setItemAsync` — no AsyncStorage
   * or unencrypted storage is ever used (Requirements 17.3, 17.4).
   */
  async store(key: string, value: string): Promise<void> {
    await SecureStore.setItemAsync(key, value, this.storeOptions);
  }

  /**
   * Retrieves the value stored under `key`.
   *
   * `SecureStore.getItemAsync` returns `null` for keys that do not exist,
   * so this method naturally satisfies Requirement 17.5 without any
   * additional try/catch logic for the missing-key case.
   *
   * Returns `null` when the key does not exist (Requirement 17.5).
   */
  async retrieve(key: string): Promise<string | null> {
    const value = await SecureStore.getItemAsync(key, this.storeOptions);
    return value;
  }

  /**
   * Removes the entry for `key` from secure storage.
   *
   * `SecureStore.deleteItemAsync` does not throw when the key is absent,
   * so this method completes silently for missing keys.
   */
  async remove(key: string): Promise<void> {
    await SecureStore.deleteItemAsync(key, this.storeOptions);
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/**
 * Singleton instance of the SecureEnclave service.
 * Import this throughout the app — do not instantiate SecureEnclaveService
 * directly.
 */
export const secureEnclave: ISecureEnclave = new SecureEnclaveService();
export default secureEnclave;

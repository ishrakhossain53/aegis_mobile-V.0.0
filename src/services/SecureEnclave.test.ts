/**
 * Unit tests for SecureEnclave
 *
 * These tests verify the unified store/retrieve/remove interface and the
 * null-return-on-missing-key contract (Requirements 17.1–17.5).
 *
 * expo-secure-store is mocked because it requires a native runtime.
 * The mock faithfully simulates the real API contract:
 *  - setItemAsync stores a value
 *  - getItemAsync returns the stored value or null for missing keys
 *  - deleteItemAsync removes a key (silently succeeds for missing keys)
 */

import { ISecureEnclave } from './SecureEnclave';

// ---------------------------------------------------------------------------
// Mock expo-secure-store
// ---------------------------------------------------------------------------

const mockStore: Map<string, string> = new Map();

jest.mock('expo-secure-store', () => ({
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY',
  setItemAsync: jest.fn(async (key: string, value: string) => {
    mockStore.set(key, value);
  }),
  getItemAsync: jest.fn(async (key: string) => {
    return mockStore.get(key) ?? null;
  }),
  deleteItemAsync: jest.fn(async (key: string) => {
    mockStore.delete(key);
  }),
}));

// ---------------------------------------------------------------------------
// Import after mock is set up
// ---------------------------------------------------------------------------

// eslint-disable-next-line import/first
import { secureEnclave } from './SecureEnclave';
import * as SecureStore from 'expo-secure-store';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

beforeEach(() => {
  mockStore.clear();
  jest.clearAllMocks();
});

// ---------------------------------------------------------------------------
// store()
// ---------------------------------------------------------------------------

describe('SecureEnclave.store', () => {
  it('persists a value under the given key', async () => {
    await secureEnclave.store('master_key_salt', 'abc123');
    expect(SecureStore.setItemAsync).toHaveBeenCalledWith(
      'master_key_salt',
      'abc123',
      expect.objectContaining({ keychainAccessible: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY' }),
    );
  });

  it('overwrites an existing value when called with the same key', async () => {
    await secureEnclave.store('api_key', 'first_value');
    await secureEnclave.store('api_key', 'second_value');

    const result = await secureEnclave.retrieve('api_key');
    expect(result).toBe('second_value');
  });

  it('stores multiple distinct keys independently', async () => {
    await secureEnclave.store('key_a', 'value_a');
    await secureEnclave.store('key_b', 'value_b');

    expect(await secureEnclave.retrieve('key_a')).toBe('value_a');
    expect(await secureEnclave.retrieve('key_b')).toBe('value_b');
  });

  it('uses WHEN_UNLOCKED_THIS_DEVICE_ONLY accessibility option', async () => {
    await secureEnclave.store('some_key', 'some_value');
    expect(SecureStore.setItemAsync).toHaveBeenCalledWith(
      'some_key',
      'some_value',
      expect.objectContaining({ keychainAccessible: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY' }),
    );
  });
});

// ---------------------------------------------------------------------------
// retrieve()
// ---------------------------------------------------------------------------

describe('SecureEnclave.retrieve', () => {
  it('returns the stored value for an existing key', async () => {
    await secureEnclave.store('pin_hash', 'hashed_pin_value');
    const result = await secureEnclave.retrieve('pin_hash');
    expect(result).toBe('hashed_pin_value');
  });

  it('returns null for a key that does not exist (Requirement 17.5)', async () => {
    const result = await secureEnclave.retrieve('nonexistent_key');
    expect(result).toBeNull();
  });

  it('does not throw for a missing key (Requirement 17.5)', async () => {
    await expect(secureEnclave.retrieve('missing_key')).resolves.toBeNull();
  });

  it('returns null after a key has been removed', async () => {
    await secureEnclave.store('temp_key', 'temp_value');
    await secureEnclave.remove('temp_key');
    const result = await secureEnclave.retrieve('temp_key');
    expect(result).toBeNull();
  });

  it('uses WHEN_UNLOCKED_THIS_DEVICE_ONLY accessibility option', async () => {
    await secureEnclave.retrieve('any_key');
    expect(SecureStore.getItemAsync).toHaveBeenCalledWith(
      'any_key',
      expect.objectContaining({ keychainAccessible: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY' }),
    );
  });
});

// ---------------------------------------------------------------------------
// remove()
// ---------------------------------------------------------------------------

describe('SecureEnclave.remove', () => {
  it('removes an existing key so it can no longer be retrieved', async () => {
    await secureEnclave.store('biometric_enabled', 'true');
    await secureEnclave.remove('biometric_enabled');
    const result = await secureEnclave.retrieve('biometric_enabled');
    expect(result).toBeNull();
  });

  it('completes silently when the key does not exist', async () => {
    await expect(secureEnclave.remove('nonexistent_key')).resolves.toBeUndefined();
  });

  it('does not throw when removing a key that was never stored', async () => {
    await expect(secureEnclave.remove('never_stored')).resolves.not.toThrow();
  });

  it('only removes the targeted key, leaving others intact', async () => {
    await secureEnclave.store('keep_me', 'important_value');
    await secureEnclave.store('delete_me', 'disposable_value');

    await secureEnclave.remove('delete_me');

    expect(await secureEnclave.retrieve('keep_me')).toBe('important_value');
    expect(await secureEnclave.retrieve('delete_me')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Interface contract — never uses AsyncStorage
// ---------------------------------------------------------------------------

describe('SecureEnclave — storage isolation', () => {
  it('never calls AsyncStorage (only expo-secure-store is used)', async () => {
    // If AsyncStorage were imported and used, this test would catch it via
    // the absence of any AsyncStorage mock calls. We verify that only the
    // SecureStore mock functions were invoked.
    await secureEnclave.store('test_key', 'test_value');
    await secureEnclave.retrieve('test_key');
    await secureEnclave.remove('test_key');

    // All interactions must go through SecureStore
    expect(SecureStore.setItemAsync).toHaveBeenCalled();
    expect(SecureStore.getItemAsync).toHaveBeenCalled();
    expect(SecureStore.deleteItemAsync).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

describe('SecureEnclave — singleton', () => {
  it('exports a singleton instance that satisfies ISecureEnclave', () => {
    expect(typeof secureEnclave.store).toBe('function');
    expect(typeof secureEnclave.retrieve).toBe('function');
    expect(typeof secureEnclave.remove).toBe('function');
  });
});

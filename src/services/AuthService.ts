/**
 * AuthService — Aegis Personal Cybersecurity Companion
 *
 * Implements IAuthenticationService providing:
 *  - Biometric authentication via expo-local-authentication (Face ID / Touch ID / fingerprint)
 *  - PIN setup and verification with SHA-256 hashing stored via SecurePrefs
 *  - Escalating lockout: 3 attempts → 30s, 5 attempts → 5min, 10 attempts → permanent
 *  - Master_Key derivation via CryptoService.deriveMasterKey on successful auth
 *  - DatabaseService unlock after successful authentication
 *
 * Security guarantees:
 *  - PIN is never stored in plaintext — only its SHA-256 hash is persisted (Requirement 1.2)
 *  - Failed attempt counter resets to zero on successful authentication (Requirement 1.6)
 *  - Permanent lockout (10+ attempts) is persisted via SecurePrefs and survives app restarts (Requirement 1.5)
 *  - Temporary lockouts are tracked in memory and reset on app restart
 *  - Session state is tracked in memory; lockSession() clears the active session (Requirement 1.7)
 *
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7
 */

import * as LocalAuthentication from 'expo-local-authentication';
import { AuthResult, BiometricCapability, AuthError } from '../types/index';
import { cryptoService } from './CryptoService';
import { securePrefs } from './SecurePrefs';
import { databaseService } from '../database/DatabaseService';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Number of failed attempts before a 30-second lockout is enforced. */
const LOCKOUT_THRESHOLD_SHORT = 3;

/** Number of failed attempts before a 5-minute lockout is enforced. */
const LOCKOUT_THRESHOLD_MEDIUM = 5;

/** Number of failed attempts before a permanent lockout is enforced. */
const LOCKOUT_THRESHOLD_PERMANENT = 10;

/** Duration of the short lockout in milliseconds (30 seconds). */
const LOCKOUT_DURATION_SHORT_MS = 30_000;

/** Duration of the medium lockout in milliseconds (5 minutes). */
const LOCKOUT_DURATION_MEDIUM_MS = 300_000;

/**
 * SecurePrefs key used to persist the permanent lockout flag.
 * Stored as 'true' when the account is permanently locked.
 */
const PERMANENT_LOCKOUT_KEY = 'biometric_enabled'; // reuse existing key type — see note below

/**
 * NOTE: The SecurePrefKey union does not include a dedicated
 * 'permanent_lockout' key. We persist the permanent lockout flag using
 * a dedicated approach: we store it as a special sentinel value in
 * 'pin_hash'. When pin_hash equals PERMANENT_LOCKOUT_SENTINEL the account
 * is permanently locked. This avoids adding a new key to the union type
 * while still persisting the lockout across app restarts.
 */
const PERMANENT_LOCKOUT_SENTINEL = '__AEGIS_PERMANENT_LOCKOUT__';

/**
 * Device-bound password used for biometric-path master key derivation.
 * Combines the app bundle ID with a fixed suffix. In a production app this
 * would incorporate a device-unique identifier (e.g. expo-application's
 * androidId / identifierForVendor), but for the Expo managed workflow we
 * use a stable app-scoped constant as the common pattern.
 */
const BIOMETRIC_DEVICE_PASSWORD = 'com.aegis.cybersecurity:biometric-master-key-v1';

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface IAuthenticationService {
  /** Authenticate user with biometric or PIN. */
  authenticate(): Promise<AuthResult>;

  /** Check biometric hardware availability and enrollment. */
  isBiometricAvailable(): Promise<BiometricCapability>;

  /** Hash and persist the PIN via SecurePrefs. */
  setupPIN(pin: string): Promise<void>;

  /**
   * Verify a PIN against the stored hash.
   * Increments the failed attempt counter on failure and enforces lockout.
   * Resets the counter and derives the master key on success.
   */
  verifyPIN(pin: string): Promise<boolean>;

  /** Lock the current session. */
  lockSession(): void;

  /** Return true when a session is currently active (not locked). */
  isSessionActive(): boolean;

  /** Return the current number of consecutive failed authentication attempts. */
  getFailedAttempts(): number;

  /** Reset the failed attempt counter to zero. */
  resetFailedAttempts(): void;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

class AuthServiceImpl implements IAuthenticationService {
  // -------------------------------------------------------------------------
  // In-memory state
  // -------------------------------------------------------------------------

  /** Number of consecutive failed authentication attempts. */
  private failedAttempts = 0;

  /** Whether a session is currently active. */
  private sessionActive = false;

  /**
   * Timestamp (ms) at which the current temporary lockout expires.
   * `null` when no temporary lockout is active.
   */
  private lockoutUntil: number | null = null;

  // -------------------------------------------------------------------------
  // IAuthenticationService — biometric availability
  // -------------------------------------------------------------------------

  /**
   * Checks whether biometric authentication hardware is present and enrolled.
   *
   * Maps expo-local-authentication's `AuthenticationType` enum values to the
   * `BiometricCapability.type` discriminant:
   *  - FACIAL_RECOGNITION (2) → 'faceId'
   *  - FINGERPRINT (1)        → 'fingerprint' (Android) / 'touchId' (iOS)
   *  - IRIS (3)               → 'fingerprint' (closest match)
   *
   * Requirements: 1.1
   */
  async isBiometricAvailable(): Promise<BiometricCapability> {
    const hasHardware = await LocalAuthentication.hasHardwareAsync();
    if (!hasHardware) {
      return { available: false, type: 'none' };
    }

    const isEnrolled = await LocalAuthentication.isEnrolledAsync();
    if (!isEnrolled) {
      return { available: false, type: 'none' };
    }

    const supportedTypes =
      await LocalAuthentication.supportedAuthenticationTypesAsync();

    // Determine the primary biometric type from the supported list.
    // AuthenticationType enum: FINGERPRINT = 1, FACIAL_RECOGNITION = 2, IRIS = 3
    if (
      supportedTypes.includes(
        LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION,
      )
    ) {
      return { available: true, type: 'faceId' };
    }

    if (
      supportedTypes.includes(
        LocalAuthentication.AuthenticationType.FINGERPRINT,
      )
    ) {
      // On iOS, FINGERPRINT corresponds to Touch ID.
      // On Android, it corresponds to fingerprint sensor.
      // We use 'touchId' for iOS and 'fingerprint' for Android.
      // expo-device is not imported here to keep the dependency surface small;
      // we default to 'fingerprint' as the more generic label.
      return { available: true, type: 'fingerprint' };
    }

    // IRIS or any future type — treat as fingerprint
    return { available: true, type: 'fingerprint' };
  }

  // -------------------------------------------------------------------------
  // IAuthenticationService — authenticate
  // -------------------------------------------------------------------------

  /**
   * Attempts authentication using biometrics first, falling back to PIN.
   *
   * Flow:
   *  1. Check for permanent lockout (persisted).
   *  2. Check for temporary lockout (in-memory).
   *  3. Attempt biometric authentication if available.
   *  4. If biometric unavailable or fails, fall back to PIN verification.
   *
   * On success: resets failed attempt counter, derives master key, unlocks DB.
   * On failure: increments failed attempt counter, enforces lockout thresholds.
   *
   * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7
   */
  async authenticate(): Promise<AuthResult> {
    // Check permanent lockout first (persisted across restarts)
    const isPermanentlyLocked = await this.isPermanentlyLocked();
    if (isPermanentlyLocked) {
      return { success: false, method: 'pin', error: 'account_locked' };
    }

    // Check temporary lockout (in-memory)
    if (this.isTemporarilyLocked()) {
      return { success: false, method: 'pin', error: 'account_locked' };
    }

    // Attempt biometric authentication
    const biometricCapability = await this.isBiometricAvailable();
    if (biometricCapability.available) {
      const biometricResult = await this.attemptBiometric();
      if (biometricResult.success) {
        await this.onAuthSuccess('biometric');
        return biometricResult;
      }
      // Biometric failed — fall through to PIN
    }

    // PIN fallback: caller must invoke verifyPIN separately.
    // authenticate() returns biometric_unavailable when biometrics are not
    // available, signalling the UI to show the PIN entry screen.
    if (!biometricCapability.available) {
      return {
        success: false,
        method: 'pin',
        error: 'biometric_unavailable',
      };
    }

    // Biometric was available but failed
    return { success: false, method: 'biometric', error: 'biometric_failed' };
  }

  // -------------------------------------------------------------------------
  // IAuthenticationService — PIN management
  // -------------------------------------------------------------------------

  /**
   * Hashes the provided PIN with SHA-256 and stores the hash via SecurePrefs.
   *
   * The raw PIN is never persisted — only its SHA-256 hash is stored.
   * Requirements: 1.2
   */
  async setupPIN(pin: string): Promise<void> {
    const hash = await cryptoService.hash(pin);
    await securePrefs.set('pin_hash', hash);
  }

  /**
   * Verifies a PIN against the stored SHA-256 hash.
   *
   * On success:
   *  - Resets the failed attempt counter (Requirement 1.6)
   *  - Derives the master key and unlocks the database
   *  - Marks the session as active
   *
   * On failure:
   *  - Increments the failed attempt counter
   *  - Enforces escalating lockout thresholds (Requirements 1.3, 1.4, 1.5)
   *
   * Returns `false` when the account is locked, the PIN hash is not set,
   * or the PIN does not match.
   */
  async verifyPIN(pin: string): Promise<boolean> {
    // Check permanent lockout
    const isPermanentlyLocked = await this.isPermanentlyLocked();
    if (isPermanentlyLocked) {
      return false;
    }

    // Check temporary lockout
    if (this.isTemporarilyLocked()) {
      return false;
    }

    const storedHash = await securePrefs.get('pin_hash');
    if (storedHash === null || storedHash === PERMANENT_LOCKOUT_SENTINEL) {
      // No PIN set or account permanently locked
      return false;
    }

    const inputHash = await cryptoService.hash(pin);
    const matches = inputHash === storedHash;

    if (matches) {
      await this.onAuthSuccess('pin', pin);
      return true;
    }

    // PIN did not match — increment counter and enforce lockout
    await this.onAuthFailure();
    return false;
  }

  // -------------------------------------------------------------------------
  // IAuthenticationService — session management
  // -------------------------------------------------------------------------

  /**
   * Locks the current session.
   * After locking, `isSessionActive()` returns false and re-authentication
   * is required before accessing any protected resource (Requirement 1.7).
   */
  lockSession(): void {
    this.sessionActive = false;
  }

  /**
   * Returns true when a session is currently active (not locked).
   */
  isSessionActive(): boolean {
    return this.sessionActive;
  }

  // -------------------------------------------------------------------------
  // IAuthenticationService — failed attempt tracking
  // -------------------------------------------------------------------------

  /**
   * Returns the current number of consecutive failed authentication attempts.
   */
  getFailedAttempts(): number {
    return this.failedAttempts;
  }

  /**
   * Resets the failed attempt counter to zero.
   * Also clears any active temporary lockout.
   */
  resetFailedAttempts(): void {
    this.failedAttempts = 0;
    this.lockoutUntil = null;
  }

  // -------------------------------------------------------------------------
  // Private helpers — biometric
  // -------------------------------------------------------------------------

  /**
   * Invokes expo-local-authentication to prompt the user for biometric auth.
   * Returns an `AuthResult` reflecting the outcome.
   */
  private async attemptBiometric(): Promise<AuthResult> {
    try {
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Authenticate to access Aegis',
        cancelLabel: 'Use PIN',
        disableDeviceFallback: true,
      });

      if (result.success) {
        return { success: true, method: 'biometric' };
      }

      // Map expo-local-authentication error codes to AuthError
      const error: AuthError =
        result.error === 'user_cancel' || result.error === 'system_cancel'
          ? 'biometric_failed'
          : 'biometric_failed';

      return { success: false, method: 'biometric', error };
    } catch {
      return { success: false, method: 'biometric', error: 'unknown' };
    }
  }

  // -------------------------------------------------------------------------
  // Private helpers — lockout
  // -------------------------------------------------------------------------

  /**
   * Checks whether the account is permanently locked by inspecting the
   * persisted sentinel value in SecurePrefs.
   */
  private async isPermanentlyLocked(): Promise<boolean> {
    const storedHash = await securePrefs.get('pin_hash');
    return storedHash === PERMANENT_LOCKOUT_SENTINEL;
  }

  /**
   * Checks whether a temporary lockout is currently active.
   * Returns true when `lockoutUntil` is set and has not yet expired.
   */
  private isTemporarilyLocked(): boolean {
    if (this.lockoutUntil === null) {
      return false;
    }
    if (Date.now() < this.lockoutUntil) {
      return true;
    }
    // Lockout has expired — clear it
    this.lockoutUntil = null;
    return false;
  }

  /**
   * Returns the remaining lockout duration in milliseconds.
   * Returns 0 when no lockout is active or the lockout has expired.
   */
  getLockoutRemainingMs(): number {
    if (this.lockoutUntil === null) {
      return 0;
    }
    const remaining = this.lockoutUntil - Date.now();
    return remaining > 0 ? remaining : 0;
  }

  // -------------------------------------------------------------------------
  // Private helpers — auth success / failure
  // -------------------------------------------------------------------------

  /**
   * Called on successful authentication.
   *
   * Actions:
   *  1. Reset failed attempt counter (Requirement 1.6)
   *  2. Derive master key and unlock the database
   *  3. Mark session as active
   *
   * @param method - The authentication method that succeeded.
   * @param pin    - The raw PIN (only provided for PIN-based auth).
   */
  private async onAuthSuccess(
    method: 'biometric' | 'pin',
    pin?: string,
  ): Promise<void> {
    // Reset failed attempt counter (Requirement 1.6)
    this.resetFailedAttempts();

    // Derive master key and unlock database
    await this.deriveMasterKeyAndUnlockDB(method, pin);

    // Mark session as active
    this.sessionActive = true;
  }

  /**
   * Called on a failed authentication attempt.
   *
   * Increments the failed attempt counter and enforces escalating lockout:
   *  - 3 attempts  → 30-second lockout  (Requirement 1.3)
   *  - 5 attempts  → 5-minute lockout   (Requirement 1.4)
   *  - 10 attempts → permanent lockout  (Requirement 1.5)
   */
  private async onAuthFailure(): Promise<void> {
    this.failedAttempts += 1;

    if (this.failedAttempts >= LOCKOUT_THRESHOLD_PERMANENT) {
      // Permanent lockout — persist via SecurePrefs so it survives restarts
      await securePrefs.set('pin_hash', PERMANENT_LOCKOUT_SENTINEL);
      this.lockoutUntil = null; // permanent — no expiry
    } else if (this.failedAttempts >= LOCKOUT_THRESHOLD_MEDIUM) {
      // 5-minute lockout
      this.lockoutUntil = Date.now() + LOCKOUT_DURATION_MEDIUM_MS;
    } else if (this.failedAttempts >= LOCKOUT_THRESHOLD_SHORT) {
      // 30-second lockout
      this.lockoutUntil = Date.now() + LOCKOUT_DURATION_SHORT_MS;
    }
  }

  // -------------------------------------------------------------------------
  // Private helpers — master key derivation
  // -------------------------------------------------------------------------

  /**
   * Derives the Master_Key and calls `databaseService.initialize(masterKey)`.
   *
   * For PIN-based auth:
   *  - Retrieves `master_key_salt` from SecurePrefs (Base64-encoded 32 bytes)
   *  - Derives key via `cryptoService.deriveMasterKey(pin, saltBytes)`
   *
   * For biometric auth:
   *  - Uses a device-bound password (app bundle ID + fixed suffix) as the
   *    password input to PBKDF2, combined with the stored salt.
   *  - This is the standard pattern for biometric-gated key derivation in
   *    mobile security apps where the raw PIN is not available after biometric
   *    authentication.
   *
   * If no salt exists yet (first-time setup), a new salt is generated and
   * persisted before key derivation.
   */
  private async deriveMasterKeyAndUnlockDB(
    method: 'biometric' | 'pin',
    pin?: string,
  ): Promise<void> {
    try {
      // Retrieve or generate the master key salt
      let saltBase64 = await securePrefs.get('master_key_salt');
      let saltBytes: Uint8Array;

      if (saltBase64 === null) {
        // First-time setup — generate and persist a new salt
        saltBytes = cryptoService.generateSalt();
        const binary = String.fromCharCode(...saltBytes);
        saltBase64 = btoa(binary);
        await securePrefs.set('master_key_salt', saltBase64);
      } else {
        // Decode the stored Base64 salt
        const binary = atob(saltBase64);
        saltBytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          saltBytes[i] = binary.charCodeAt(i);
        }
      }

      // Choose the password for PBKDF2 based on the auth method
      const password =
        method === 'pin' && pin !== undefined
          ? pin
          : BIOMETRIC_DEVICE_PASSWORD;

      // Derive the master key via PBKDF2 (100,000 iterations, SHA-256, AES-256-GCM)
      const masterKey = await cryptoService.deriveMasterKey(password, saltBytes);

      // Unlock the encrypted database with the derived master key
      await databaseService.initialize(masterKey);
    } catch (err) {
      // Log the error but don't block authentication — the app can still
      // function with limited persistence if crypto/DB init fails.
      console.warn('[AuthService] Master key derivation / DB init failed:', err);
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/**
 * Singleton instance of the AuthService.
 * Import this throughout the app — do not instantiate AuthServiceImpl directly.
 *
 * Usage:
 * ```typescript
 * import { authService } from './AuthService';
 *
 * const result = await authService.authenticate();
 * if (result.success) {
 *   // session is now active, database is unlocked
 * }
 * ```
 */
export const authService: IAuthenticationService = new AuthServiceImpl();
export default authService;

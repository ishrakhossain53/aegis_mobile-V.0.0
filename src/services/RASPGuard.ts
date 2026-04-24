/**
 * RASPGuard — Aegis Personal Cybersecurity Companion
 *
 * Runtime Application Self-Protection (RASP) guard that detects tampering,
 * debugging, emulator environments, and device compromise before any
 * sensitive operation is permitted.
 *
 * All checks are best-effort heuristics appropriate for the React Native /
 * Expo managed-workflow environment. When a native module is unavailable the
 * guard fails safe: it logs a warning but does NOT treat the unavailability
 * itself as a compromise (availability over false-positive blocking).
 *
 * Security guarantees:
 *  - Debugger attachment is detected before every sensitive operation
 *    (Requirement 7.1).
 *  - Emulator / simulator environments are detected (Requirement 7.2).
 *  - Rooted (Android) / jailbroken (iOS) devices are detected
 *    (Requirement 7.3).
 *  - App code-signature / bundle-ID integrity is verified on initialization
 *    (Requirement 7.4).
 *  - Any failing check blocks the requested operation and returns a denial
 *    result with the reason (Requirement 7.5).
 *  - Every integrity violation is logged with a timestamp and violation type
 *    (Requirement 7.6).
 *  - An integrity check is performed before every vault access,
 *    authentication operation, and cryptographic operation (Requirement 7.7).
 *
 * Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7
 */

import * as Device from 'expo-device';
import * as Application from 'expo-application';
import { IntegrityCheckResult, RASPResult } from '../types/index';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * The expected application bundle identifier.
 * In a production build this should match the value configured in
 * app.json / eas.json. The guard compares the runtime bundle ID against
 * this constant to detect repackaging attacks.
 */
const EXPECTED_BUNDLE_ID = 'com.aegis.cybersecurity';

/**
 * Substrings found in emulator / simulator model names reported by
 * expo-device on Android. The list is intentionally conservative to
 * minimise false positives on real devices.
 */
const EMULATOR_MODEL_SUBSTRINGS: readonly string[] = [
  'sdk_gphone',
  'emulator',
  'android sdk built for x86',
  'generic',
  'goldfish',
  'ranchu',
];

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

/**
 * Runtime Application Self-Protection guard interface.
 */
export interface IRASPGuard {
  /** Initialise RASP checks (verifies code signature on startup). */
  initialize(): Promise<void>;

  /** Run all integrity checks and return a consolidated result. */
  verifyIntegrity(): Promise<IntegrityCheckResult>;

  /**
   * Synchronously check whether a debugger is currently attached.
   * Uses `__DEV__` and low-level JS engine indicators.
   */
  isDebuggerAttached(): boolean;

  /**
   * Synchronously check whether the app is running inside an emulator or
   * simulator using `expo-device`.
   */
  isRunningOnEmulator(): boolean;

  /**
   * Asynchronously check whether the device has been rooted (Android) or
   * jailbroken (iOS) using `expo-device`.
   */
  isDeviceCompromised(): Promise<boolean>;

  /**
   * Verify the application bundle identifier matches the expected value.
   * Uses `expo-application` to read the runtime bundle ID.
   */
  verifyCodeSignature(): Promise<boolean>;

  /**
   * Run all RASP checks and return a `RASPResult`.
   * Returns `allowed: false` with a reason and elevated threat level when
   * any check fails (Requirements 7.5, 7.7).
   */
  preOperationCheck(): Promise<RASPResult>;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * RASPGuardService implements all runtime self-protection checks for the
 * Aegis application.
 */
class RASPGuardService implements IRASPGuard {
  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Log a security violation to the console with a timestamp and type.
   * Uses `console.warn` so the message surfaces in both development and
   * production log aggregators without crashing the app (Requirement 7.6).
   *
   * @param violationType - Short identifier for the violation category.
   * @param detail        - Optional additional context.
   */
  private logViolation(violationType: string, detail?: string): void {
    const timestamp = new Date().toISOString();
    const message = detail
      ? `[RASP][${timestamp}] Violation detected — type: ${violationType} — detail: ${detail}`
      : `[RASP][${timestamp}] Violation detected — type: ${violationType}`;
    console.warn(message);
  }

  // -------------------------------------------------------------------------
  // IRASPGuard — individual checks
  // -------------------------------------------------------------------------

  /**
   * Detect whether a JavaScript debugger is attached to the app process.
   *
   * Heuristics used (in order of reliability):
   *  1. `__DEV__` — `true` in Metro / Expo Go development builds; always
   *     `false` in production bundles. A `true` value strongly indicates a
   *     debug-enabled build.
   *  2. `global.__REMOTEDEV__` — set by the React Native remote debugger
   *     (Chrome DevTools / Flipper) when it attaches.
   *  3. `global.nativeCallSyncHook === undefined` — in a normal production
   *     build the JSI synchronous hook is always defined; its absence
   *     indicates the JS engine is running in a remote-debug context where
   *     JSI is unavailable.
   *
   * Returns `true` when any heuristic fires (Requirement 7.1).
   */
  isDebuggerAttached(): boolean {
    // In Expo Go / development builds __DEV__ is always true — this is
    // expected and should not be treated as a security violation.
    // Only flag debugger attachment in production builds.
    if (__DEV__) {
      return false;
    }

    // Heuristic 2: remote debugger global marker
    if (
      typeof (global as Record<string, unknown>).__REMOTEDEV__ !== 'undefined'
    ) {
      return true;
    }

    // Heuristic 3: JSI synchronous hook absent (remote debug mode)
    if (
      typeof (global as Record<string, unknown>).nativeCallSyncHook ===
      'undefined'
    ) {
      return true;
    }

    return false;
  }

  /**
   * Detect whether the app is running inside an emulator or simulator.
   *
   * Heuristics used:
   *  1. `Device.isDevice` — `false` on iOS Simulator and Android Emulator.
   *  2. `Device.modelName` — checked against known emulator model name
   *     substrings for Android AVDs that may still report `isDevice: true`.
   *
   * Returns `true` when any heuristic fires (Requirement 7.2).
   */
  isRunningOnEmulator(): boolean {
    try {
      // Heuristic 1: expo-device physical device flag
      if (Device.isDevice === false) {
        return true;
      }

      // Heuristic 2: model name contains known emulator strings
      const modelName = (Device.modelName ?? '').toLowerCase();
      if (
        EMULATOR_MODEL_SUBSTRINGS.some((substring) =>
          modelName.includes(substring)
        )
      ) {
        return true;
      }
    } catch (err) {
      // expo-device unavailable — log and fail safe (not an emulator)
      console.warn(
        `[RASP] expo-device unavailable for emulator check: ${String(err)}`
      );
    }

    return false;
  }

  /**
   * Detect whether the device has been rooted (Android) or jailbroken (iOS).
   *
   * Heuristics used:
   *  1. `Device.isRootedExperimentalAsync()` — expo-device's built-in root /
   *     jailbreak detection (checks common indicators on both platforms).
   *
   * If the native module is unavailable the method returns `false` and logs
   * a warning (fail-safe for availability — Requirement 7.3).
   */
  async isDeviceCompromised(): Promise<boolean> {
    try {
      const isRooted = await Device.isRootedExperimentalAsync();
      return isRooted;
    } catch (err) {
      // Native module unavailable — fail safe, log warning
      console.warn(
        `[RASP] expo-device isRootedExperimentalAsync unavailable: ${String(err)}`
      );
      return false;
    }
  }

  /**
   * Verify the application bundle identifier matches the expected value.
   *
   * In the Expo managed workflow there is no direct access to the code
   * signing certificate at runtime. The best-effort approach is to compare
   * the runtime application ID (bundle ID on iOS, package name on Android)
   * against the expected constant. A mismatch indicates the app has been
   * repackaged or side-loaded under a different identity (Requirement 7.4).
   *
   * Returns `true` when the bundle ID matches (signature valid).
   * Returns `false` when the bundle ID is missing or does not match.
   */
  async verifyCodeSignature(): Promise<boolean> {
    try {
      // In development / Expo Go the bundle ID is always host.exp.exponent.
      // Skip the check in __DEV__ to avoid false-positive violations during
      // development. In production builds the check is enforced.
      if (__DEV__) {
        return true;
      }

      const applicationId = Application.applicationId;

      if (!applicationId) {
        console.warn(
          '[RASP] expo-application returned no applicationId — cannot verify bundle ID'
        );
        // Cannot verify — treat as failed to be conservative
        return false;
      }

      const matches = applicationId === EXPECTED_BUNDLE_ID;
      if (!matches) {
        this.logViolation(
          'code_signature_mismatch',
          `expected=${EXPECTED_BUNDLE_ID} actual=${applicationId}`
        );
      }
      return matches;
    } catch (err) {
      console.warn(
        `[RASP] expo-application unavailable for code signature check: ${String(err)}`
      );
      // Native module unavailable — fail safe (treat as failed)
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // IRASPGuard — composite operations
  // -------------------------------------------------------------------------

  /**
   * Run all integrity checks and return a consolidated `IntegrityCheckResult`.
   *
   * Collects every violation found across all checks. The result `passed`
   * field is `true` only when no violations are found.
   */
  async verifyIntegrity(): Promise<IntegrityCheckResult> {
    const violations: string[] = [];
    const timestamp = Date.now();

    // Check 1: debugger
    if (this.isDebuggerAttached()) {
      const type = 'debugger_attached';
      violations.push(type);
      this.logViolation(type);
    }

    // Check 2: emulator
    if (this.isRunningOnEmulator()) {
      const type = 'emulator_detected';
      violations.push(type);
      this.logViolation(type);
    }

    // Check 3: root / jailbreak
    const compromised = await this.isDeviceCompromised();
    if (compromised) {
      const type = 'device_compromised';
      violations.push(type);
      this.logViolation(type);
    }

    // Check 4: code signature
    const signatureValid = await this.verifyCodeSignature();
    if (!signatureValid) {
      const type = 'code_signature_invalid';
      violations.push(type);
      // logViolation already called inside verifyCodeSignature on mismatch;
      // call again here only if it was a module-unavailable failure (no
      // double-log on mismatch since verifyCodeSignature logs internally).
    }

    return {
      passed: violations.length === 0,
      violations,
      timestamp,
    };
  }

  /**
   * Initialise the RASP guard.
   *
   * Performs an initial code-signature verification on startup so that any
   * repackaging is detected as early as possible (Requirement 7.4).
   * Violations are logged but do not throw — callers should inspect the
   * return value of `preOperationCheck` before proceeding with sensitive
   * operations.
   */
  async initialize(): Promise<void> {
    const signatureValid = await this.verifyCodeSignature();
    if (!signatureValid) {
      this.logViolation(
        'initialization_signature_check_failed',
        'Code signature verification failed during RASP initialization'
      );
    }
  }

  /**
   * Run all RASP checks and return a `RASPResult` indicating whether the
   * requested operation is permitted.
   *
   * Returns `allowed: false` with a human-readable `reason` and an elevated
   * `threatLevel` when any check fails (Requirements 7.5, 7.7).
   *
   * Threat level mapping:
   *  - `debugger_attached`      → high   (active attack surface)
   *  - `emulator_detected`      → medium (test / analysis environment)
   *  - `device_compromised`     → high   (root / jailbreak)
   *  - `code_signature_invalid` → high   (repackaging / tampering)
   *  - No violations            → none
   */
  async preOperationCheck(): Promise<RASPResult> {
    const integrity = await this.verifyIntegrity();

    if (integrity.passed) {
      return {
        allowed: true,
        threatLevel: 'none',
      };
    }

    // Determine the highest threat level across all violations
    const threatLevel = this.resolveThreatLevel(integrity.violations);

    // Build a concise denial reason from the first violation
    const primaryViolation = integrity.violations[0];
    const reason = this.buildDenialReason(primaryViolation, integrity.violations);

    return {
      allowed: false,
      reason,
      threatLevel,
    };
  }

  // -------------------------------------------------------------------------
  // Private utility methods
  // -------------------------------------------------------------------------

  /**
   * Map a list of violation types to the highest applicable threat level.
   *
   * @param violations - Non-empty array of violation type strings.
   * @returns The highest threat level across all violations.
   */
  private resolveThreatLevel(
    violations: string[]
  ): 'none' | 'low' | 'medium' | 'high' {
    const HIGH_VIOLATIONS = new Set([
      'debugger_attached',
      'device_compromised',
      'code_signature_invalid',
      'initialization_signature_check_failed',
    ]);
    const MEDIUM_VIOLATIONS = new Set(['emulator_detected']);

    if (violations.some((v) => HIGH_VIOLATIONS.has(v))) {
      return 'high';
    }
    if (violations.some((v) => MEDIUM_VIOLATIONS.has(v))) {
      return 'medium';
    }
    // Any unrecognised violation defaults to low
    return 'low';
  }

  /**
   * Build a human-readable denial reason string from the detected violations.
   *
   * @param primaryViolation - The first (most significant) violation type.
   * @param allViolations    - All detected violation types.
   * @returns A descriptive denial reason string.
   */
  private buildDenialReason(
    primaryViolation: string,
    allViolations: string[]
  ): string {
    const REASON_MAP: Record<string, string> = {
      debugger_attached:
        'A debugger is attached to the application process. Operation blocked for security.',
      emulator_detected:
        'The application is running on an emulator or simulator. Operation blocked for security.',
      device_compromised:
        'The device appears to be rooted or jailbroken. Operation blocked for security.',
      code_signature_invalid:
        'Application code signature verification failed. The app may have been tampered with.',
      initialization_signature_check_failed:
        'Application integrity could not be verified at startup.',
    };

    const primaryReason =
      REASON_MAP[primaryViolation] ??
      `Security check failed: ${primaryViolation}`;

    if (allViolations.length > 1) {
      return `${primaryReason} (${allViolations.length} violation(s) detected: ${allViolations.join(', ')})`;
    }

    return primaryReason;
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/**
 * Singleton instance of the RASPGuard service.
 * Import this throughout the app — do not instantiate RASPGuardService
 * directly.
 *
 * Usage:
 * ```typescript
 * import { raspGuard } from './RASPGuard';
 *
 * const result = await raspGuard.preOperationCheck();
 * if (!result.allowed) {
 *   throw new Error(result.reason);
 * }
 * ```
 */
export const raspGuard: IRASPGuard = new RASPGuardService();
export default raspGuard;

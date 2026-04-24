/**
 * SessionLockService — Aegis Personal Cybersecurity Companion
 *
 * Implements ISessionLockService providing:
 *  - Automatic session locking after a configurable idle timeout (default 60s)
 *  - Configurable timeout range: 30–300 seconds (Requirement 2.4)
 *  - Clearing sensitive data from memory on lock (Requirement 2.2)
 *  - Re-authentication via AuthService after lock (Requirement 2.3)
 *  - Inactivity timer reset on user interaction (Requirement 2.5)
 *  - Lock event subscription for UI components
 *
 * Security guarantees:
 *  - Session is locked after 60s of inactivity by default (Requirement 2.1)
 *  - On lock, authService.lockSession() is called to clear session state (Requirement 2.2, 2.3)
 *  - Auto-lock timeout is clamped to the valid 30–300s range (Requirement 2.4)
 *  - resetTimer() must be called on every user interaction to prevent premature lock (Requirement 2.5)
 *
 * Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
 */

import { authService } from './AuthService';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default auto-lock timeout in seconds (Requirement 2.1). */
const DEFAULT_AUTO_LOCK_TIMEOUT_SECONDS = 60;

/** Minimum configurable auto-lock timeout in seconds (Requirement 2.4). */
const MIN_AUTO_LOCK_TIMEOUT_SECONDS = 30;

/** Maximum configurable auto-lock timeout in seconds (Requirement 2.4). */
const MAX_AUTO_LOCK_TIMEOUT_SECONDS = 300;

/** Interval in milliseconds at which the inactivity countdown is decremented. */
const TICK_INTERVAL_MS = 1000;

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface ISessionLockService {
  /** Start the inactivity timer. Call once when the session becomes active. */
  startSession(): void;

  /**
   * Reset the inactivity timer.
   * Must be called on every user interaction to prevent premature auto-lock.
   * Requirements: 2.5
   */
  resetTimer(): void;

  /**
   * Immediately lock the session.
   * Clears sensitive data from memory and calls authService.lockSession().
   * Requirements: 2.2, 2.3
   */
  lockSession(): void;

  /**
   * Returns true when the session is currently locked.
   * Re-authentication via AuthService is required before access is restored.
   */
  isLocked(): boolean;

  /**
   * Returns the number of seconds remaining until the session auto-locks.
   * Returns 0 when the session is already locked or the timer is not running.
   */
  getTimeUntilLock(): number;

  /**
   * Configure the auto-lock timeout.
   * The value is clamped to the valid range [30, 300] seconds.
   * Requirements: 2.4
   */
  setAutoLockTimeout(seconds: number): void;

  /**
   * Subscribe to lock events.
   * The callback is invoked each time the session transitions to the locked state.
   */
  onLock(callback: () => void): void;

  /**
   * Unsubscribe a previously registered lock event callback.
   */
  offLock(callback: () => void): void;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

class SessionLockServiceImpl implements ISessionLockService {
  // -------------------------------------------------------------------------
  // In-memory state
  // -------------------------------------------------------------------------

  /** Whether the session is currently locked. */
  private locked = true;

  /**
   * Auto-lock timeout in seconds.
   * Defaults to 60s; configurable between 30–300s (Requirement 2.4).
   */
  private autoLockTimeoutSeconds = DEFAULT_AUTO_LOCK_TIMEOUT_SECONDS;

  /**
   * Seconds remaining until the session auto-locks.
   * Counts down from `autoLockTimeoutSeconds` to 0.
   */
  private secondsUntilLock = DEFAULT_AUTO_LOCK_TIMEOUT_SECONDS;

  /**
   * Handle for the `setInterval` tick timer.
   * `null` when the timer is not running.
   */
  private tickIntervalId: ReturnType<typeof setInterval> | null = null;

  /**
   * Set of callbacks subscribed to lock events.
   * Each callback is invoked when the session transitions to locked.
   */
  private lockListeners: Set<() => void> = new Set();

  // -------------------------------------------------------------------------
  // ISessionLockService — session lifecycle
  // -------------------------------------------------------------------------

  /**
   * Start the inactivity timer.
   *
   * Marks the session as unlocked, resets the countdown to the configured
   * timeout, and starts the tick interval. If a timer is already running it
   * is cleared first to avoid duplicate intervals.
   *
   * Requirements: 2.1
   */
  startSession(): void {
    this.locked = false;
    this.secondsUntilLock = this.autoLockTimeoutSeconds;
    this.startTick();
  }

  /**
   * Reset the inactivity timer.
   *
   * Called on every user interaction. Resets the countdown back to the full
   * configured timeout so the session is not locked while the user is active.
   *
   * Has no effect when the session is already locked — the user must
   * re-authenticate via AuthService to start a new session.
   *
   * Requirements: 2.5
   */
  resetTimer(): void {
    if (this.locked) {
      return;
    }
    this.secondsUntilLock = this.autoLockTimeoutSeconds;
  }

  /**
   * Immediately lock the session.
   *
   * Actions:
   *  1. Stop the tick interval.
   *  2. Mark the session as locked.
   *  3. Reset the countdown to 0.
   *  4. Call authService.lockSession() to clear the active session state and
   *     any sensitive data held by the AuthService (Requirement 2.2, 2.3).
   *  5. Notify all registered lock listeners.
   *
   * Requirements: 2.2, 2.3
   */
  lockSession(): void {
    this.stopTick();
    this.locked = true;
    this.secondsUntilLock = 0;

    // Clear sensitive data from memory by locking the auth session.
    // This clears the active session state in AuthService (Requirement 2.2).
    // After this call, re-authentication is required (Requirement 2.3).
    authService.lockSession();

    // Notify UI subscribers so they can redirect to the auth screen.
    this.notifyLockListeners();
  }

  // -------------------------------------------------------------------------
  // ISessionLockService — state queries
  // -------------------------------------------------------------------------

  /**
   * Returns true when the session is currently locked.
   */
  isLocked(): boolean {
    return this.locked;
  }

  /**
   * Returns the number of seconds remaining until the session auto-locks.
   * Returns 0 when the session is already locked or the timer is not running.
   */
  getTimeUntilLock(): number {
    if (this.locked) {
      return 0;
    }
    return Math.max(0, this.secondsUntilLock);
  }

  // -------------------------------------------------------------------------
  // ISessionLockService — configuration
  // -------------------------------------------------------------------------

  /**
   * Configure the auto-lock timeout.
   *
   * The provided value is clamped to the valid range [30, 300] seconds
   * (Requirement 2.4). If the timer is currently running, the new timeout
   * takes effect on the next `startSession()` or `resetTimer()` call.
   *
   * Requirements: 2.4
   */
  setAutoLockTimeout(seconds: number): void {
    this.autoLockTimeoutSeconds = Math.min(
      MAX_AUTO_LOCK_TIMEOUT_SECONDS,
      Math.max(MIN_AUTO_LOCK_TIMEOUT_SECONDS, seconds),
    );
  }

  // -------------------------------------------------------------------------
  // ISessionLockService — lock event subscriptions
  // -------------------------------------------------------------------------

  /**
   * Subscribe to lock events.
   * The callback is invoked each time the session transitions to locked.
   */
  onLock(callback: () => void): void {
    this.lockListeners.add(callback);
  }

  /**
   * Unsubscribe a previously registered lock event callback.
   */
  offLock(callback: () => void): void {
    this.lockListeners.delete(callback);
  }

  // -------------------------------------------------------------------------
  // Private helpers — tick timer
  // -------------------------------------------------------------------------

  /**
   * Start the 1-second tick interval.
   * Clears any existing interval before starting a new one to prevent
   * duplicate timers.
   */
  private startTick(): void {
    this.stopTick();
    this.tickIntervalId = setInterval(() => {
      this.onTick();
    }, TICK_INTERVAL_MS);
  }

  /**
   * Stop the tick interval and clear the handle.
   */
  private stopTick(): void {
    if (this.tickIntervalId !== null) {
      clearInterval(this.tickIntervalId);
      this.tickIntervalId = null;
    }
  }

  /**
   * Called once per second by the tick interval.
   *
   * Decrements the countdown by 1. When the countdown reaches 0, the session
   * is automatically locked (Requirement 2.1).
   */
  private onTick(): void {
    if (this.locked) {
      this.stopTick();
      return;
    }

    this.secondsUntilLock -= 1;

    if (this.secondsUntilLock <= 0) {
      // Inactivity timeout reached — auto-lock the session (Requirement 2.1).
      this.lockSession();
    }
  }

  // -------------------------------------------------------------------------
  // Private helpers — event notification
  // -------------------------------------------------------------------------

  /**
   * Invoke all registered lock event listeners.
   */
  private notifyLockListeners(): void {
    for (const listener of this.lockListeners) {
      try {
        listener();
      } catch {
        // Swallow listener errors to prevent one bad subscriber from
        // blocking the others or disrupting the lock flow.
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/**
 * Singleton instance of the SessionLockService.
 * Import this throughout the app — do not instantiate SessionLockServiceImpl directly.
 *
 * Usage:
 * ```typescript
 * import { sessionLockService } from './SessionLockService';
 *
 * // On successful authentication:
 * sessionLockService.startSession();
 *
 * // On every user interaction (e.g. touch event in root layout):
 * sessionLockService.resetTimer();
 *
 * // Subscribe to lock events to redirect to auth screen:
 * sessionLockService.onLock(() => router.replace('/auth'));
 * ```
 */
export const sessionLockService: ISessionLockService =
  new SessionLockServiceImpl();
export default sessionLockService;

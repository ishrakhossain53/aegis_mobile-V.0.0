/**
 * SecureClipboardService — Aegis Personal Cybersecurity Companion
 *
 * Singleton service managing clipboard operations with automatic purge of
 * sensitive data after a configurable timeout (default 30 seconds).
 *
 * Uses expo-clipboard for all clipboard I/O:
 *   - Clipboard.setStringAsync(value)  — write
 *   - Clipboard.getStringAsync()       — read
 *   - Clipboard.setStringAsync('')     — clear (write empty string)
 *
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
 */

import { ClipboardDataType } from '../types/index';

// ---------------------------------------------------------------------------
// Clipboard abstraction (expo-clipboard)
// ---------------------------------------------------------------------------

/**
 * Minimal interface over expo-clipboard so the module can be mocked in tests
 * and gracefully degraded when the native module is unavailable.
 */
interface ClipboardModule {
  setStringAsync(value: string): Promise<void>;
  getStringAsync(): Promise<string>;
}

/**
 * Lazily loads expo-clipboard.
 * Returns null when the package is not installed (e.g. in unit-test environments
 * that do not mock it), allowing the service to degrade gracefully.
 */
function loadClipboard(): ClipboardModule | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('expo-clipboard') as { default?: ClipboardModule } & ClipboardModule;
    // expo-clipboard exports named exports; the module itself has setStringAsync etc.
    if (typeof mod.setStringAsync === 'function') {
      return mod as ClipboardModule;
    }
    if (mod.default && typeof mod.default.setStringAsync === 'function') {
      return mod.default;
    }
    return null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// ISecureClipboardService interface
// ---------------------------------------------------------------------------

export interface ISecureClipboardService {
  /**
   * Copies `value` to the system clipboard and starts (or restarts) the
   * auto-purge timer.
   *
   * Requirements: 5.1, 5.3
   */
  copy(value: string, type: ClipboardDataType): Promise<void>;

  /**
   * Reads the current clipboard content.
   * Returns null when the clipboard is empty or no content was copied via
   * this service.
   */
  paste(): Promise<string | null>;

  /**
   * Immediately clears the system clipboard and cancels the auto-purge timer.
   *
   * Requirement: 5.2
   */
  clear(): void;

  /**
   * Returns true when a value was copied via this service and the auto-purge
   * timer has not yet expired.
   */
  hasContent(): boolean;

  /**
   * Returns the number of seconds remaining until the clipboard is
   * automatically cleared.  Returns 0 when no content is pending.
   */
  getTimeUntilClear(): number;

  /**
   * Configures the auto-purge timeout.
   * Valid range: 10–60 seconds (Requirement 5.4).
   * Values outside the range are clamped to the nearest boundary.
   */
  setClipboardTimeout(seconds: number): void;

  /**
   * Registers a callback to be invoked when the clipboard is cleared
   * (either by the auto-purge timer or by an explicit `clear()` call).
   *
   * Requirement: 5.5
   */
  onClear(callback: () => void): void;

  /**
   * Removes a previously registered clear callback.
   */
  offClear(callback: () => void): void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_SECONDS = 30;
const MIN_TIMEOUT_SECONDS = 10;
const MAX_TIMEOUT_SECONDS = 60;

// ---------------------------------------------------------------------------
// SecureClipboardServiceImpl
// ---------------------------------------------------------------------------

export class SecureClipboardServiceImpl implements ISecureClipboardService {
  // -------------------------------------------------------------------------
  // Private state
  // -------------------------------------------------------------------------

  /** Configured auto-purge timeout in seconds. */
  private timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS;

  /** Whether a value is currently held in the clipboard by this service. */
  private _hasContent: boolean = false;

  /** Unix timestamp (ms) when the clipboard will be auto-cleared. */
  private clearAt: number = 0;

  /** Active auto-purge timer handle. */
  private timerId: ReturnType<typeof setTimeout> | null = null;

  /** Registered clear-notification callbacks. */
  private clearCallbacks: Set<() => void> = new Set();

  // -------------------------------------------------------------------------
  // ISecureClipboardService — copy
  // -------------------------------------------------------------------------

  /**
   * Writes `value` to the system clipboard and (re)starts the auto-purge
   * timer.
   *
   * Requirements: 5.1, 5.3
   */
  async copy(value: string, _type: ClipboardDataType): Promise<void> {
    // Cancel any existing timer before starting a new one
    this._cancelTimer();

    const clipboard = loadClipboard();
    if (clipboard) {
      await clipboard.setStringAsync(value);
    }

    this._hasContent = true;
    this.clearAt = Date.now() + this.timeoutSeconds * 1000;

    // Schedule auto-purge (Requirement 5.1)
    this.timerId = setTimeout(() => {
      void this._autoClear();
    }, this.timeoutSeconds * 1000);
  }

  // -------------------------------------------------------------------------
  // ISecureClipboardService — paste
  // -------------------------------------------------------------------------

  /**
   * Returns the current clipboard string, or null when the clipboard is
   * empty or no content was set by this service.
   */
  async paste(): Promise<string | null> {
    if (!this._hasContent) {
      return null;
    }
    const clipboard = loadClipboard();
    if (!clipboard) {
      return null;
    }
    const value = await clipboard.getStringAsync();
    return value.length > 0 ? value : null;
  }

  // -------------------------------------------------------------------------
  // ISecureClipboardService — clear
  // -------------------------------------------------------------------------

  /**
   * Immediately clears the system clipboard and cancels the auto-purge timer.
   * Notifies all registered callbacks.
   *
   * Requirement: 5.2, 5.5
   */
  clear(): void {
    this._cancelTimer();
    this._clearClipboard();
    this._notifyCallbacks();
  }

  // -------------------------------------------------------------------------
  // ISecureClipboardService — hasContent
  // -------------------------------------------------------------------------

  hasContent(): boolean {
    return this._hasContent;
  }

  // -------------------------------------------------------------------------
  // ISecureClipboardService — getTimeUntilClear
  // -------------------------------------------------------------------------

  /**
   * Returns seconds remaining until auto-clear, rounded up to the nearest
   * whole second.  Returns 0 when no content is pending.
   */
  getTimeUntilClear(): number {
    if (!this._hasContent || this.clearAt === 0) {
      return 0;
    }
    const remaining = this.clearAt - Date.now();
    return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
  }

  // -------------------------------------------------------------------------
  // ISecureClipboardService — setClipboardTimeout
  // -------------------------------------------------------------------------

  /**
   * Sets the auto-purge timeout, clamped to [10, 60] seconds.
   *
   * Requirement: 5.4
   */
  setClipboardTimeout(seconds: number): void {
    this.timeoutSeconds = Math.max(
      MIN_TIMEOUT_SECONDS,
      Math.min(MAX_TIMEOUT_SECONDS, seconds),
    );
  }

  // -------------------------------------------------------------------------
  // ISecureClipboardService — onClear / offClear
  // -------------------------------------------------------------------------

  /**
   * Registers a callback invoked whenever the clipboard is cleared.
   *
   * Requirement: 5.5
   */
  onClear(callback: () => void): void {
    this.clearCallbacks.add(callback);
  }

  /**
   * Removes a previously registered clear callback.
   */
  offClear(callback: () => void): void {
    this.clearCallbacks.delete(callback);
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Cancels the active auto-purge timer, if any.
   */
  private _cancelTimer(): void {
    if (this.timerId !== null) {
      clearTimeout(this.timerId);
      this.timerId = null;
    }
  }

  /**
   * Writes an empty string to the system clipboard and resets internal state.
   */
  private _clearClipboard(): void {
    this._hasContent = false;
    this.clearAt = 0;

    const clipboard = loadClipboard();
    if (clipboard) {
      // Fire-and-forget — we do not await here because clear() is synchronous
      void clipboard.setStringAsync('');
    }
  }

  /**
   * Invokes all registered clear callbacks.
   */
  private _notifyCallbacks(): void {
    for (const cb of this.clearCallbacks) {
      try {
        cb();
      } catch {
        // Swallow callback errors to prevent one bad listener from blocking others
      }
    }
  }

  /**
   * Called by the auto-purge timer on expiry.
   * Clears the clipboard and notifies listeners (Requirement 5.2, 5.5).
   */
  private async _autoClear(): Promise<void> {
    this.timerId = null;
    this._clearClipboard();
    this._notifyCallbacks();
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/**
 * Singleton SecureClipboardService instance.
 *
 * Usage:
 * ```typescript
 * import { secureClipboardService } from './SecureClipboardService';
 *
 * // Copy a password (starts 30-second auto-purge timer):
 * await secureClipboardService.copy(password, 'password');
 *
 * // Listen for clipboard clear events:
 * secureClipboardService.onClear(() => {
 *   showToast('Clipboard cleared');
 * });
 * ```
 */
export const secureClipboardService = new SecureClipboardServiceImpl();
export default secureClipboardService;

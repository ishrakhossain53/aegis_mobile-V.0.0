/**
 * SessionLockService tests — Aegis Personal Cybersecurity Companion
 */

// ---------------------------------------------------------------------------
// Mock AuthService
// ---------------------------------------------------------------------------

const mockLockSession = jest.fn();

jest.mock('./AuthService', () => ({
  authService: {
    lockSession: (...args: unknown[]) => mockLockSession(...args),
  },
}));

import { SessionLockServiceImpl } from './SessionLockService';

// ---------------------------------------------------------------------------
// Helper — create a fresh service instance per test
// ---------------------------------------------------------------------------

function makeService(): SessionLockServiceImpl {
  return new SessionLockServiceImpl();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SessionLockService', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    mockLockSession.mockClear();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // Initial state
  // -------------------------------------------------------------------------

  describe('initial state', () => {
    it('starts in locked state', () => {
      const svc = makeService();
      expect(svc.isLocked()).toBe(true);
    });

    it('getTimeUntilLock returns 0 when locked', () => {
      const svc = makeService();
      expect(svc.getTimeUntilLock()).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // startSession
  // -------------------------------------------------------------------------

  describe('startSession()', () => {
    it('marks session as unlocked', () => {
      const svc = makeService();
      svc.startSession();
      expect(svc.isLocked()).toBe(false);
    });

    it('getTimeUntilLock returns the configured timeout after startSession', () => {
      const svc = makeService();
      svc.startSession();
      const remaining = svc.getTimeUntilLock();
      expect(remaining).toBeGreaterThan(0);
      expect(remaining).toBeLessThanOrEqual(60);
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 2.1 — auto-lock after 60s idle
  // -------------------------------------------------------------------------

  describe('Requirement 2.1 — auto-lock after idle timeout', () => {
    it('auto-locks after 60 seconds of inactivity (default timeout)', () => {
      const svc = makeService();
      svc.startSession();
      expect(svc.isLocked()).toBe(false);

      jest.advanceTimersByTime(60_000);

      expect(svc.isLocked()).toBe(true);
    });

    it('does not lock before the timeout expires', () => {
      const svc = makeService();
      svc.startSession();

      jest.advanceTimersByTime(59_000);

      expect(svc.isLocked()).toBe(false);
    });

    it('calls authService.lockSession() on auto-lock (Req 2.2, 2.3)', () => {
      const svc = makeService();
      svc.startSession();

      jest.advanceTimersByTime(60_000);

      expect(mockLockSession).toHaveBeenCalledTimes(1);
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 2.4 — configurable timeout 30–300s
  // -------------------------------------------------------------------------

  describe('Requirement 2.4 — configurable timeout', () => {
    it('respects a custom timeout of 30 seconds', () => {
      const svc = makeService();
      svc.setAutoLockTimeout(30);
      svc.startSession();

      jest.advanceTimersByTime(29_000);
      expect(svc.isLocked()).toBe(false);

      jest.advanceTimersByTime(1_000);
      expect(svc.isLocked()).toBe(true);
    });

    it('respects a custom timeout of 300 seconds', () => {
      const svc = makeService();
      svc.setAutoLockTimeout(300);
      svc.startSession();

      jest.advanceTimersByTime(299_000);
      expect(svc.isLocked()).toBe(false);

      jest.advanceTimersByTime(1_000);
      expect(svc.isLocked()).toBe(true);
    });

    it('clamps timeout below 30s to 30s', () => {
      const svc = makeService();
      svc.setAutoLockTimeout(5); // below minimum
      svc.startSession();

      jest.advanceTimersByTime(29_000);
      expect(svc.isLocked()).toBe(false);

      jest.advanceTimersByTime(1_000);
      expect(svc.isLocked()).toBe(true);
    });

    it('clamps timeout above 300s to 300s', () => {
      const svc = makeService();
      svc.setAutoLockTimeout(9999); // above maximum
      svc.startSession();

      jest.advanceTimersByTime(299_000);
      expect(svc.isLocked()).toBe(false);

      jest.advanceTimersByTime(1_000);
      expect(svc.isLocked()).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 2.5 — resetTimer() prevents premature lock
  // -------------------------------------------------------------------------

  describe('Requirement 2.5 — resetTimer() resets inactivity countdown', () => {
    it('resets the countdown when called before timeout', () => {
      const svc = makeService();
      svc.startSession();

      // Advance 50 seconds, then reset
      jest.advanceTimersByTime(50_000);
      svc.resetTimer();

      // 50 more seconds — should NOT have locked (reset gave us 60s again)
      jest.advanceTimersByTime(50_000);
      expect(svc.isLocked()).toBe(false);
    });

    it('locks after the full timeout following a reset', () => {
      const svc = makeService();
      svc.startSession();

      jest.advanceTimersByTime(50_000);
      svc.resetTimer();

      jest.advanceTimersByTime(60_000);
      expect(svc.isLocked()).toBe(true);
    });

    it('has no effect when session is already locked', () => {
      const svc = makeService();
      // Session is locked by default — resetTimer should be a no-op
      svc.resetTimer();
      expect(svc.isLocked()).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // lockSession() — immediate lock
  // -------------------------------------------------------------------------

  describe('lockSession()', () => {
    it('immediately locks the session', () => {
      const svc = makeService();
      svc.startSession();
      expect(svc.isLocked()).toBe(false);

      svc.lockSession();
      expect(svc.isLocked()).toBe(true);
    });

    it('calls authService.lockSession()', () => {
      const svc = makeService();
      svc.startSession();
      svc.lockSession();
      expect(mockLockSession).toHaveBeenCalledTimes(1);
    });

    it('getTimeUntilLock returns 0 after lockSession()', () => {
      const svc = makeService();
      svc.startSession();
      svc.lockSession();
      expect(svc.getTimeUntilLock()).toBe(0);
    });

    it('stops the auto-lock timer (no double-lock)', () => {
      const svc = makeService();
      svc.startSession();
      svc.lockSession();
      mockLockSession.mockClear();

      // Advance past the original timeout — should not fire again
      jest.advanceTimersByTime(120_000);
      expect(mockLockSession).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // Lock event subscriptions
  // -------------------------------------------------------------------------

  describe('onLock / offLock subscriptions', () => {
    it('invokes registered callback when session auto-locks', () => {
      const svc = makeService();
      const cb = jest.fn();
      svc.onLock(cb);
      svc.startSession();

      jest.advanceTimersByTime(60_000);

      expect(cb).toHaveBeenCalledTimes(1);
    });

    it('invokes registered callback when lockSession() is called', () => {
      const svc = makeService();
      const cb = jest.fn();
      svc.onLock(cb);
      svc.startSession();
      svc.lockSession();

      expect(cb).toHaveBeenCalledTimes(1);
    });

    it('does not invoke callback after offLock()', () => {
      const svc = makeService();
      const cb = jest.fn();
      svc.onLock(cb);
      svc.offLock(cb);
      svc.startSession();
      svc.lockSession();

      expect(cb).not.toHaveBeenCalled();
    });

    it('supports multiple callbacks', () => {
      const svc = makeService();
      const cb1 = jest.fn();
      const cb2 = jest.fn();
      svc.onLock(cb1);
      svc.onLock(cb2);
      svc.startSession();
      svc.lockSession();

      expect(cb1).toHaveBeenCalledTimes(1);
      expect(cb2).toHaveBeenCalledTimes(1);
    });

    it('continues notifying remaining callbacks if one throws', () => {
      const svc = makeService();
      const badCb = jest.fn().mockImplementation(() => { throw new Error('oops'); });
      const goodCb = jest.fn();
      svc.onLock(badCb);
      svc.onLock(goodCb);
      svc.startSession();
      svc.lockSession();

      expect(goodCb).toHaveBeenCalledTimes(1);
    });
  });

  // -------------------------------------------------------------------------
  // getTimeUntilLock
  // -------------------------------------------------------------------------

  describe('getTimeUntilLock()', () => {
    it('decreases as time passes', () => {
      const svc = makeService();
      svc.startSession();

      const initial = svc.getTimeUntilLock();
      jest.advanceTimersByTime(10_000);
      const later = svc.getTimeUntilLock();

      expect(later).toBeLessThan(initial);
    });

    it('returns 0 after the session locks', () => {
      const svc = makeService();
      svc.startSession();
      jest.advanceTimersByTime(60_000);
      expect(svc.getTimeUntilLock()).toBe(0);
    });
  });
});

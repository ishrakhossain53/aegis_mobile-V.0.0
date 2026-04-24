/**
 * Tests for SecureClipboardService
 *
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
 */

// ---------------------------------------------------------------------------
// Mock expo-clipboard before importing the service
// ---------------------------------------------------------------------------

const mockSetStringAsync = jest.fn().mockResolvedValue(undefined);
const mockGetStringAsync = jest.fn().mockResolvedValue('');

jest.mock('expo-clipboard', () => ({
  setStringAsync: mockSetStringAsync,
  getStringAsync: mockGetStringAsync,
}), { virtual: true });

// ---------------------------------------------------------------------------
// Import after mocks are set up
// ---------------------------------------------------------------------------

import { SecureClipboardServiceImpl } from './SecureClipboardService';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Creates a fresh service instance for each test to avoid shared state. */
function makeService(): SecureClipboardServiceImpl {
  return new SecureClipboardServiceImpl();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SecureClipboardService', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    mockSetStringAsync.mockClear();
    mockGetStringAsync.mockClear();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // Requirement 5.1 — 30-second auto-purge timer starts on copy
  // -------------------------------------------------------------------------

  describe('Requirement 5.1 — auto-purge timer', () => {
    it('starts a 30-second timer when copy() is called', async () => {
      const svc = makeService();
      await svc.copy('secret', 'password');

      expect(svc.hasContent()).toBe(true);

      // Advance just under 30 seconds — content should still be present
      jest.advanceTimersByTime(29_999);
      expect(svc.hasContent()).toBe(true);

      // Advance past 30 seconds — content should be cleared
      jest.advanceTimersByTime(1);
      expect(svc.hasContent()).toBe(false);
    });

    it('writes the value to the system clipboard on copy()', async () => {
      const svc = makeService();
      await svc.copy('my-password', 'password');

      expect(mockSetStringAsync).toHaveBeenCalledWith('my-password');
    });

    it('restarts the timer when copy() is called again before expiry', async () => {
      const svc = makeService();
      await svc.copy('first', 'password');

      // Advance 20 seconds, then copy again
      jest.advanceTimersByTime(20_000);
      await svc.copy('second', 'password');

      // 25 seconds after the second copy — should still have content
      jest.advanceTimersByTime(25_000);
      expect(svc.hasContent()).toBe(true);

      // 30 seconds after the second copy — should be cleared
      jest.advanceTimersByTime(5_000);
      expect(svc.hasContent()).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 5.2 — clipboard cleared on timer expiry
  // -------------------------------------------------------------------------

  describe('Requirement 5.2 — clipboard cleared on expiry', () => {
    it('writes an empty string to the system clipboard when the timer expires', async () => {
      const svc = makeService();
      await svc.copy('secret', 'password');

      mockSetStringAsync.mockClear();

      jest.advanceTimersByTime(30_000);

      // Allow the async _autoClear to flush
      await Promise.resolve();

      expect(mockSetStringAsync).toHaveBeenCalledWith('');
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 5.3 — supported data types
  // -------------------------------------------------------------------------

  describe('Requirement 5.3 — supported data types', () => {
    const types = ['password', 'apiKey', 'totp', 'generic'] as const;

    for (const type of types) {
      it(`accepts data type "${type}"`, async () => {
        const svc = makeService();
        await expect(svc.copy('value', type)).resolves.toBeUndefined();
        expect(svc.hasContent()).toBe(true);
      });
    }
  });

  // -------------------------------------------------------------------------
  // Requirement 5.4 — configurable timeout (10–60 seconds)
  // -------------------------------------------------------------------------

  describe('Requirement 5.4 — configurable timeout', () => {
    it('uses the configured timeout instead of the default 30 seconds', async () => {
      const svc = makeService();
      svc.setClipboardTimeout(10);
      await svc.copy('secret', 'password');

      jest.advanceTimersByTime(9_999);
      expect(svc.hasContent()).toBe(true);

      jest.advanceTimersByTime(1);
      expect(svc.hasContent()).toBe(false);
    });

    it('clamps timeout below 10 seconds to 10 seconds', async () => {
      const svc = makeService();
      svc.setClipboardTimeout(5); // below minimum
      await svc.copy('secret', 'password');

      // Should still be present at 9 seconds (clamped to 10)
      jest.advanceTimersByTime(9_999);
      expect(svc.hasContent()).toBe(true);

      jest.advanceTimersByTime(1);
      expect(svc.hasContent()).toBe(false);
    });

    it('clamps timeout above 60 seconds to 60 seconds', async () => {
      const svc = makeService();
      svc.setClipboardTimeout(120); // above maximum
      await svc.copy('secret', 'password');

      // Should still be present at 59 seconds (clamped to 60)
      jest.advanceTimersByTime(59_999);
      expect(svc.hasContent()).toBe(true);

      jest.advanceTimersByTime(1);
      expect(svc.hasContent()).toBe(false);
    });

    it('accepts the minimum boundary value of 10 seconds', async () => {
      const svc = makeService();
      svc.setClipboardTimeout(10);
      await svc.copy('secret', 'password');

      jest.advanceTimersByTime(10_000);
      expect(svc.hasContent()).toBe(false);
    });

    it('accepts the maximum boundary value of 60 seconds', async () => {
      const svc = makeService();
      svc.setClipboardTimeout(60);
      await svc.copy('secret', 'password');

      jest.advanceTimersByTime(60_000);
      expect(svc.hasContent()).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 5.5 — UI notification on clear
  // -------------------------------------------------------------------------

  describe('Requirement 5.5 — UI notification on clear', () => {
    it('invokes registered onClear callbacks when the timer expires', async () => {
      const svc = makeService();
      const callback = jest.fn();
      svc.onClear(callback);

      await svc.copy('secret', 'password');
      expect(callback).not.toHaveBeenCalled();

      jest.advanceTimersByTime(30_000);
      await Promise.resolve();

      expect(callback).toHaveBeenCalledTimes(1);
    });

    it('invokes registered onClear callbacks when clear() is called explicitly', async () => {
      const svc = makeService();
      const callback = jest.fn();
      svc.onClear(callback);

      await svc.copy('secret', 'password');
      svc.clear();

      expect(callback).toHaveBeenCalledTimes(1);
    });

    it('does not invoke callbacks removed via offClear()', async () => {
      const svc = makeService();
      const callback = jest.fn();
      svc.onClear(callback);
      svc.offClear(callback);

      await svc.copy('secret', 'password');
      svc.clear();

      expect(callback).not.toHaveBeenCalled();
    });

    it('supports multiple callbacks', async () => {
      const svc = makeService();
      const cb1 = jest.fn();
      const cb2 = jest.fn();
      svc.onClear(cb1);
      svc.onClear(cb2);

      await svc.copy('secret', 'password');
      svc.clear();

      expect(cb1).toHaveBeenCalledTimes(1);
      expect(cb2).toHaveBeenCalledTimes(1);
    });

    it('continues notifying remaining callbacks if one throws', async () => {
      const svc = makeService();
      const badCb = jest.fn().mockImplementation(() => {
        throw new Error('callback error');
      });
      const goodCb = jest.fn();
      svc.onClear(badCb);
      svc.onClear(goodCb);

      await svc.copy('secret', 'password');
      svc.clear();

      expect(goodCb).toHaveBeenCalledTimes(1);
    });
  });

  // -------------------------------------------------------------------------
  // clear() — immediate clear
  // -------------------------------------------------------------------------

  describe('clear()', () => {
    it('immediately clears hasContent', async () => {
      const svc = makeService();
      await svc.copy('secret', 'password');
      expect(svc.hasContent()).toBe(true);

      svc.clear();
      expect(svc.hasContent()).toBe(false);
    });

    it('cancels the auto-purge timer so callbacks are not called twice', async () => {
      const svc = makeService();
      const callback = jest.fn();
      svc.onClear(callback);

      await svc.copy('secret', 'password');
      svc.clear(); // explicit clear — callback fires once

      jest.advanceTimersByTime(30_000); // timer should be cancelled
      await Promise.resolve();

      expect(callback).toHaveBeenCalledTimes(1);
    });

    it('writes an empty string to the system clipboard', async () => {
      const svc = makeService();
      await svc.copy('secret', 'password');
      mockSetStringAsync.mockClear();

      svc.clear();
      await Promise.resolve();

      expect(mockSetStringAsync).toHaveBeenCalledWith('');
    });
  });

  // -------------------------------------------------------------------------
  // hasContent()
  // -------------------------------------------------------------------------

  describe('hasContent()', () => {
    it('returns false before any copy', () => {
      const svc = makeService();
      expect(svc.hasContent()).toBe(false);
    });

    it('returns true after copy and false after clear', async () => {
      const svc = makeService();
      await svc.copy('value', 'generic');
      expect(svc.hasContent()).toBe(true);

      svc.clear();
      expect(svc.hasContent()).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // getTimeUntilClear()
  // -------------------------------------------------------------------------

  describe('getTimeUntilClear()', () => {
    it('returns 0 when no content is pending', () => {
      const svc = makeService();
      expect(svc.getTimeUntilClear()).toBe(0);
    });

    it('returns approximately the configured timeout immediately after copy', async () => {
      const svc = makeService();
      await svc.copy('secret', 'password');

      const remaining = svc.getTimeUntilClear();
      expect(remaining).toBeGreaterThanOrEqual(29);
      expect(remaining).toBeLessThanOrEqual(30);
    });

    it('decreases as time passes', async () => {
      const svc = makeService();
      await svc.copy('secret', 'password');

      jest.advanceTimersByTime(10_000);
      const remaining = svc.getTimeUntilClear();
      expect(remaining).toBeGreaterThanOrEqual(19);
      expect(remaining).toBeLessThanOrEqual(20);
    });

    it('returns 0 after the timer expires', async () => {
      const svc = makeService();
      await svc.copy('secret', 'password');

      jest.advanceTimersByTime(30_000);
      await Promise.resolve();

      expect(svc.getTimeUntilClear()).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // paste()
  // -------------------------------------------------------------------------

  describe('paste()', () => {
    it('returns null when no content has been copied', async () => {
      const svc = makeService();
      const result = await svc.paste();
      expect(result).toBeNull();
    });

    it('returns the clipboard value after copy', async () => {
      const svc = makeService();
      mockGetStringAsync.mockResolvedValueOnce('my-secret');
      await svc.copy('my-secret', 'password');

      const result = await svc.paste();
      expect(result).toBe('my-secret');
    });

    it('returns null after clear', async () => {
      const svc = makeService();
      await svc.copy('secret', 'password');
      svc.clear();

      const result = await svc.paste();
      expect(result).toBeNull();
    });
  });
});

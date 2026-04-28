/**
 * ThemeContext tests — Aegis Personal Cybersecurity Companion
 *
 * Tests the theme logic: color palettes, toggle, persistence.
 * Uses pure unit tests for palette values and a hook test for state management.
 */

// ---------------------------------------------------------------------------
// Mocks — must be before imports
// ---------------------------------------------------------------------------

const mockGet = jest.fn();
const mockSet = jest.fn().mockResolvedValue(undefined);

jest.mock('../services/SecurePrefs', () => ({
  securePrefs: {
    get: (...args: unknown[]) => mockGet(...args),
    set: (...args: unknown[]) => mockSet(...args),
  },
}));

// Provide a stable useColorScheme mock without spreading all of react-native
jest.mock('react-native/Libraries/Utilities/useColorScheme', () => ({
  default: jest.fn().mockReturnValue('dark'),
}));

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import { darkTheme, lightTheme } from './colors';

// ---------------------------------------------------------------------------
// Pure palette tests (no React needed)
// ---------------------------------------------------------------------------

describe('ThemeContext — color palettes', () => {
  describe('darkTheme', () => {
    it('has a near-black background', () => {
      expect(darkTheme.background).toBe('#0A0A0F');
    });

    it('has a light textPrimary (near white)', () => {
      expect(darkTheme.textPrimary).toBe('#F0F0FF');
    });

    it('has indigo primary color', () => {
      expect(darkTheme.primary).toBe('#6366F1');
    });

    it('has green safe color', () => {
      expect(darkTheme.safe).toBe('#00C97A');
    });

    it('has amber warning color', () => {
      expect(darkTheme.warning).toBe('#F59E0B');
    });

    it('has red danger color', () => {
      expect(darkTheme.danger).toBe('#EF4444');
    });

    it('has a dark surface color', () => {
      expect(darkTheme.surface).toBe('#13131C');
    });

    it('has a dark tab bar color', () => {
      expect(darkTheme.tabBar).toBe('#0F0F18');
    });

    it('has statusColors map', () => {
      expect(darkTheme.statusColors).toBeDefined();
      expect(typeof darkTheme.statusColors.safe).toBe('string');
      expect(typeof darkTheme.statusColors.critical).toBe('string');
    });

    it('has scoreGradient with high/medium/low', () => {
      expect(Array.isArray(darkTheme.scoreGradient.high)).toBe(true);
      expect(Array.isArray(darkTheme.scoreGradient.medium)).toBe(true);
      expect(Array.isArray(darkTheme.scoreGradient.low)).toBe(true);
    });
  });

  describe('lightTheme', () => {
    it('has a near-white background', () => {
      expect(lightTheme.background).toBe('#F5F5FA');
    });

    it('has a dark textPrimary (near black)', () => {
      expect(lightTheme.textPrimary).toBe('#0F0F1A');
    });

    it('has the same primary color as dark theme', () => {
      expect(lightTheme.primary).toBe(darkTheme.primary);
    });

    it('has a white surface', () => {
      expect(lightTheme.surface).toBe('#FFFFFF');
    });

    it('has a white tab bar', () => {
      expect(lightTheme.tabBar).toBe('#FFFFFF');
    });

    it('has a lighter border than dark theme', () => {
      // Light border is lighter than dark border
      expect(lightTheme.border).toBe('#E0E0EC');
      expect(darkTheme.border).toBe('#2A2A3E');
    });

    it('has statusColors map', () => {
      expect(lightTheme.statusColors).toBeDefined();
      expect(typeof lightTheme.statusColors.safe).toBe('string');
    });
  });

  describe('theme contrast', () => {
    it('dark background is darker than light background', () => {
      // Dark background starts with #0A (very dark), light with #F5 (very light)
      const darkBg = parseInt(darkTheme.background.slice(1, 3), 16);
      const lightBg = parseInt(lightTheme.background.slice(1, 3), 16);
      expect(darkBg).toBeLessThan(lightBg);
    });

    it('dark textPrimary is lighter than light textPrimary', () => {
      // Dark text is near-white (#F0), light text is near-black (#0F)
      const darkText = parseInt(darkTheme.textPrimary.slice(1, 3), 16);
      const lightText = parseInt(lightTheme.textPrimary.slice(1, 3), 16);
      expect(darkText).toBeGreaterThan(lightText);
    });

    it('both themes have a red destructive color', () => {
      // Both are red hex colors
      expect(darkTheme.destructive).toMatch(/^#[0-9A-Fa-f]{6}$/);
      expect(lightTheme.destructive).toMatch(/^#[0-9A-Fa-f]{6}$/);
      // Red channel should be dominant (first two hex digits > 0xCC)
      const darkRed = parseInt(darkTheme.destructive.slice(1, 3), 16);
      const lightRed = parseInt(lightTheme.destructive.slice(1, 3), 16);
      expect(darkRed).toBeGreaterThan(0xCC);
      expect(lightRed).toBeGreaterThan(0xCC);
    });
  });

  describe('scoreGradient', () => {
    it('high gradient has 2 colors', () => {
      expect(darkTheme.scoreGradient.high.length).toBe(2);
      expect(lightTheme.scoreGradient.high.length).toBe(2);
    });

    it('medium gradient has 2 colors', () => {
      expect(darkTheme.scoreGradient.medium.length).toBe(2);
    });

    it('low gradient has 2 colors', () => {
      expect(darkTheme.scoreGradient.low.length).toBe(2);
    });
  });
});

// ---------------------------------------------------------------------------
// ThemeProvider state tests
// ---------------------------------------------------------------------------

import React from 'react';
import { renderHook, act } from '@testing-library/react-hooks';
import { ThemeProvider, useTheme } from './ThemeContext';

const flushPromises = (ms = 100) => new Promise((resolve) => setTimeout(resolve, ms));

describe('ThemeContext — provider state', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockGet.mockResolvedValue(null);
  });

  const wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(ThemeProvider, null, children);

  it('SecurePrefs.get is called with theme_mode on mount', async () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    await act(async () => { await flushPromises(); });
    expect(mockGet).toHaveBeenCalledWith('theme_mode');
  });

  it('toggleTheme calls SecurePrefs.set with the new mode', async () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    await act(async () => { await flushPromises(); });

    const currentMode = result.current.mode;
    await act(async () => {
      result.current.toggleTheme();
      await flushPromises();
    });

    const expectedMode = currentMode === 'dark' ? 'light' : 'dark';
    expect(mockSet).toHaveBeenCalledWith('theme_mode', expectedMode);
  });

  it('setTheme("light") calls SecurePrefs.set with light', async () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    await act(async () => { await flushPromises(); });

    await act(async () => {
      result.current.setTheme('light');
      await flushPromises();
    });

    expect(mockSet).toHaveBeenCalledWith('theme_mode', 'light');
    expect(result.current.mode).toBe('light');
    expect(result.current.isDark).toBe(false);
  });

  it('loads saved light preference from SecurePrefs', async () => {
    mockGet.mockResolvedValue('light');
    const { result } = renderHook(() => useTheme(), { wrapper });
    await act(async () => { await flushPromises(); });
    expect(result.current.mode).toBe('light');
    expect(result.current.isDark).toBe(false);
  });

  it('colors match lightTheme when mode is light', async () => {
    mockGet.mockResolvedValue('light');
    const { result } = renderHook(() => useTheme(), { wrapper });
    await act(async () => { await flushPromises(); });
    expect(result.current.colors.background).toBe(lightTheme.background);
    expect(result.current.colors.textPrimary).toBe(lightTheme.textPrimary);
  });
});

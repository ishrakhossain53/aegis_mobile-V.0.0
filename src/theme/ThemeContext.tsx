/**
 * ThemeContext — Aegis dark / light mode
 *
 * Provides:
 *  - Current theme colors via useTheme()
 *  - Toggle function via useThemeToggle()
 *  - Persists preference to SecurePrefs so it survives restarts
 *  - Defaults to the device color scheme on first launch
 */

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  ReactNode,
} from 'react';
import { useColorScheme } from 'react-native';
import { darkTheme, lightTheme, ThemeColors } from './colors';
import { securePrefs } from '../services/SecurePrefs';

// ---------------------------------------------------------------------------
// Context types
// ---------------------------------------------------------------------------

type ThemeMode = 'dark' | 'light';

interface ThemeContextValue {
  colors: ThemeColors;
  mode: ThemeMode;
  isDark: boolean;
  toggleTheme: () => void;
  setTheme: (mode: ThemeMode) => void;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const ThemeContext = createContext<ThemeContextValue>({
  colors: darkTheme,
  mode: 'dark',
  isDark: true,
  toggleTheme: () => {},
  setTheme: () => {},
});

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function ThemeProvider({ children }: { children: ReactNode }) {
  const deviceScheme = useColorScheme();
  const [mode, setMode] = useState<ThemeMode>('dark');

  // Load persisted preference on mount
  useEffect(() => {
    (async () => {
      try {
        const saved = await securePrefs.get('theme_mode');
        if (saved === 'light' || saved === 'dark') {
          setMode(saved);
        } else {
          // Default to device scheme
          setMode(deviceScheme === 'light' ? 'light' : 'dark');
        }
      } catch {
        setMode(deviceScheme === 'light' ? 'light' : 'dark');
      }
    })();
  }, [deviceScheme]);

  const setTheme = useCallback(async (newMode: ThemeMode) => {
    setMode(newMode);
    try {
      await securePrefs.set('theme_mode', newMode);
    } catch {
      // non-fatal
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(mode === 'dark' ? 'light' : 'dark');
  }, [mode, setTheme]);

  const value: ThemeContextValue = {
    colors: mode === 'dark' ? darkTheme : lightTheme,
    mode,
    isDark: mode === 'dark',
    toggleTheme,
    setTheme,
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/** Returns the current theme colors and mode info. */
export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext);
}

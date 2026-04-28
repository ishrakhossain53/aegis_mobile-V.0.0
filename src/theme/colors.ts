/**
 * Semantic color token system for Aegis Personal Cybersecurity Companion.
 *
 * Supports dark and light themes. All UI components consume colors via
 * the useTheme() hook from ThemeContext rather than importing this directly.
 *
 * Requirements: 24.1, 24.2, 24.3, 24.4
 */

// ---------------------------------------------------------------------------
// Status / semantic tokens (theme-independent)
// ---------------------------------------------------------------------------

export const statusColors: Record<string, string> = {
  safe: '#00C97A',
  advisory: '#F59E0B',
  warning: '#F59E0B',
  critical: '#EF4444',
  excellent: '#00C97A',
  good: '#00C97A',
  fair: '#F59E0B',
  poor: '#EF4444',
  compromised: '#EF4444',
  neutral: '#8E8E93',
};

export const scoreGradient = {
  high: ['#00C97A', '#00A060'] as [string, string],
  medium: ['#F59E0B', '#D97706'] as [string, string],
  low: ['#EF4444', '#DC2626'] as [string, string],
};

// ---------------------------------------------------------------------------
// Theme palettes
// ---------------------------------------------------------------------------

export interface ThemeColors {
  // Semantic status
  safe: string;
  warning: string;
  danger: string;
  neutral: string;

  // Background hierarchy
  background: string;
  surface: string;
  surfaceElevated: string;
  border: string;

  // Text hierarchy
  textPrimary: string;
  textSecondary: string;
  textMuted: string;
  textMonospace: string;

  // Interactive
  primary: string;
  primaryPressed: string;
  destructive: string;
  success: string;

  // Tab bar
  tabBar: string;
  tabBarBorder: string;

  // Status maps
  statusColors: Record<string, string>;
  scoreGradient: typeof scoreGradient;
}

export const darkTheme: ThemeColors = {
  safe: '#00C97A',
  warning: '#F59E0B',
  danger: '#EF4444',
  neutral: '#8E8E93',

  background: '#0A0A0F',
  surface: '#13131C',
  surfaceElevated: '#1C1C2A',
  border: '#2A2A3E',

  textPrimary: '#F0F0FF',
  textSecondary: '#9090A8',
  textMuted: '#55556A',
  textMonospace: '#00C97A',

  primary: '#6366F1',
  primaryPressed: '#4F52D4',
  destructive: '#EF4444',
  success: '#00C97A',

  tabBar: '#0F0F18',
  tabBarBorder: '#1E1E2E',

  statusColors,
  scoreGradient,
};

export const lightTheme: ThemeColors = {
  safe: '#059669',
  warning: '#D97706',
  danger: '#DC2626',
  neutral: '#6B7280',

  background: '#F5F5FA',
  surface: '#FFFFFF',
  surfaceElevated: '#EEEEF6',
  border: '#E0E0EC',

  textPrimary: '#0F0F1A',
  textSecondary: '#4B4B6A',
  textMuted: '#9090A8',
  textMonospace: '#059669',

  primary: '#6366F1',
  primaryPressed: '#4F52D4',
  destructive: '#DC2626',
  success: '#059669',

  tabBar: '#FFFFFF',
  tabBarBorder: '#E0E0EC',

  statusColors: {
    ...statusColors,
    safe: '#059669',
    excellent: '#059669',
    good: '#059669',
    warning: '#D97706',
    advisory: '#D97706',
    fair: '#D97706',
    critical: '#DC2626',
    poor: '#DC2626',
    compromised: '#DC2626',
  },
  scoreGradient: {
    high: ['#059669', '#047857'],
    medium: ['#D97706', '#B45309'],
    low: ['#DC2626', '#B91C1C'],
  },
};

// ---------------------------------------------------------------------------
// Legacy default export (dark) — kept for backward compat during migration
// ---------------------------------------------------------------------------
export const colors = darkTheme;
export type ColorKey = keyof ThemeColors;

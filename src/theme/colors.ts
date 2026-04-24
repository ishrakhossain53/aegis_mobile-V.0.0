/**
 * Semantic color token system for Aegis Personal Cybersecurity Companion.
 *
 * All UI components MUST reference colors from this module rather than
 * using raw hex literals, ensuring consistent, accessible color usage
 * that communicates security status clearly.
 *
 * Requirements: 24.1, 24.2, 24.3, 24.4
 */

// ---------------------------------------------------------------------------
// Semantic status tokens
// ---------------------------------------------------------------------------

/** Safe / secure state — score ≥ 80, no threats, secure network. */
const safe = '#00FF88' as const;

/** Warning / advisory state — score 50–79, minor issues, weak passwords. */
const warning = '#FFB800' as const;

/** Critical / danger state — score < 50, active threats, breaches detected. */
const danger = '#FF3B30' as const;

/** Neutral / inactive state — disabled UI, secondary text. */
const neutral = '#8E8E93' as const;

// ---------------------------------------------------------------------------
// Background hierarchy tokens
// ---------------------------------------------------------------------------

/** App-level background — near-black base layer. */
const background = '#0A0A0F' as const;

/** Card / surface layer rendered on top of background. */
const surface = '#12121A' as const;

/** Elevated surface — modals, bottom sheets, popovers. */
const surfaceElevated = '#1C1C28' as const;

/** Border / divider between surface elements. */
const border = '#2A2A3A' as const;

// ---------------------------------------------------------------------------
// Text hierarchy tokens
// ---------------------------------------------------------------------------

/** Primary body text — maximum contrast on dark backgrounds. */
const textPrimary = '#FFFFFF' as const;

/** Secondary / supporting text — reduced emphasis. */
const textSecondary = '#A0A0B0' as const;

/** Muted / placeholder text — lowest emphasis. */
const textMuted = '#606070' as const;

/**
 * Monospace text color — used for passwords, API keys, hashes, and other
 * sensitive data displayed in a fixed-width font.
 */
const textMonospace = '#00FF88' as const;

// ---------------------------------------------------------------------------
// Interactive state colors
// ---------------------------------------------------------------------------

/** Primary interactive color — buttons, links, active tab indicators. */
const primary = '#5B5BFF' as const;

/** Primary color in pressed / active state. */
const primaryPressed = '#4444DD' as const;

/** Destructive action color — delete, revoke, wipe. */
const destructive = '#FF3B30' as const;

/** Success confirmation color — matches `safe`. */
const success = '#00FF88' as const;

// ---------------------------------------------------------------------------
// Status color map
// Requirement 24.4 — maps threat level / score level strings to hex values.
// ---------------------------------------------------------------------------

/**
 * Maps threat level and score level strings to their corresponding hex color.
 * Used by components that receive a dynamic status string and need the
 * matching color without a switch statement.
 *
 * @example
 * const color = statusColors['critical']; // '#FF3B30'
 */
export const statusColors: Record<string, string> = {
  // Threat levels (ThreatLevel type)
  safe: safe,
  advisory: warning,
  warning: warning,
  critical: danger,

  // Security score levels (SecurityScore.level)
  excellent: safe,
  good: safe,
  fair: warning,
  poor: danger,

  // Generic boolean-style states
  compromised: danger,
  neutral: neutral,
} as const;

// ---------------------------------------------------------------------------
// Score gradient stops
// Used by ScoreRing and other score visualisation components.
// ---------------------------------------------------------------------------

/**
 * Gradient color pairs for each score band.
 * Index 0 is the start color, index 1 is the end color.
 */
export const scoreGradient = {
  /** Score 80–100 — green gradient */
  high: ['#00FF88', '#00CC66'] as [string, string],
  /** Score 50–79 — amber gradient */
  medium: ['#FFB800', '#FF8C00'] as [string, string],
  /** Score 0–49 — red gradient */
  low: ['#FF3B30', '#CC2020'] as [string, string],
} as const;

// ---------------------------------------------------------------------------
// Main colors export
// ---------------------------------------------------------------------------

/**
 * Central color token object for the Aegis design system.
 *
 * Import and use as:
 * ```ts
 * import { colors } from '@/theme/colors';
 * style={{ backgroundColor: colors.surface }}
 * ```
 */
export const colors = {
  // Semantic status
  safe,
  warning,
  danger,
  neutral,

  // Background hierarchy
  background,
  surface,
  surfaceElevated,
  border,

  // Text hierarchy
  textPrimary,
  textSecondary,
  textMuted,
  textMonospace,

  // Status color map
  statusColors,

  // Score gradient
  scoreGradient,

  // Interactive states
  primary,
  primaryPressed,
  destructive,
  success,
} as const;

export type ColorKey = keyof typeof colors;

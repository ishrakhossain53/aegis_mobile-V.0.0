/**
 * SecurityBadge — Aegis Personal Cybersecurity Companion
 *
 * Renders a pill-shaped badge indicating a security status:
 *   safe     → green (#00FF88) background tint, "SAFE" label
 *   warning  → amber (#FFB800) background tint, "WARNING" label
 *   critical → red   (#FF3B30) background tint, "CRITICAL" label
 *
 * Background is 15% opacity of the status color rendered on colors.surface.
 * Text is all-caps monospace, rounded pill shape.
 *
 * Requirements: 13.4, 13.5, 13.6
 */

import React from 'react';
import { View, Text, StyleSheet, ViewStyle } from 'react-native';
import { colors } from '../theme/colors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SecurityBadgeProps {
  status: 'safe' | 'warning' | 'critical';
  style?: ViewStyle;
}

// ---------------------------------------------------------------------------
// Status configuration
// ---------------------------------------------------------------------------

const STATUS_CONFIG = {
  safe: {
    color: '#00FF88',
    label: 'SAFE',
  },
  warning: {
    color: '#FFB800',
    label: 'WARNING',
  },
  critical: {
    color: '#FF3B30',
    label: 'CRITICAL',
  },
} as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Converts a hex color string to an rgba string with the given opacity.
 * Supports 6-digit hex strings (e.g. "#00FF88").
 */
function hexToRgba(hex: string, opacity: number): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r}, ${g}, ${b}, ${opacity})`;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const SecurityBadge: React.FC<SecurityBadgeProps> = ({ status, style }) => {
  const config = STATUS_CONFIG[status];
  const backgroundColor = hexToRgba(config.color, 0.15);

  return (
    <View
      style={[styles.badge, { backgroundColor }, style]}
      accessibilityLabel={`Security status: ${config.label}`}
      accessibilityRole="text"
    >
      <Text style={[styles.label, { color: config.color }]}>
        {config.label}
      </Text>
    </View>
  );
};

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  badge: {
    alignSelf: 'flex-start',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 100,
  },
  label: {
    fontFamily: 'monospace',
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.8,
  },
});

export default SecurityBadge;

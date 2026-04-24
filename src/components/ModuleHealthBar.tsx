/**
 * ModuleHealthBar — Aegis Personal Cybersecurity Companion
 *
 * Horizontal progress bar with label, score value ({score}/100), and fill
 * color following the same green/amber/red thresholds as ScoreRing.
 * Tappable — invokes onPress to navigate to the relevant module screen.
 *
 * Color thresholds:
 *   80–100 → #00FF88 (green)
 *   50–79  → #FFB800 (amber)
 *   0–49   → #FF3B30 (red)
 *
 * Requirements: 21.1, 21.2, 21.3, 21.4, 21.5
 */

import React from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ViewStyle,
} from 'react-native';
import { colors } from '../theme/colors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ModuleHealthBarProps {
  label: string;
  /** 0–100 */
  score: number;
  onPress?: () => void;
  style?: ViewStyle;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getScoreColor(score: number): string {
  if (score >= 80) return '#00FF88';
  if (score >= 50) return '#FFB800';
  return '#FF3B30';
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const ModuleHealthBar: React.FC<ModuleHealthBarProps> = ({
  label,
  score,
  onPress,
  style,
}) => {
  const clampedScore = Math.max(0, Math.min(100, score));
  const fillColor = getScoreColor(clampedScore);
  const fillPercent = `${clampedScore}%`;

  return (
    <TouchableOpacity
      onPress={onPress}
      activeOpacity={onPress ? 0.7 : 1}
      style={[styles.container, style]}
      accessibilityLabel={`${label}: ${clampedScore} out of 100. Tap to view details.`}
      accessibilityRole="button"
      accessibilityHint="Opens the module detail screen"
    >
      {/* Header row: label + score */}
      <View style={styles.header}>
        <Text style={styles.label} numberOfLines={1}>
          {label}
        </Text>
        <Text style={[styles.scoreText, { color: fillColor }]}>
          {clampedScore}/100
        </Text>
      </View>

      {/* Progress bar */}
      <View style={styles.trackContainer}>
        <View
          style={[
            styles.fill,
            { width: fillPercent, backgroundColor: fillColor },
          ]}
          accessibilityElementsHidden
        />
      </View>
    </TouchableOpacity>
  );
};

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  container: {
    backgroundColor: colors.surface,
    borderRadius: 10,
    padding: 12,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  label: {
    color: colors.textPrimary,
    fontSize: 14,
    fontWeight: '600',
    flex: 1,
    marginRight: 8,
  },
  scoreText: {
    fontSize: 13,
    fontWeight: '700',
    fontFamily: 'monospace',
  },
  trackContainer: {
    height: 6,
    backgroundColor: colors.border,
    borderRadius: 3,
    overflow: 'hidden',
  },
  fill: {
    height: '100%',
    borderRadius: 3,
  },
});

export default ModuleHealthBar;

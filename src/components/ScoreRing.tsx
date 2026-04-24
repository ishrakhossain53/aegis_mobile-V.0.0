/**
 * ScoreRing — Aegis Personal Cybersecurity Companion
 *
 * Animated circular progress ring displaying a 0–100 security score.
 * Uses React Native's Animated API (no Reanimated dependency) for
 * maximum Expo Go compatibility.
 *
 * Color thresholds:
 *   80–100 → #00FF88 (green)
 *   50–79  → #FFB800 (amber)
 *   0–49   → #FF3B30 (red)
 *
 * Requirements: 12.1, 12.2, 12.3, 12.4, 12.5
 */

import React, { useEffect, useRef } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ViewStyle,
  Animated,
} from 'react-native';
import { colors } from '../theme/colors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScoreRingProps {
  /** 0–100 */
  score: number;
  /** default 120 */
  size?: number;
  /** default 10 */
  strokeWidth?: number;
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

export const ScoreRing: React.FC<ScoreRingProps> = ({
  score,
  size = 120,
  strokeWidth = 10,
  style,
}) => {
  const clampedScore = Math.max(0, Math.min(100, score));
  const ringColor = getScoreColor(clampedScore);
  const halfSize = size / 2;
  const innerSize = size - strokeWidth * 2;

  // Animated value: 0 → clampedScore over 800ms
  const progressAnim = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    progressAnim.setValue(0);
    Animated.timing(progressAnim, {
      toValue: clampedScore,
      duration: 800,
      useNativeDriver: false,
    }).start();
  }, [clampedScore]);

  // Right half rotates from -180° → 0° as progress goes 0 → 50
  const rightRotation = progressAnim.interpolate({
    inputRange: [0, 50, 100],
    outputRange: ['-180deg', '0deg', '0deg'],
    extrapolate: 'clamp',
  });

  // Left half stays at -180° until progress > 50, then rotates to 0°
  const leftRotation = progressAnim.interpolate({
    inputRange: [0, 50, 100],
    outputRange: ['-180deg', '-180deg', '0deg'],
    extrapolate: 'clamp',
  });

  return (
    <View
      style={[{ width: size, height: size }, style]}
      accessibilityLabel={`Security score: ${clampedScore} out of 100`}
      accessibilityRole="progressbar"
      accessibilityValue={{ min: 0, max: 100, now: clampedScore }}
    >
      {/* Background track */}
      <View
        style={[
          styles.track,
          {
            width: size,
            height: size,
            borderRadius: halfSize,
            borderWidth: strokeWidth,
            borderColor: colors.border,
          },
        ]}
      />

      {/* Right half-circle clip */}
      <View
        style={[
          styles.halfCircleContainer,
          { width: halfSize, height: size, left: halfSize, overflow: 'hidden' },
        ]}
      >
        <Animated.View
          style={[
            {
              width: size,
              height: size,
              borderRadius: halfSize,
              borderWidth: strokeWidth,
              borderColor: ringColor,
              position: 'absolute',
              right: 0,
            },
            { transform: [{ rotate: rightRotation }] },
          ]}
        />
      </View>

      {/* Left half-circle clip */}
      <View
        style={[
          styles.halfCircleContainer,
          { width: halfSize, height: size, left: 0, overflow: 'hidden' },
        ]}
      >
        <Animated.View
          style={[
            {
              width: size,
              height: size,
              borderRadius: halfSize,
              borderWidth: strokeWidth,
              borderColor: ringColor,
              position: 'absolute',
              left: 0,
            },
            { transform: [{ rotate: leftRotation }] },
          ]}
        />
      </View>

      {/* Center score text */}
      <View
        style={[
          styles.centerContent,
          {
            width: innerSize,
            height: innerSize,
            borderRadius: innerSize / 2,
            top: strokeWidth,
            left: strokeWidth,
          },
        ]}
      >
        <Text style={[styles.scoreText, { color: ringColor }]}>
          {clampedScore}
        </Text>
      </View>
    </View>
  );
};

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  track: {
    position: 'absolute',
    top: 0,
    left: 0,
  },
  halfCircleContainer: {
    position: 'absolute',
    top: 0,
  },
  centerContent: {
    position: 'absolute',
    backgroundColor: colors.surface,
    alignItems: 'center',
    justifyContent: 'center',
  },
  scoreText: {
    fontSize: 28,
    fontWeight: 'bold',
  },
});

export default ScoreRing;

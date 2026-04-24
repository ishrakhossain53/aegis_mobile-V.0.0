/**
 * AlertItem — Aegis Personal Cybersecurity Companion
 *
 * Displays a security threat alert with:
 *   - Left accent bar: critical/high → red, medium → amber, low → neutral
 *   - Title, description, and formatted timestamp
 *   - Dismiss action that marks the alert resolved in the data store
 *   - Resolved alerts render at 0.4 opacity and remain visible in the list
 *
 * Requirements: 22.1, 22.2, 22.3, 22.4, 22.5
 */

import React, { useCallback } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ViewStyle,
} from 'react-native';
import { Threat } from '../types/index';
import { colors } from '../theme/colors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AlertItemProps {
  threat: Threat;
  onDismiss?: (id: string) => void;
  style?: ViewStyle;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getAccentColor(severity: Threat['severity']): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return '#FF3B30';
    case 'medium':
      return '#FFB800';
    case 'low':
    default:
      return colors.neutral;
  }
}

function getSeverityLabel(severity: Threat['severity']): string {
  return severity.toUpperCase();
}

function formatTimestamp(timestamp: number): string {
  return new Date(timestamp).toLocaleString();
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const AlertItem: React.FC<AlertItemProps> = ({
  threat,
  onDismiss,
  style,
}) => {
  const accentColor = getAccentColor(threat.severity);

  const handleDismiss = useCallback(() => {
    onDismiss?.(threat.id);
  }, [threat.id, onDismiss]);

  return (
    <View
      style={[
        styles.container,
        threat.resolved && styles.resolvedContainer,
        style,
      ]}
      accessibilityLabel={`${getSeverityLabel(threat.severity)} alert: ${threat.description}. Detected at ${formatTimestamp(threat.detectedAt)}.${threat.resolved ? ' Resolved.' : ''}`}
      accessibilityRole="alert"
    >
      {/* Left accent bar */}
      <View
        style={[styles.accentBar, { backgroundColor: accentColor }]}
        accessibilityElementsHidden
      />

      {/* Content */}
      <View style={styles.content}>
        {/* Header: severity badge + title */}
        <View style={styles.header}>
          <View
            style={[styles.severityBadge, { backgroundColor: `${accentColor}26` }]}
          >
            <Text style={[styles.severityText, { color: accentColor }]}>
              {getSeverityLabel(threat.severity)}
            </Text>
          </View>
          {threat.resolved && (
            <View style={styles.resolvedBadge}>
              <Text style={styles.resolvedText}>RESOLVED</Text>
            </View>
          )}
        </View>

        {/* Description */}
        <Text style={styles.description} numberOfLines={3}>
          {threat.description}
        </Text>

        {/* App info (if applicable) */}
        {threat.appName && (
          <Text style={styles.appName} numberOfLines={1}>
            App: {threat.appName}
          </Text>
        )}

        {/* Footer: timestamp + dismiss button */}
        <View style={styles.footer}>
          <Text style={styles.timestamp}>
            {formatTimestamp(threat.detectedAt)}
          </Text>

          {!threat.resolved && onDismiss && (
            <TouchableOpacity
              onPress={handleDismiss}
              style={styles.dismissButton}
              accessibilityLabel={`Dismiss alert: ${threat.description}`}
              accessibilityRole="button"
              accessibilityHint="Marks this alert as resolved"
            >
              <Text style={styles.dismissText}>Dismiss</Text>
            </TouchableOpacity>
          )}
        </View>
      </View>
    </View>
  );
};

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    backgroundColor: colors.surface,
    borderRadius: 10,
    overflow: 'hidden',
    borderWidth: 1,
    borderColor: colors.border,
  },
  resolvedContainer: {
    opacity: 0.4,
  },
  accentBar: {
    width: 4,
    alignSelf: 'stretch',
  },
  content: {
    flex: 1,
    padding: 12,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 6,
    gap: 8,
  },
  severityBadge: {
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 4,
  },
  severityText: {
    fontSize: 10,
    fontWeight: '700',
    fontFamily: 'monospace',
    letterSpacing: 0.5,
  },
  resolvedBadge: {
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 4,
    backgroundColor: `${colors.neutral}26`,
  },
  resolvedText: {
    fontSize: 10,
    fontWeight: '700',
    fontFamily: 'monospace',
    color: colors.neutral,
    letterSpacing: 0.5,
  },
  description: {
    color: colors.textPrimary,
    fontSize: 14,
    lineHeight: 20,
    marginBottom: 6,
  },
  appName: {
    color: colors.textSecondary,
    fontSize: 12,
    marginBottom: 6,
  },
  footer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 4,
  },
  timestamp: {
    color: colors.textMuted,
    fontSize: 11,
  },
  dismissButton: {
    paddingHorizontal: 12,
    paddingVertical: 4,
    borderRadius: 6,
    backgroundColor: colors.surfaceElevated,
    borderWidth: 1,
    borderColor: colors.border,
  },
  dismissText: {
    color: colors.textSecondary,
    fontSize: 12,
    fontWeight: '600',
  },
});

export default AlertItem;

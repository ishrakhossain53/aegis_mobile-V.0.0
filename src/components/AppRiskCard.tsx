/**
 * AppRiskCard — Aegis Personal Cybersecurity Companion
 *
 * Displays an installed app's risk profile:
 *   - App name and package name
 *   - SecurityBadge for the risk level
 *   - Total permission count
 *   - Dangerous permission count (visually distinct)
 *
 * Tapping opens the full permission detail view for that app.
 *
 * Requirements: 23.1, 23.2, 23.3
 */

import React, { useCallback } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ViewStyle,
} from 'react-native';
import { InstalledApp } from '../types/index';
import { SecurityBadge } from './SecurityBadge';
import { colors } from '../theme/colors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AppRiskCardProps {
  app: InstalledApp;
  onPress?: (app: InstalledApp) => void;
  style?: ViewStyle;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Maps InstalledApp.riskLevel to SecurityBadge status.
 * 'medium' maps to 'warning' since SecurityBadge only has safe/warning/critical.
 */
function riskLevelToBadgeStatus(
  riskLevel: InstalledApp['riskLevel'],
): 'safe' | 'warning' | 'critical' {
  switch (riskLevel) {
    case 'low':
      return 'safe';
    case 'medium':
      return 'warning';
    case 'high':
    case 'critical':
      return 'critical';
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const AppRiskCard: React.FC<AppRiskCardProps> = ({
  app,
  onPress,
  style,
}) => {
  const dangerousCount = app.permissions.filter((p) => p.dangerous).length;
  const totalCount = app.permissions.length;
  const badgeStatus = riskLevelToBadgeStatus(app.riskLevel);

  const handlePress = useCallback(() => {
    onPress?.(app);
  }, [app, onPress]);

  return (
    <TouchableOpacity
      onPress={handlePress}
      activeOpacity={0.75}
      style={[styles.container, style]}
      accessibilityLabel={`${app.name}, package ${app.packageName}, risk level ${app.riskLevel}, ${totalCount} permissions, ${dangerousCount} dangerous`}
      accessibilityRole="button"
      accessibilityHint="Tap to view full permission details"
    >
      {/* Top row: app name + badge */}
      <View style={styles.topRow}>
        <View style={styles.appInfo}>
          {/* App icon placeholder */}
          <View style={styles.appIconPlaceholder} accessibilityElementsHidden>
            <Text style={styles.appIconText}>
              {app.name.charAt(0).toUpperCase()}
            </Text>
          </View>

          <View style={styles.nameBlock}>
            <Text style={styles.appName} numberOfLines={1}>
              {app.name}
            </Text>
            <Text style={styles.packageName} numberOfLines={1}>
              {app.packageName}
            </Text>
          </View>
        </View>

        <SecurityBadge status={badgeStatus} />
      </View>

      {/* Bottom row: permission counts */}
      <View style={styles.permissionRow}>
        <View style={styles.permissionStat}>
          <Text style={styles.permissionCount}>{totalCount}</Text>
          <Text style={styles.permissionLabel}>Permissions</Text>
        </View>

        <View style={styles.divider} accessibilityElementsHidden />

        <View style={styles.permissionStat}>
          <Text
            style={[
              styles.permissionCount,
              dangerousCount > 0 && styles.dangerousCount,
            ]}
          >
            {dangerousCount}
          </Text>
          <Text
            style={[
              styles.permissionLabel,
              dangerousCount > 0 && styles.dangerousLabel,
            ]}
          >
            Dangerous
          </Text>
        </View>

        <View style={styles.divider} accessibilityElementsHidden />

        <View style={styles.permissionStat}>
          <Text style={styles.permissionCount}>{app.riskScore}</Text>
          <Text style={styles.permissionLabel}>Risk Score</Text>
        </View>

        {/* Chevron */}
        <Text style={styles.chevron} accessibilityElementsHidden>
          ›
        </Text>
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
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: colors.border,
  },
  topRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  appInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
    marginRight: 10,
  },
  appIconPlaceholder: {
    width: 40,
    height: 40,
    borderRadius: 10,
    backgroundColor: colors.surfaceElevated,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 10,
    borderWidth: 1,
    borderColor: colors.border,
  },
  appIconText: {
    color: colors.textSecondary,
    fontSize: 18,
    fontWeight: '700',
  },
  nameBlock: {
    flex: 1,
  },
  appName: {
    color: colors.textPrimary,
    fontSize: 15,
    fontWeight: '600',
    marginBottom: 2,
  },
  packageName: {
    color: colors.textMuted,
    fontSize: 11,
    fontFamily: 'monospace',
  },
  permissionRow: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.surfaceElevated,
    borderRadius: 8,
    paddingVertical: 10,
    paddingHorizontal: 12,
  },
  permissionStat: {
    flex: 1,
    alignItems: 'center',
  },
  permissionCount: {
    color: colors.textPrimary,
    fontSize: 18,
    fontWeight: '700',
    marginBottom: 2,
  },
  dangerousCount: {
    color: '#FF3B30',
  },
  permissionLabel: {
    color: colors.textMuted,
    fontSize: 10,
    fontWeight: '500',
  },
  dangerousLabel: {
    color: '#FF3B30',
  },
  divider: {
    width: 1,
    height: 28,
    backgroundColor: colors.border,
    marginHorizontal: 4,
  },
  chevron: {
    color: colors.textMuted,
    fontSize: 22,
    marginLeft: 8,
  },
});

export default AppRiskCard;

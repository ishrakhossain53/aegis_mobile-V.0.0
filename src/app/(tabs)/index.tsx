/**
 * index.tsx — Dashboard Screen
 *
 * Main security overview screen displaying:
 *  - ScoreRing (size 160) with overall score and level label
 *  - 5 ModuleHealthBar components (Vault Health, Network Safety, App Risk,
 *    OS Hygiene, Breach Status)
 *  - Last 3 AlertItem components in "Recent Alerts" with "View All" link
 *  - Quick action row: "Scan Network", "Check Breaches", "Add Credential"
 *  - Pull-to-refresh recalculates security score; ring animates on refresh
 *
 * Requirements: 11.1, 11.7, 26.1
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  ScrollView,
  RefreshControl,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  ActivityIndicator,
} from 'react-native';
import { router } from 'expo-router';
import { ScoreRing } from '../../components/ScoreRing';
import { ModuleHealthBar } from '../../components/ModuleHealthBar';
import { AlertItem } from '../../components/AlertItem';
import { securityScoreService } from '../../services/SecurityScoreService';
import { threatMonitorService } from '../../services/ThreatMonitorService';
import { sessionLockService } from '../../services/SessionLockService';
import { SecurityScore, ScoreBreakdown, Threat } from '../../types/index';
import { colors } from '../../theme/colors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DashboardState {
  score: SecurityScore | null;
  breakdown: ScoreBreakdown | null;
  recentAlerts: Threat[];
  isLoading: boolean;
  isRefreshing: boolean;
  error: string | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getLevelLabel(level: SecurityScore['level']): string {
  switch (level) {
    case 'excellent': return 'Excellent';
    case 'good': return 'Good';
    case 'fair': return 'Fair';
    case 'poor': return 'Poor';
    case 'critical': return 'Critical';
  }
}

function getLevelColor(level: SecurityScore['level']): string {
  switch (level) {
    case 'excellent':
    case 'good': return colors.safe;
    case 'fair': return colors.warning;
    case 'poor':
    case 'critical': return colors.danger;
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function DashboardScreen() {
  const [state, setState] = useState<DashboardState>({
    score: null,
    breakdown: null,
    recentAlerts: [],
    isLoading: true,
    isRefreshing: false,
    error: null,
  });

  // -------------------------------------------------------------------------
  // Data loading
  // -------------------------------------------------------------------------

  const loadDashboardData = useCallback(async (isRefresh = false) => {
    setState((prev) => ({
      ...prev,
      isLoading: !isRefresh,
      isRefreshing: isRefresh,
      error: null,
    }));

    try {
      const [score, breakdown, threats] = await Promise.all([
        securityScoreService.calculateSecurityScore(),
        securityScoreService.getScoreBreakdown(),
        threatMonitorService.getActiveThreats(),
      ]);

      setState({
        score,
        breakdown,
        recentAlerts: threats.slice(0, 3),
        isLoading: false,
        isRefreshing: false,
        error: null,
      });
    } catch {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        isRefreshing: false,
        error: 'Failed to load security data. Pull to refresh.',
      }));
    }
  }, []);

  useEffect(() => {
    void loadDashboardData();
  }, [loadDashboardData]);

  // -------------------------------------------------------------------------
  // Session activity tracking
  // -------------------------------------------------------------------------

  const handleInteraction = useCallback(() => {
    sessionLockService.resetTimer();
  }, []);

  // -------------------------------------------------------------------------
  // Alert dismiss
  // -------------------------------------------------------------------------

  const handleDismissAlert = useCallback(async (id: string) => {
    await threatMonitorService.resolveThreats([id]);
    setState((prev) => ({
      ...prev,
      recentAlerts: prev.recentAlerts.map((t) =>
        t.id === id ? { ...t, resolved: true } : t,
      ),
    }));
  }, []);

  // -------------------------------------------------------------------------
  // Quick actions
  // -------------------------------------------------------------------------

  const handleScanNetwork = useCallback(() => {
    handleInteraction();
    router.push('/(tabs)/network');
  }, [handleInteraction]);

  const handleCheckBreaches = useCallback(() => {
    handleInteraction();
    router.push('/(tabs)/alerts');
  }, [handleInteraction]);

  const handleAddCredential = useCallback(() => {
    handleInteraction();
    router.push('/(tabs)/vault');
  }, [handleInteraction]);

  // -------------------------------------------------------------------------
  // Module navigation
  // -------------------------------------------------------------------------

  const navigateToVault = useCallback(() => {
    handleInteraction();
    router.push('/(tabs)/vault');
  }, [handleInteraction]);

  const navigateToNetwork = useCallback(() => {
    handleInteraction();
    router.push('/(tabs)/network');
  }, [handleInteraction]);

  const navigateToAudit = useCallback(() => {
    handleInteraction();
    router.push('/(tabs)/audit');
  }, [handleInteraction]);

  const navigateToAlerts = useCallback(() => {
    handleInteraction();
    router.push('/(tabs)/alerts');
  }, [handleInteraction]);

  // -------------------------------------------------------------------------
  // Loading state
  // -------------------------------------------------------------------------

  if (state.isLoading) {
    return (
      <SafeAreaView style={styles.safeArea}>
        <View style={styles.loadingContainer}>
          <ActivityIndicator
            size="large"
            color={colors.primary}
            accessibilityLabel="Loading security data…"
          />
          <Text style={styles.loadingText}>Calculating security score…</Text>
        </View>
      </SafeAreaView>
    );
  }

  // -------------------------------------------------------------------------
  // Main render
  // -------------------------------------------------------------------------

  const { score, breakdown, recentAlerts } = state;

  return (
    <SafeAreaView style={styles.safeArea}>
      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.scrollContent}
        refreshControl={
          <RefreshControl
            refreshing={state.isRefreshing}
            onRefresh={() => loadDashboardData(true)}
            tintColor={colors.primary}
            title="Recalculating score…"
            titleColor={colors.textMuted}
          />
        }
        onScrollBeginDrag={handleInteraction}
        showsVerticalScrollIndicator={false}
      >
        {/* Header */}
        <View style={styles.header}>
          <Text style={styles.headerTitle} accessibilityRole="header">
            Security Overview
          </Text>
          <Text style={styles.headerSubtitle}>
            {score
              ? `Updated ${new Date(score.lastUpdated).toLocaleTimeString()}`
              : 'Pull to refresh'}
          </Text>
        </View>

        {/* Error banner */}
        {state.error && (
          <View style={styles.errorBanner} accessibilityRole="alert">
            <Text style={styles.errorText}>{state.error}</Text>
          </View>
        )}

        {/* Score Ring */}
        <View style={styles.scoreSection}>
          <ScoreRing
            score={score?.overall ?? 0}
            size={160}
            strokeWidth={12}
            style={styles.scoreRing}
          />
          {score && (
            <View style={styles.scoreLabelContainer}>
              <Text
                style={[styles.scoreLevel, { color: getLevelColor(score.level) }]}
                accessibilityLabel={`Security level: ${getLevelLabel(score.level)}`}
              >
                {getLevelLabel(score.level)}
              </Text>
              <Text style={styles.scoreDescription}>
                Overall Security Score
              </Text>
            </View>
          )}
        </View>

        {/* Module Health Bars */}
        {breakdown && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>Module Health</Text>
            <View style={styles.moduleList}>
              <ModuleHealthBar
                label="Vault Health"
                score={breakdown.vaultHealth.score}
                onPress={navigateToVault}
                style={styles.moduleBar}
              />
              <ModuleHealthBar
                label="Network Safety"
                score={breakdown.networkSafety.score}
                onPress={navigateToNetwork}
                style={styles.moduleBar}
              />
              <ModuleHealthBar
                label="App Risk"
                score={breakdown.appRisk.score}
                onPress={navigateToAudit}
                style={styles.moduleBar}
              />
              <ModuleHealthBar
                label="OS Hygiene"
                score={breakdown.osHygiene.score}
                style={styles.moduleBar}
              />
              <ModuleHealthBar
                label="Breach Status"
                score={breakdown.breachStatus.score}
                onPress={navigateToAlerts}
                style={styles.moduleBar}
              />
            </View>
          </View>
        )}

        {/* Quick Actions */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Quick Actions</Text>
          <View style={styles.quickActions}>
            <TouchableOpacity
              style={styles.quickActionButton}
              onPress={handleScanNetwork}
              accessibilityLabel="Scan network for threats"
              accessibilityRole="button"
            >
              <Text style={styles.quickActionIcon}>📡</Text>
              <Text style={styles.quickActionLabel}>Scan Network</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.quickActionButton}
              onPress={handleCheckBreaches}
              accessibilityLabel="Check for data breaches"
              accessibilityRole="button"
            >
              <Text style={styles.quickActionIcon}>🔍</Text>
              <Text style={styles.quickActionLabel}>Check Breaches</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.quickActionButton}
              onPress={handleAddCredential}
              accessibilityLabel="Add a new credential to the vault"
              accessibilityRole="button"
            >
              <Text style={styles.quickActionIcon}>➕</Text>
              <Text style={styles.quickActionLabel}>Add Credential</Text>
            </TouchableOpacity>
          </View>
        </View>

        {/* Recent Alerts */}
        <View style={styles.section}>
          <View style={styles.sectionHeader}>
            <Text style={styles.sectionTitle}>Recent Alerts</Text>
            <TouchableOpacity
              onPress={navigateToAlerts}
              accessibilityLabel="View all alerts"
              accessibilityRole="button"
            >
              <Text style={styles.viewAllLink}>View All</Text>
            </TouchableOpacity>
          </View>

          {recentAlerts.length === 0 ? (
            <View style={styles.emptyAlerts}>
              <Text style={styles.emptyAlertsIcon}>✅</Text>
              <Text style={styles.emptyAlertsText}>All Clear</Text>
              <Text style={styles.emptyAlertsSubtext}>
                No active security alerts
              </Text>
            </View>
          ) : (
            <View style={styles.alertList}>
              {recentAlerts.map((threat) => (
                <AlertItem
                  key={threat.id}
                  threat={threat}
                  onDismiss={handleDismissAlert}
                  style={styles.alertItem}
                />
              ))}
            </View>
          )}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: colors.background,
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    paddingHorizontal: 16,
    paddingBottom: 32,
  },
  loadingContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 16,
  },
  loadingText: {
    color: colors.textMuted,
    fontSize: 14,
  },

  // Header
  header: {
    paddingTop: 16,
    paddingBottom: 8,
  },
  headerTitle: {
    color: colors.textPrimary,
    fontSize: 28,
    fontWeight: '700',
  },
  headerSubtitle: {
    color: colors.textMuted,
    fontSize: 12,
    marginTop: 2,
  },

  // Error
  errorBanner: {
    backgroundColor: `${colors.danger}1A`,
    borderRadius: 10,
    padding: 12,
    marginVertical: 8,
    borderWidth: 1,
    borderColor: `${colors.danger}40`,
  },
  errorText: {
    color: colors.danger,
    fontSize: 13,
    textAlign: 'center',
  },

  // Score section
  scoreSection: {
    alignItems: 'center',
    paddingVertical: 24,
  },
  scoreRing: {
    marginBottom: 16,
  },
  scoreLabelContainer: {
    alignItems: 'center',
  },
  scoreLevel: {
    fontSize: 22,
    fontWeight: '700',
    marginBottom: 4,
  },
  scoreDescription: {
    color: colors.textMuted,
    fontSize: 13,
  },

  // Sections
  section: {
    marginBottom: 24,
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  sectionTitle: {
    color: colors.textPrimary,
    fontSize: 17,
    fontWeight: '700',
    marginBottom: 12,
  },
  viewAllLink: {
    color: colors.primary,
    fontSize: 14,
    fontWeight: '600',
  },

  // Module bars
  moduleList: {
    gap: 8,
  },
  moduleBar: {
    // spacing handled by gap
  },

  // Quick actions
  quickActions: {
    flexDirection: 'row',
    gap: 10,
  },
  quickActionButton: {
    flex: 1,
    backgroundColor: colors.surface,
    borderRadius: 12,
    paddingVertical: 16,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: colors.border,
    gap: 6,
  },
  quickActionIcon: {
    fontSize: 24,
  },
  quickActionLabel: {
    color: colors.textSecondary,
    fontSize: 11,
    fontWeight: '600',
    textAlign: 'center',
  },

  // Alerts
  alertList: {
    gap: 8,
  },
  alertItem: {
    // spacing handled by gap
  },
  emptyAlerts: {
    alignItems: 'center',
    paddingVertical: 24,
    backgroundColor: colors.surface,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
  },
  emptyAlertsIcon: {
    fontSize: 32,
    marginBottom: 8,
  },
  emptyAlertsText: {
    color: colors.safe,
    fontSize: 16,
    fontWeight: '700',
    marginBottom: 4,
  },
  emptyAlertsSubtext: {
    color: colors.textMuted,
    fontSize: 13,
  },
});

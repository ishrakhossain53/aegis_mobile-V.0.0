/**
 * index.tsx — Dashboard Screen
 *
 * Main security overview with dark/light theme support.
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
import { useTheme } from '../../theme/ThemeContext';

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

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function DashboardScreen() {
  const { colors } = useTheme();

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

  const handleInteraction = useCallback(() => {
    sessionLockService.resetTimer();
  }, []);

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

  const navigateToVault = useCallback(() => { handleInteraction(); router.push('/(tabs)/vault'); }, [handleInteraction]);
  const navigateToNetwork = useCallback(() => { handleInteraction(); router.push('/(tabs)/network'); }, [handleInteraction]);
  const navigateToAudit = useCallback(() => { handleInteraction(); router.push('/(tabs)/audit'); }, [handleInteraction]);
  const navigateToAlerts = useCallback(() => { handleInteraction(); router.push('/(tabs)/alerts'); }, [handleInteraction]);

  // -------------------------------------------------------------------------
  // Score color
  // -------------------------------------------------------------------------

  function getLevelColor(level: SecurityScore['level']): string {
    switch (level) {
      case 'excellent':
      case 'good': return colors.safe;
      case 'fair': return colors.warning;
      case 'poor':
      case 'critical': return colors.danger;
    }
  }

  // -------------------------------------------------------------------------
  // Loading
  // -------------------------------------------------------------------------

  if (state.isLoading) {
    return (
      <SafeAreaView style={[styles.safeArea, { backgroundColor: colors.background }]}>
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={colors.primary} />
          <Text style={[styles.loadingText, { color: colors.textMuted }]}>
            Calculating security score…
          </Text>
        </View>
      </SafeAreaView>
    );
  }

  const { score, breakdown, recentAlerts } = state;

  // -------------------------------------------------------------------------
  // Main render
  // -------------------------------------------------------------------------

  return (
    <SafeAreaView style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.scrollContent}
        refreshControl={
          <RefreshControl
            refreshing={state.isRefreshing}
            onRefresh={() => loadDashboardData(true)}
            tintColor={colors.primary}
          />
        }
        onScrollBeginDrag={handleInteraction}
        showsVerticalScrollIndicator={false}
      >
        {/* Header */}
        <View style={styles.header}>
          <View>
            <Text style={[styles.headerTitle, { color: colors.textPrimary }]}
              accessibilityRole="header">
              Security Overview
            </Text>
            <Text style={[styles.headerSubtitle, { color: colors.textMuted }]}>
              {score
                ? `Updated ${new Date(score.lastUpdated).toLocaleTimeString()}`
                : 'Pull to refresh'}
            </Text>
          </View>
        </View>

        {/* Error banner */}
        {state.error && (
          <View style={[styles.errorBanner, {
            backgroundColor: `${colors.danger}18`,
            borderColor: `${colors.danger}35`,
          }]} accessibilityRole="alert">
            <Text style={[styles.errorText, { color: colors.danger }]}>{state.error}</Text>
          </View>
        )}

        {/* Score Ring Card */}
        <View style={[styles.scoreCard, {
          backgroundColor: colors.surface,
          borderColor: colors.border,
        }]}>
          <ScoreRing
            score={score?.overall ?? 0}
            size={148}
            strokeWidth={11}
          />
          {score && (
            <View style={styles.scoreLabelContainer}>
              <Text style={[styles.scoreValue, { color: colors.textPrimary }]}>
                {score.overall}
              </Text>
              <Text style={[styles.scoreLevel, { color: getLevelColor(score.level) }]}>
                {getLevelLabel(score.level)}
              </Text>
              <Text style={[styles.scoreDescription, { color: colors.textMuted }]}>
                Security Score
              </Text>
            </View>
          )}
        </View>

        {/* Module Health */}
        {breakdown && (
          <View style={styles.section}>
            <Text style={[styles.sectionTitle, { color: colors.textPrimary }]}>
              Module Health
            </Text>
            <View style={[styles.moduleCard, {
              backgroundColor: colors.surface,
              borderColor: colors.border,
            }]}>
              <ModuleHealthBar label="Vault Health" score={breakdown.vaultHealth.score} onPress={navigateToVault} />
              <View style={[styles.moduleDivider, { backgroundColor: colors.border }]} />
              <ModuleHealthBar label="Network Safety" score={breakdown.networkSafety.score} onPress={navigateToNetwork} />
              <View style={[styles.moduleDivider, { backgroundColor: colors.border }]} />
              <ModuleHealthBar label="App Risk" score={breakdown.appRisk.score} onPress={navigateToAudit} />
              <View style={[styles.moduleDivider, { backgroundColor: colors.border }]} />
              <ModuleHealthBar label="OS Hygiene" score={breakdown.osHygiene.score} />
              <View style={[styles.moduleDivider, { backgroundColor: colors.border }]} />
              <ModuleHealthBar label="Breach Status" score={breakdown.breachStatus.score} onPress={navigateToAlerts} />
            </View>
          </View>
        )}

        {/* Quick Actions */}
        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: colors.textPrimary }]}>
            Quick Actions
          </Text>
          <View style={styles.quickActions}>
            <QuickActionButton
              emoji="📡"
              label="Scan Network"
              onPress={handleScanNetwork}
              colors={colors}
            />
            <QuickActionButton
              emoji="🔍"
              label="Check Breaches"
              onPress={handleCheckBreaches}
              colors={colors}
            />
            <QuickActionButton
              emoji="➕"
              label="Add Credential"
              onPress={handleAddCredential}
              colors={colors}
            />
          </View>
        </View>

        {/* Recent Alerts */}
        <View style={styles.section}>
          <View style={styles.sectionHeader}>
            <Text style={[styles.sectionTitle, { color: colors.textPrimary }]}>
              Recent Alerts
            </Text>
            <TouchableOpacity onPress={navigateToAlerts} accessibilityRole="button">
              <Text style={[styles.viewAllLink, { color: colors.primary }]}>View All</Text>
            </TouchableOpacity>
          </View>

          {recentAlerts.length === 0 ? (
            <View style={[styles.emptyAlerts, {
              backgroundColor: `${colors.safe}12`,
              borderColor: `${colors.safe}30`,
            }]}>
              <Text style={styles.emptyAlertsIcon}>✅</Text>
              <Text style={[styles.emptyAlertsText, { color: colors.safe }]}>All Clear</Text>
              <Text style={[styles.emptyAlertsSubtext, { color: colors.textMuted }]}>
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
// QuickActionButton
// ---------------------------------------------------------------------------

interface QuickActionButtonProps {
  emoji: string;
  label: string;
  onPress: () => void;
  colors: ReturnType<typeof useTheme>['colors'];
}

function QuickActionButton({ emoji, label, onPress, colors }: QuickActionButtonProps) {
  return (
    <TouchableOpacity
      style={[styles.quickActionButton, {
        backgroundColor: colors.surface,
        borderColor: colors.border,
      }]}
      onPress={onPress}
      accessibilityRole="button"
      accessibilityLabel={label}
    >
      <Text style={styles.quickActionIcon}>{emoji}</Text>
      <Text style={[styles.quickActionLabel, { color: colors.textSecondary }]}>{label}</Text>
    </TouchableOpacity>
  );
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  safeArea: { flex: 1 },
  scrollView: { flex: 1 },
  scrollContent: { paddingHorizontal: 16, paddingBottom: 32 },

  loadingContainer: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 16 },
  loadingText: { fontSize: 14 },

  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    paddingTop: 20,
    paddingBottom: 16,
  },
  headerTitle: { fontSize: 26, fontWeight: '800', letterSpacing: -0.3 },
  headerSubtitle: { fontSize: 12, marginTop: 3 },

  errorBanner: {
    borderRadius: 12,
    padding: 12,
    marginBottom: 12,
    borderWidth: 1,
  },
  errorText: { fontSize: 13, textAlign: 'center' },

  // Score card
  scoreCard: {
    borderRadius: 20,
    borderWidth: 1,
    padding: 24,
    alignItems: 'center',
    marginBottom: 20,
    flexDirection: 'row',
    gap: 24,
  },
  scoreLabelContainer: { flex: 1 },
  scoreValue: { fontSize: 48, fontWeight: '800', letterSpacing: -1, lineHeight: 52 },
  scoreLevel: { fontSize: 18, fontWeight: '700', marginTop: 2 },
  scoreDescription: { fontSize: 12, marginTop: 4 },

  // Sections
  section: { marginBottom: 20 },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  sectionTitle: { fontSize: 16, fontWeight: '700', marginBottom: 10, letterSpacing: -0.1 },
  viewAllLink: { fontSize: 13, fontWeight: '600' },

  // Module card
  moduleCard: {
    borderRadius: 16,
    borderWidth: 1,
    paddingVertical: 4,
    paddingHorizontal: 16,
  },
  moduleDivider: { height: StyleSheet.hairlineWidth, marginHorizontal: -16 },

  // Quick actions
  quickActions: { flexDirection: 'row', gap: 10 },
  quickActionButton: {
    flex: 1,
    borderRadius: 14,
    paddingVertical: 16,
    alignItems: 'center',
    borderWidth: 1,
    gap: 6,
  },
  quickActionIcon: { fontSize: 22 },
  quickActionLabel: { fontSize: 11, fontWeight: '600', textAlign: 'center' },

  // Alerts
  alertList: { gap: 8 },
  alertItem: {},
  emptyAlerts: {
    alignItems: 'center',
    paddingVertical: 28,
    borderRadius: 16,
    borderWidth: 1,
  },
  emptyAlertsIcon: { fontSize: 28, marginBottom: 8 },
  emptyAlertsText: { fontSize: 15, fontWeight: '700', marginBottom: 4 },
  emptyAlertsSubtext: { fontSize: 13 },
});

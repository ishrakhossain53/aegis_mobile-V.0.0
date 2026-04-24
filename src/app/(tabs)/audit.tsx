/**
 * audit.tsx — App Permission Audit Screen
 *
 * Displays:
 *  - Summary card: total apps, high-risk count, overall audit SecurityBadge
 *  - Sort control: By Risk (default) / By Name / By Install Date
 *  - FlatList of AppRiskCard components; high-risk apps (score ≥ 70) with
 *    red left border accent
 *  - Tapping card opens permission detail bottom sheet
 *  - "Re-audit" header button triggers fresh scan
 *
 * Requirements: 29.1, 29.2, 29.3, 29.4, 29.5
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  FlatList,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  Modal,
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import { AppRiskCard } from '../../components/AppRiskCard';
import { SecurityBadge } from '../../components/SecurityBadge';
import { permissionAuditorService } from '../../services/PermissionAuditorService';
import { sessionLockService } from '../../services/SessionLockService';
import { InstalledApp, AuditReport, AppPermission } from '../../types/index';
import { colors } from '../../theme/colors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SortMode = 'risk' | 'name' | 'installDate';

interface PermissionDetailSheet {
  visible: boolean;
  app: InstalledApp | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sortApps(apps: InstalledApp[], mode: SortMode): InstalledApp[] {
  const sorted = [...apps];
  switch (mode) {
    case 'risk':
      return sorted.sort((a, b) => b.riskScore - a.riskScore);
    case 'name':
      return sorted.sort((a, b) => a.name.localeCompare(b.name));
    case 'installDate':
      return sorted.sort((a, b) => b.installedDate - a.installedDate);
  }
}

function overallRiskToStatus(overallRisk: number): 'safe' | 'warning' | 'critical' {
  if (overallRisk >= 70) return 'critical';
  if (overallRisk >= 40) return 'warning';
  return 'safe';
}

function categoryLabel(category: AppPermission['category']): string {
  const labels: Record<AppPermission['category'], string> = {
    location: 'Location',
    camera: 'Camera',
    microphone: 'Microphone',
    contacts: 'Contacts',
    storage: 'Storage',
    phone: 'Phone',
    sms: 'SMS',
    calendar: 'Calendar',
    sensors: 'Sensors',
    network: 'Network',
  };
  return labels[category] ?? category;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AuditScreen() {
  const [apps, setApps] = useState<InstalledApp[]>([]);
  const [auditReport, setAuditReport] = useState<AuditReport | null>(null);
  const [sortMode, setSortMode] = useState<SortMode>('risk');
  const [isLoading, setIsLoading] = useState(true);
  const [isReauditing, setIsReauditing] = useState(false);
  const [detailSheet, setDetailSheet] = useState<PermissionDetailSheet>({
    visible: false,
    app: null,
  });

  // -------------------------------------------------------------------------
  // Data loading
  // -------------------------------------------------------------------------

  const loadAuditData = useCallback(async (forceRefresh = false) => {
    if (forceRefresh) {
      setIsReauditing(true);
    } else {
      setIsLoading(true);
    }

    try {
      const report = await permissionAuditorService.auditAllApps();
      const installedApps = await permissionAuditorService.getInstalledApps();
      setAuditReport(report);
      setApps(installedApps);
    } catch {
      setApps([]);
      setAuditReport(null);
    } finally {
      setIsLoading(false);
      setIsReauditing(false);
    }
  }, []);

  useEffect(() => {
    void loadAuditData();
  }, [loadAuditData]);

  // -------------------------------------------------------------------------
  // Session activity
  // -------------------------------------------------------------------------

  const handleInteraction = useCallback(() => {
    sessionLockService.resetTimer();
  }, []);

  // -------------------------------------------------------------------------
  // Card press → permission detail
  // -------------------------------------------------------------------------

  const handleCardPress = useCallback((app: InstalledApp) => {
    handleInteraction();
    setDetailSheet({ visible: true, app });
  }, [handleInteraction]);

  // -------------------------------------------------------------------------
  // Sorted apps
  // -------------------------------------------------------------------------

  const sortedApps = sortApps(apps, sortMode);

  // -------------------------------------------------------------------------
  // Loading state
  // -------------------------------------------------------------------------

  if (isLoading) {
    return (
      <SafeAreaView style={styles.safeArea}>
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={colors.primary} />
          <Text style={styles.loadingText}>Auditing installed apps…</Text>
        </View>
      </SafeAreaView>
    );
  }

  // -------------------------------------------------------------------------
  // Main render
  // -------------------------------------------------------------------------

  return (
    <SafeAreaView style={styles.safeArea}>
      {/* Header */}
      <View style={styles.header}>
        <View style={styles.headerRow}>
          <Text style={styles.headerTitle} accessibilityRole="header">
            App Audit
          </Text>
          <TouchableOpacity
            style={[styles.reauditButton, isReauditing && styles.reauditButtonDisabled]}
            onPress={() => {
              handleInteraction();
              void loadAuditData(true);
            }}
            disabled={isReauditing}
            accessibilityLabel="Re-audit all installed apps"
            accessibilityRole="button"
          >
            {isReauditing ? (
              <ActivityIndicator size="small" color={colors.primary} />
            ) : (
              <Text style={styles.reauditButtonText}>Re-audit</Text>
            )}
          </TouchableOpacity>
        </View>
      </View>

      <FlatList
        data={sortedApps}
        keyExtractor={(item) => item.id}
        onScrollBeginDrag={handleInteraction}
        showsVerticalScrollIndicator={false}
        ListHeaderComponent={() => (
          <View>
            {/* Summary Card */}
            {auditReport && (
              <View style={styles.summaryCard}>
                <View style={styles.summaryHeader}>
                  <Text style={styles.summaryTitle}>Audit Summary</Text>
                  <SecurityBadge
                    status={overallRiskToStatus(auditReport.overallRisk)}
                  />
                </View>

                <View style={styles.summaryStats}>
                  <SummaryStat
                    value={auditReport.totalApps}
                    label="Total Apps"
                    color={colors.textPrimary}
                  />
                  <View style={styles.statDivider} />
                  <SummaryStat
                    value={auditReport.highRiskApps}
                    label="High Risk"
                    color={auditReport.highRiskApps > 0 ? colors.danger : colors.safe}
                  />
                  <View style={styles.statDivider} />
                  <SummaryStat
                    value={auditReport.dangerousPermissions}
                    label="Dangerous Perms"
                    color={
                      auditReport.dangerousPermissions > 10
                        ? colors.danger
                        : auditReport.dangerousPermissions > 5
                        ? colors.warning
                        : colors.safe
                    }
                  />
                </View>

                {auditReport.recommendations.length > 0 && (
                  <View style={styles.recommendations}>
                    <Text style={styles.recommendationsTitle}>Recommendations</Text>
                    {auditReport.recommendations.slice(0, 3).map((rec, idx) => (
                      <View key={idx} style={styles.recommendationItem}>
                        <Text style={styles.recommendationBullet}>→</Text>
                        <Text style={styles.recommendationText}>{rec}</Text>
                      </View>
                    ))}
                  </View>
                )}
              </View>
            )}

            {/* Sort control */}
            <View style={styles.sortControl}>
              <Text style={styles.sortLabel}>Sort by:</Text>
              <View style={styles.sortButtons}>
                {(
                  [
                    { key: 'risk', label: 'Risk' },
                    { key: 'name', label: 'Name' },
                    { key: 'installDate', label: 'Install Date' },
                  ] as { key: SortMode; label: string }[]
                ).map((option) => (
                  <TouchableOpacity
                    key={option.key}
                    style={[
                      styles.sortButton,
                      sortMode === option.key && styles.sortButtonActive,
                    ]}
                    onPress={() => {
                      handleInteraction();
                      setSortMode(option.key);
                    }}
                    accessibilityLabel={`Sort by ${option.label}`}
                    accessibilityRole="button"
                    accessibilityState={{ selected: sortMode === option.key }}
                  >
                    <Text
                      style={[
                        styles.sortButtonText,
                        sortMode === option.key && styles.sortButtonTextActive,
                      ]}
                    >
                      {option.label}
                    </Text>
                  </TouchableOpacity>
                ))}
              </View>
            </View>
          </View>
        )}
        renderItem={({ item }) => (
          <View
            style={[
              styles.cardWrapper,
              item.riskScore >= 70 && styles.highRiskCardWrapper,
            ]}
          >
            <AppRiskCard
              app={item}
              onPress={handleCardPress}
              style={styles.appCard}
            />
          </View>
        )}
        ListEmptyComponent={() => (
          <View style={styles.emptyState}>
            <Text style={styles.emptyIcon}>📱</Text>
            <Text style={styles.emptyTitle}>No Apps Found</Text>
            <Text style={styles.emptySubtitle}>
              App enumeration is not available on this platform
            </Text>
          </View>
        )}
        contentContainerStyle={styles.listContent}
        ItemSeparatorComponent={() => <View style={styles.separator} />}
      />

      {/* Permission Detail Bottom Sheet */}
      <Modal
        visible={detailSheet.visible}
        animationType="slide"
        presentationStyle="pageSheet"
        onRequestClose={() => setDetailSheet({ visible: false, app: null })}
      >
        <SafeAreaView style={styles.modalSafeArea}>
          <View style={styles.modalHeader}>
            <View style={styles.modalTitleBlock}>
              <Text style={styles.modalTitle} numberOfLines={1}>
                {detailSheet.app?.name ?? 'App Permissions'}
              </Text>
              <Text style={styles.modalSubtitle} numberOfLines={1}>
                {detailSheet.app?.packageName}
              </Text>
            </View>
            <TouchableOpacity
              onPress={() => setDetailSheet({ visible: false, app: null })}
              accessibilityLabel="Close permission details"
              accessibilityRole="button"
            >
              <Text style={styles.modalClose}>✕</Text>
            </TouchableOpacity>
          </View>

          {detailSheet.app && (
            <ScrollView style={styles.modalContent}>
              {/* Risk summary */}
              <View style={styles.riskSummary}>
                <View style={styles.riskScoreBlock}>
                  <Text style={styles.riskScoreValue}>
                    {detailSheet.app.riskScore}
                  </Text>
                  <Text style={styles.riskScoreLabel}>Risk Score</Text>
                </View>
                <SecurityBadge
                  status={
                    detailSheet.app.riskScore >= 70
                      ? 'critical'
                      : detailSheet.app.riskScore >= 40
                      ? 'warning'
                      : 'safe'
                  }
                />
              </View>

              {/* Permission list grouped by category */}
              <Text style={styles.permissionsTitle}>
                Permissions ({detailSheet.app.permissions.length})
              </Text>

              {detailSheet.app.permissions.length === 0 ? (
                <Text style={styles.noPermissionsText}>No permissions declared</Text>
              ) : (
                detailSheet.app.permissions.map((perm, idx) => (
                  <View key={idx} style={styles.permissionRow}>
                    <View style={styles.permissionLeft}>
                      <Text style={styles.permissionName} numberOfLines={1}>
                        {perm.name.split('.').pop() ?? perm.name}
                      </Text>
                      <Text style={styles.permissionCategory}>
                        {categoryLabel(perm.category)}
                      </Text>
                    </View>
                    {perm.dangerous && (
                      <View style={styles.dangerousBadge}>
                        <Text style={styles.dangerousBadgeText}>DANGEROUS</Text>
                      </View>
                    )}
                  </View>
                ))
              )}
            </ScrollView>
          )}
        </SafeAreaView>
      </Modal>
    </SafeAreaView>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface SummaryStatProps {
  value: number;
  label: string;
  color: string;
}

const SummaryStat: React.FC<SummaryStatProps> = ({ value, label, color }) => (
  <View style={summaryStyles.stat}>
    <Text style={[summaryStyles.value, { color }]}>{value}</Text>
    <Text style={summaryStyles.label}>{label}</Text>
  </View>
);

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: colors.background,
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
  header: {
    paddingHorizontal: 16,
    paddingTop: 16,
    paddingBottom: 8,
  },
  headerRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  headerTitle: {
    color: colors.textPrimary,
    fontSize: 28,
    fontWeight: '700',
  },
  reauditButton: {
    paddingHorizontal: 14,
    paddingVertical: 7,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: colors.primary,
    minWidth: 80,
    alignItems: 'center',
  },
  reauditButtonDisabled: {
    opacity: 0.5,
  },
  reauditButtonText: {
    color: colors.primary,
    fontSize: 13,
    fontWeight: '700',
  },
  listContent: {
    paddingHorizontal: 16,
    paddingBottom: 32,
  },
  summaryCard: {
    backgroundColor: colors.surface,
    borderRadius: 14,
    padding: 16,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: colors.border,
  },
  summaryHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  summaryTitle: {
    color: colors.textPrimary,
    fontSize: 16,
    fontWeight: '700',
  },
  summaryStats: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.surfaceElevated,
    borderRadius: 10,
    paddingVertical: 12,
    paddingHorizontal: 8,
    marginBottom: 12,
  },
  statDivider: {
    width: 1,
    height: 32,
    backgroundColor: colors.border,
    marginHorizontal: 4,
  },
  recommendations: {
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: colors.border,
  },
  recommendationsTitle: {
    color: colors.textMuted,
    fontSize: 11,
    fontWeight: '600',
    textTransform: 'uppercase',
    letterSpacing: 0.8,
    marginBottom: 8,
  },
  recommendationItem: {
    flexDirection: 'row',
    gap: 8,
    marginBottom: 6,
  },
  recommendationBullet: {
    color: colors.primary,
    fontSize: 13,
    fontWeight: '700',
  },
  recommendationText: {
    color: colors.textSecondary,
    fontSize: 13,
    flex: 1,
    lineHeight: 18,
  },
  sortControl: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 12,
    gap: 10,
  },
  sortLabel: {
    color: colors.textMuted,
    fontSize: 13,
  },
  sortButtons: {
    flexDirection: 'row',
    gap: 6,
  },
  sortButton: {
    paddingHorizontal: 12,
    paddingVertical: 5,
    borderRadius: 8,
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
  },
  sortButtonActive: {
    backgroundColor: colors.primary,
    borderColor: colors.primary,
  },
  sortButtonText: {
    color: colors.textSecondary,
    fontSize: 12,
    fontWeight: '600',
  },
  sortButtonTextActive: {
    color: '#FFFFFF',
  },
  cardWrapper: {
    // default — no accent
  },
  highRiskCardWrapper: {
    borderLeftWidth: 3,
    borderLeftColor: colors.danger,
    borderRadius: 14,
    overflow: 'hidden',
  },
  appCard: {
    borderRadius: 12,
  },
  separator: {
    height: 8,
  },
  emptyState: {
    alignItems: 'center',
    paddingVertical: 64,
  },
  emptyIcon: {
    fontSize: 48,
    marginBottom: 16,
  },
  emptyTitle: {
    color: colors.textPrimary,
    fontSize: 18,
    fontWeight: '700',
    marginBottom: 8,
  },
  emptySubtitle: {
    color: colors.textMuted,
    fontSize: 14,
    textAlign: 'center',
  },
  modalSafeArea: {
    flex: 1,
    backgroundColor: colors.background,
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  modalTitleBlock: {
    flex: 1,
    marginRight: 12,
  },
  modalTitle: {
    color: colors.textPrimary,
    fontSize: 18,
    fontWeight: '700',
  },
  modalSubtitle: {
    color: colors.textMuted,
    fontSize: 11,
    fontFamily: 'monospace',
    marginTop: 2,
  },
  modalClose: {
    color: colors.textMuted,
    fontSize: 18,
    padding: 4,
  },
  modalContent: {
    flex: 1,
    paddingHorizontal: 20,
    paddingTop: 16,
  },
  riskSummary: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: colors.surface,
    borderRadius: 12,
    padding: 16,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: colors.border,
  },
  riskScoreBlock: {
    alignItems: 'center',
  },
  riskScoreValue: {
    color: colors.textPrimary,
    fontSize: 36,
    fontWeight: '700',
  },
  riskScoreLabel: {
    color: colors.textMuted,
    fontSize: 11,
    marginTop: 2,
  },
  permissionsTitle: {
    color: colors.textPrimary,
    fontSize: 15,
    fontWeight: '700',
    marginBottom: 12,
  },
  noPermissionsText: {
    color: colors.textMuted,
    fontSize: 14,
    fontStyle: 'italic',
  },
  permissionRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  permissionLeft: {
    flex: 1,
    marginRight: 8,
  },
  permissionName: {
    color: colors.textPrimary,
    fontSize: 13,
    fontFamily: 'monospace',
    marginBottom: 2,
  },
  permissionCategory: {
    color: colors.textMuted,
    fontSize: 11,
  },
  dangerousBadge: {
    backgroundColor: `${colors.danger}1A`,
    borderRadius: 6,
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderWidth: 1,
    borderColor: `${colors.danger}40`,
  },
  dangerousBadgeText: {
    color: colors.danger,
    fontSize: 9,
    fontWeight: '700',
    letterSpacing: 0.5,
  },
});

const summaryStyles = StyleSheet.create({
  stat: {
    flex: 1,
    alignItems: 'center',
  },
  value: {
    fontSize: 24,
    fontWeight: '700',
    marginBottom: 2,
  },
  label: {
    color: colors.textMuted,
    fontSize: 10,
    fontWeight: '500',
    textAlign: 'center',
  },
});

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
import { useTheme } from '../../theme/ThemeContext';

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
  const { colors } = useTheme();
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
      <SafeAreaView style={[styles.safeArea, { backgroundColor: colors.background }]}>
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={colors.primary} />
          <Text style={[styles.loadingText, { color: colors.textMuted }]}>Auditing installed apps…</Text>
        </View>
      </SafeAreaView>
    );
  }

  // -------------------------------------------------------------------------
  // Main render
  // -------------------------------------------------------------------------

  return (
    <SafeAreaView style={[styles.safeArea, { backgroundColor: colors.background }]}>
      {/* Header */}
      <View style={styles.header}>
        <View style={styles.headerRow}>
          <Text style={[styles.headerTitle, { color: colors.textPrimary }]} accessibilityRole="header">App Audit</Text>
          <TouchableOpacity
            style={[styles.reauditButton, { borderColor: colors.primary }, isReauditing && styles.reauditButtonDisabled]}
            onPress={() => { handleInteraction(); void loadAuditData(true); }}
            disabled={isReauditing}
          >
            {isReauditing
              ? <ActivityIndicator size="small" color={colors.primary} />
              : <Text style={[styles.reauditButtonText, { color: colors.primary }]}>Re-audit</Text>
            }
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
            {auditReport && (
              <View style={[styles.summaryCard, { backgroundColor: colors.surface, borderColor: colors.border }]}>
                <View style={styles.summaryHeader}>
                  <Text style={[styles.summaryTitle, { color: colors.textPrimary }]}>Audit Summary</Text>
                  <SecurityBadge status={overallRiskToStatus(auditReport.overallRisk)} />
                </View>
                <View style={[styles.summaryStats, { backgroundColor: colors.surfaceElevated }]}>
                  <SummaryStat value={auditReport.totalApps} label="Total Apps" color={colors.textPrimary} />
                  <View style={[styles.statDivider, { backgroundColor: colors.border }]} />
                  <SummaryStat value={auditReport.highRiskApps} label="High Risk" color={auditReport.highRiskApps > 0 ? colors.danger : colors.safe} />
                  <View style={[styles.statDivider, { backgroundColor: colors.border }]} />
                  <SummaryStat value={auditReport.dangerousPermissions} label="Dangerous Perms"
                    color={auditReport.dangerousPermissions > 10 ? colors.danger : auditReport.dangerousPermissions > 5 ? colors.warning : colors.safe}
                  />
                </View>
                {auditReport.recommendations.length > 0 && (
                  <View style={[styles.recommendations, { borderTopColor: colors.border }]}>
                    <Text style={[styles.recommendationsTitle, { color: colors.textMuted }]}>Recommendations</Text>
                    {auditReport.recommendations.slice(0, 3).map((rec, idx) => (
                      <View key={idx} style={styles.recommendationItem}>
                        <Text style={[styles.recommendationBullet, { color: colors.primary }]}>→</Text>
                        <Text style={[styles.recommendationText, { color: colors.textSecondary }]}>{rec}</Text>
                      </View>
                    ))}
                  </View>
                )}
              </View>
            )}
            <View style={styles.sortControl}>
              <Text style={[styles.sortLabel, { color: colors.textMuted }]}>Sort by:</Text>
              <View style={styles.sortButtons}>
                {([{ key: 'risk', label: 'Risk' }, { key: 'name', label: 'Name' }, { key: 'installDate', label: 'Install Date' }] as { key: SortMode; label: string }[]).map((option) => (
                  <TouchableOpacity
                    key={option.key}
                    style={[
                      styles.sortButton,
                      { backgroundColor: colors.surface, borderColor: colors.border },
                      sortMode === option.key && { backgroundColor: colors.primary, borderColor: colors.primary },
                    ]}
                    onPress={() => { handleInteraction(); setSortMode(option.key); }}
                    accessibilityRole="button"
                    accessibilityState={{ selected: sortMode === option.key }}
                  >
                    <Text style={[styles.sortButtonText, { color: sortMode === option.key ? '#FFFFFF' : colors.textSecondary }]}>
                      {option.label}
                    </Text>
                  </TouchableOpacity>
                ))}
              </View>
            </View>
          </View>
        )}
        renderItem={({ item }) => (
          <View style={[styles.cardWrapper, item.riskScore >= 70 && [styles.highRiskCardWrapper, { borderLeftColor: colors.danger }]]}>
            <AppRiskCard app={item} onPress={handleCardPress} style={styles.appCard} />
          </View>
        )}
        ListEmptyComponent={() => (
          <View style={styles.emptyState}>
            <Text style={styles.emptyIcon}>📱</Text>
            <Text style={[styles.emptyTitle, { color: colors.textPrimary }]}>No Apps Found</Text>
            <Text style={[styles.emptySubtitle, { color: colors.textMuted }]}>App enumeration is not available on this platform</Text>
          </View>
        )}
        contentContainerStyle={styles.listContent}
        ItemSeparatorComponent={() => <View style={styles.separator} />}
      />

      <Modal
        visible={detailSheet.visible}
        animationType="slide"
        presentationStyle="pageSheet"
        onRequestClose={() => setDetailSheet({ visible: false, app: null })}
      >
        <SafeAreaView style={[styles.modalSafeArea, { backgroundColor: colors.background }]}>
          <View style={[styles.modalHeader, { borderBottomColor: colors.border }]}>
            <View style={styles.modalTitleBlock}>
              <Text style={[styles.modalTitle, { color: colors.textPrimary }]} numberOfLines={1}>
                {detailSheet.app?.name ?? 'App Permissions'}
              </Text>
              <Text style={[styles.modalSubtitle, { color: colors.textMuted }]} numberOfLines={1}>
                {detailSheet.app?.packageName}
              </Text>
            </View>
            <TouchableOpacity onPress={() => setDetailSheet({ visible: false, app: null })}>
              <Text style={[styles.modalClose, { color: colors.textMuted }]}>✕</Text>
            </TouchableOpacity>
          </View>
          {detailSheet.app && (
            <ScrollView style={styles.modalContent}>
              <View style={[styles.riskSummary, { backgroundColor: colors.surface, borderColor: colors.border }]}>
                <View style={styles.riskScoreBlock}>
                  <Text style={[styles.riskScoreValue, { color: colors.textPrimary }]}>{detailSheet.app.riskScore}</Text>
                  <Text style={[styles.riskScoreLabel, { color: colors.textMuted }]}>Risk Score</Text>
                </View>
                <SecurityBadge status={detailSheet.app.riskScore >= 70 ? 'critical' : detailSheet.app.riskScore >= 40 ? 'warning' : 'safe'} />
              </View>
              <Text style={[styles.permissionsTitle, { color: colors.textPrimary }]}>
                Permissions ({detailSheet.app.permissions.length})
              </Text>
              {detailSheet.app.permissions.length === 0 ? (
                <Text style={[styles.noPermissionsText, { color: colors.textMuted }]}>No permissions declared</Text>
              ) : (
                detailSheet.app.permissions.map((perm, idx) => (
                  <View key={idx} style={[styles.permissionRow, { borderBottomColor: colors.border }]}>
                    <View style={styles.permissionLeft}>
                      <Text style={[styles.permissionName, { color: colors.textPrimary }]} numberOfLines={1}>
                        {perm.name.split('.').pop() ?? perm.name}
                      </Text>
                      <Text style={[styles.permissionCategory, { color: colors.textMuted }]}>{categoryLabel(perm.category)}</Text>
                    </View>
                    {perm.dangerous && (
                      <View style={[styles.dangerousBadge, { backgroundColor: `${colors.danger}18`, borderColor: `${colors.danger}40` }]}>
                        <Text style={[styles.dangerousBadgeText, { color: colors.danger }]}>DANGEROUS</Text>
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
    <Text style={[summaryStyles.label, { color: '#9090A8' }]}>{label}</Text>
  </View>
);

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  safeArea: { flex: 1 },
  loadingContainer: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 16 },
  loadingText: { fontSize: 14 },
  header: { paddingHorizontal: 16, paddingTop: 20, paddingBottom: 8 },
  headerRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  headerTitle: { fontSize: 26, fontWeight: '800', letterSpacing: -0.3 },
  reauditButton: { paddingHorizontal: 14, paddingVertical: 7, borderRadius: 8, borderWidth: 1, minWidth: 80, alignItems: 'center' },
  reauditButtonDisabled: { opacity: 0.5 },
  reauditButtonText: { fontSize: 13, fontWeight: '700' },
  listContent: { paddingHorizontal: 16, paddingBottom: 32 },
  summaryCard: { borderRadius: 16, padding: 16, marginBottom: 16, borderWidth: 1 },
  summaryHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 },
  summaryTitle: { fontSize: 16, fontWeight: '700' },
  summaryStats: { flexDirection: 'row', alignItems: 'center', borderRadius: 10, paddingVertical: 12, paddingHorizontal: 8, marginBottom: 12 },
  statDivider: { width: 1, height: 32, marginHorizontal: 4 },
  recommendations: { paddingTop: 12, borderTopWidth: 1 },
  recommendationsTitle: { fontSize: 11, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 },
  recommendationItem: { flexDirection: 'row', gap: 8, marginBottom: 6 },
  recommendationBullet: { fontSize: 13, fontWeight: '700' },
  recommendationText: { fontSize: 13, flex: 1, lineHeight: 18 },
  sortControl: { flexDirection: 'row', alignItems: 'center', marginBottom: 12, gap: 10 },
  sortLabel: { fontSize: 13 },
  sortButtons: { flexDirection: 'row', gap: 6 },
  sortButton: { paddingHorizontal: 12, paddingVertical: 5, borderRadius: 8, borderWidth: 1 },
  sortButtonText: { fontSize: 12, fontWeight: '600' },
  cardWrapper: {},
  highRiskCardWrapper: { borderLeftWidth: 3, borderRadius: 14, overflow: 'hidden' },
  appCard: { borderRadius: 12 },
  separator: { height: 8 },
  emptyState: { alignItems: 'center', paddingVertical: 64 },
  emptyIcon: { fontSize: 48, marginBottom: 16 },
  emptyTitle: { fontSize: 18, fontWeight: '700', marginBottom: 8 },
  emptySubtitle: { fontSize: 14, textAlign: 'center' },
  modalSafeArea: { flex: 1 },
  modalHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: 20, paddingVertical: 16, borderBottomWidth: 1 },
  modalTitleBlock: { flex: 1, marginRight: 12 },
  modalTitle: { fontSize: 18, fontWeight: '700' },
  modalSubtitle: { fontSize: 11, fontFamily: 'monospace', marginTop: 2 },
  modalClose: { fontSize: 18, padding: 4 },
  modalContent: { flex: 1, paddingHorizontal: 20, paddingTop: 16 },
  riskSummary: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', borderRadius: 12, padding: 16, marginBottom: 20, borderWidth: 1 },
  riskScoreBlock: { alignItems: 'center' },
  riskScoreValue: { fontSize: 36, fontWeight: '700' },
  riskScoreLabel: { fontSize: 11, marginTop: 2 },
  permissionsTitle: { fontSize: 15, fontWeight: '700', marginBottom: 12 },
  noPermissionsText: { fontSize: 14, fontStyle: 'italic' },
  permissionRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingVertical: 10, borderBottomWidth: 1 },
  permissionLeft: { flex: 1, marginRight: 8 },
  permissionName: { fontSize: 13, fontFamily: 'monospace', marginBottom: 2 },
  permissionCategory: { fontSize: 11 },
  dangerousBadge: { borderRadius: 6, paddingHorizontal: 8, paddingVertical: 3, borderWidth: 1 },
  dangerousBadgeText: { fontSize: 9, fontWeight: '700', letterSpacing: 0.5 },
});

const summaryStyles = StyleSheet.create({
  stat: { flex: 1, alignItems: 'center' },
  value: { fontSize: 24, fontWeight: '700', marginBottom: 2 },
  label: { fontSize: 10, fontWeight: '500', textAlign: 'center' },
});

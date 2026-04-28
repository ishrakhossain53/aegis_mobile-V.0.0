/**
 * alerts.tsx — Alerts Screen
 *
 * Displays:
 *  - Segmented control tabs: "Breaches" | "Threats"
 *  - Breaches tab: AlertItem list grouped by monitored identity;
 *    "Add Email to Monitor" when empty
 *  - Threats tab: AlertItem list sorted by severity then timestamp
 *  - Empty state: green checkmark + "All Clear" message
 *  - Filter bar (All / Breaches / Threats / Network)
 *  - Dismiss and escalate actions per alert
 *  - "Mark All Resolved" header button
 *
 * Requirements: 28.1, 28.2, 28.3, 28.4
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  FlatList,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  TextInput,
  Modal,
  ActivityIndicator,
  Alert,
  ScrollView,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { AlertItem } from '../../components/AlertItem';
import { threatMonitorService } from '../../services/ThreatMonitorService';
import { breachService } from '../../services/BreachService';
import { sessionLockService } from '../../services/SessionLockService';
import { Threat, MonitoredIdentity } from '../../types/index';
import { useTheme } from '../../theme/ThemeContext';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type TabType = 'breaches' | 'threats';
type ThreatFilter = 'all' | 'breaches' | 'threats' | 'network';

const SEVERITY_ORDER: Record<Threat['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sortThreatsBySeverityThenTime(threats: Threat[]): Threat[] {
  return [...threats].sort((a, b) => {
    const severityDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (severityDiff !== 0) return severityDiff;
    return b.detectedAt - a.detectedAt;
  });
}

function threatToAlertItem(identity: MonitoredIdentity): Threat {
  return {
    id: identity.id,
    type: 'data_exfiltration',
    severity: identity.status === 'compromised' ? 'high' : 'low',
    description:
      identity.status === 'compromised'
        ? `${identity.value} found in ${identity.breachCount} data breach${identity.breachCount !== 1 ? 'es' : ''}.`
        : `${identity.value} — No breaches found.`,
    detectedAt: identity.lastChecked || identity.addedAt,
    resolved: identity.status === 'safe',
    metadata: { identityType: identity.type, value: identity.value },
  };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AlertsScreen() {
  const { colors } = useTheme();
  const [activeTab, setActiveTab] = useState<TabType>('breaches');
  const [activeFilter, setActiveFilter] = useState<ThreatFilter>('all');
  const [threats, setThreats] = useState<Threat[]>([]);
  const [identities, setIdentities] = useState<MonitoredIdentity[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showAddEmailModal, setShowAddEmailModal] = useState(false);
  const [emailInput, setEmailInput] = useState('');
  const [isAddingEmail, setIsAddingEmail] = useState(false);

  // -------------------------------------------------------------------------
  // Data loading
  // -------------------------------------------------------------------------

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [allThreats, allIdentities] = await Promise.all([
        threatMonitorService.getThreatHistory(),
        breachService.getMonitoredIdentities(),
      ]);
      setThreats(allThreats);
      setIdentities(allIdentities);
    } catch {
      // Show empty state on error
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  // -------------------------------------------------------------------------
  // Session activity
  // -------------------------------------------------------------------------

  const handleInteraction = useCallback(() => {
    sessionLockService.resetTimer();
  }, []);

  // -------------------------------------------------------------------------
  // Threat dismiss
  // -------------------------------------------------------------------------

  const handleDismissThreat = useCallback(async (id: string) => {
    handleInteraction();
    await threatMonitorService.resolveThreats([id]);
    setThreats((prev) =>
      prev.map((t) => (t.id === id ? { ...t, resolved: true, resolvedAt: Date.now() } : t)),
    );
  }, [handleInteraction]);

  // -------------------------------------------------------------------------
  // Mark all resolved
  // -------------------------------------------------------------------------

  const handleMarkAllResolved = useCallback(async () => {
    handleInteraction();
    const unresolvedIds = threats
      .filter((t) => !t.resolved)
      .map((t) => t.id);

    if (unresolvedIds.length === 0) return;

    Alert.alert(
      'Mark All Resolved',
      `Mark ${unresolvedIds.length} alert${unresolvedIds.length !== 1 ? 's' : ''} as resolved?`,
      [
        {
          text: 'Mark All',
          onPress: async () => {
            await threatMonitorService.resolveThreats(unresolvedIds);
            setThreats((prev) =>
              prev.map((t) =>
                unresolvedIds.includes(t.id)
                  ? { ...t, resolved: true, resolvedAt: Date.now() }
                  : t,
              ),
            );
          },
        },
        { text: 'Cancel', style: 'cancel' },
      ],
    );
  }, [threats, handleInteraction]);

  // -------------------------------------------------------------------------
  // Add email to monitor
  // -------------------------------------------------------------------------

  const handleAddEmail = useCallback(async () => {
    const email = emailInput.trim();
    if (!email || !email.includes('@')) {
      Alert.alert('Invalid Email', 'Please enter a valid email address.');
      return;
    }

    setIsAddingEmail(true);
    try {
      await breachService.addMonitoredEmail(email);
      // Trigger a breach check for the new email
      try {
        await breachService.checkEmail(email);
      } catch (checkErr) {
        // Show API key error prominently — user needs to configure it
        if (checkErr instanceof Error && checkErr.message.includes('API key')) {
          Alert.alert(
            'API Key Required',
            'Add your HaveIBeenPwned API key in Settings (⚙️) to check for breaches.\n\nThe email has been added to monitoring.',
          );
        }
      }
      setEmailInput('');
      setShowAddEmailModal(false);
      await loadData();
    } catch (err) {
      Alert.alert('Error', err instanceof Error ? err.message : 'Failed to add email. Please try again.');
    } finally {
      setIsAddingEmail(false);
    }
  }, [emailInput, loadData]);

  // -------------------------------------------------------------------------
  // Filtered threats
  // -------------------------------------------------------------------------

  const getFilteredThreats = useCallback((): Threat[] => {
    let filtered = threats;

    if (activeFilter === 'network') {
      filtered = filtered.filter((t) => t.type === 'suspicious_network');
    } else if (activeFilter === 'threats') {
      filtered = filtered.filter(
        (t) => t.type !== 'suspicious_network' && t.type !== 'data_exfiltration',
      );
    }

    return sortThreatsBySeverityThenTime(filtered);
  }, [threats, activeFilter]);

  // -------------------------------------------------------------------------
  // Render helpers
  // -------------------------------------------------------------------------

  const renderFilterBar = () => (
    <ScrollView
      horizontal
      showsHorizontalScrollIndicator={false}
      style={styles.filterScroll}
      contentContainerStyle={styles.filterContent}
    >
      {(['all', 'breaches', 'threats', 'network'] as ThreatFilter[]).map((filter) => (
        <TouchableOpacity
          key={filter}
          style={[
            styles.filterChip,
            { backgroundColor: colors.surface, borderColor: colors.border },
            activeFilter === filter && { backgroundColor: colors.primary, borderColor: colors.primary },
          ]}
          onPress={() => { handleInteraction(); setActiveFilter(filter); }}
          accessibilityLabel={`Filter: ${filter}`}
          accessibilityRole="button"
          accessibilityState={{ selected: activeFilter === filter }}
        >
          <Text style={[
            styles.filterChipText,
            { color: colors.textSecondary },
            activeFilter === filter && { color: '#FFFFFF' },
          ]}>
            {filter.charAt(0).toUpperCase() + filter.slice(1)}
          </Text>
        </TouchableOpacity>
      ))}
    </ScrollView>
  );

  const renderBreachesTab = () => {
    if (identities.length === 0) {
      return (
        <View style={styles.emptyState}>
          <Text style={styles.emptyIcon}>📧</Text>
          <Text style={[styles.emptyTitle, { color: colors.safe }]}>No Emails Monitored</Text>
          <Text style={[styles.emptySubtitle, { color: colors.textMuted }]}>
            Add your email address to monitor for data breaches
          </Text>
          <TouchableOpacity
            style={[styles.addEmailButton, { backgroundColor: colors.primary }]}
            onPress={() => { handleInteraction(); setShowAddEmailModal(true); }}
            accessibilityLabel="Add email to monitor"
            accessibilityRole="button"
          >
            <Text style={styles.addEmailButtonText}>+ Add Email to Monitor</Text>
          </TouchableOpacity>
        </View>
      );
    }

    const breachAlerts = identities.map(threatToAlertItem);

    return (
      <View>
        <TouchableOpacity
          style={[styles.addEmailInline, { borderColor: colors.primary }]}
          onPress={() => { handleInteraction(); setShowAddEmailModal(true); }}
          accessibilityLabel="Add another email to monitor"
          accessibilityRole="button"
        >
          <Text style={[styles.addEmailInlineText, { color: colors.primary }]}>+ Add Email to Monitor</Text>
        </TouchableOpacity>
        <FlatList
          data={breachAlerts}
          keyExtractor={(item) => item.id}
          renderItem={({ item }) => <AlertItem threat={item} style={styles.alertItem} />}
          scrollEnabled={false}
          ItemSeparatorComponent={() => <View style={styles.separator} />}
        />
      </View>
    );
  };

  const renderThreatsTab = () => {
    const filteredThreats = getFilteredThreats();
    if (filteredThreats.length === 0) {
      return (
        <View style={styles.emptyState}>
          <Text style={styles.emptyIcon}>✅</Text>
          <Text style={[styles.emptyTitle, { color: colors.safe }]}>All Clear</Text>
          <Text style={[styles.emptySubtitle, { color: colors.textMuted }]}>No security threats detected</Text>
        </View>
      );
    }
    return (
      <FlatList
        data={filteredThreats}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <AlertItem threat={item} onDismiss={handleDismissThreat} style={styles.alertItem} />
        )}
        scrollEnabled={false}
        ItemSeparatorComponent={() => <View style={styles.separator} />}
      />
    );
  };

  // -------------------------------------------------------------------------
  // Main render
  // -------------------------------------------------------------------------

  const unresolvedCount = threats.filter((t) => !t.resolved).length;

  return (
    <SafeAreaView style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <View style={styles.header}>
        <View style={styles.headerRow}>
          <Text style={[styles.headerTitle, { color: colors.textPrimary }]} accessibilityRole="header">
            Alerts
          </Text>
          {unresolvedCount > 0 && (
            <TouchableOpacity onPress={handleMarkAllResolved} accessibilityRole="button">
              <Text style={[styles.markAllText, { color: colors.primary }]}>Mark All Resolved</Text>
            </TouchableOpacity>
          )}
        </View>
      </View>

      {/* Segmented control */}
      <View style={[styles.segmentedControl, { backgroundColor: colors.surface, borderColor: colors.border }]}>
        {(['breaches', 'threats'] as TabType[]).map((tab) => (
          <TouchableOpacity
            key={tab}
            style={[styles.segment, activeTab === tab && [styles.segmentActive, { backgroundColor: colors.surfaceElevated }]]}
            onPress={() => { handleInteraction(); setActiveTab(tab); }}
            accessibilityRole="tab"
            accessibilityState={{ selected: activeTab === tab }}
          >
            <Text style={[styles.segmentText, { color: colors.textMuted }, activeTab === tab && { color: colors.textPrimary }]}>
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </Text>
            {tab === 'breaches' && identities.filter((i) => i.status === 'compromised').length > 0 && (
              <View style={[styles.badge, { backgroundColor: colors.danger }]}>
                <Text style={styles.badgeText}>{identities.filter((i) => i.status === 'compromised').length}</Text>
              </View>
            )}
            {tab === 'threats' && threats.filter((t) => !t.resolved).length > 0 && (
              <View style={[styles.badge, { backgroundColor: colors.danger }]}>
                <Text style={styles.badgeText}>{threats.filter((t) => !t.resolved).length}</Text>
              </View>
            )}
          </TouchableOpacity>
        ))}
      </View>

      {activeTab === 'threats' && renderFilterBar()}

      {isLoading ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={colors.primary} />
        </View>
      ) : (
        <ScrollView
          style={styles.scrollView}
          contentContainerStyle={styles.scrollContent}
          onScrollBeginDrag={handleInteraction}
          showsVerticalScrollIndicator={false}
        >
          {activeTab === 'breaches' ? renderBreachesTab() : renderThreatsTab()}
        </ScrollView>
      )}

      {/* Add Email Modal */}
      <Modal
        visible={showAddEmailModal}
        animationType="slide"
        presentationStyle="pageSheet"
        onRequestClose={() => setShowAddEmailModal(false)}
      >
        <SafeAreaView style={[styles.modalSafeArea, { backgroundColor: colors.background }]}>
          <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : 'height'} style={{ flex: 1 }}>
            <View style={[styles.modalHeader, { borderBottomColor: colors.border }]}>
              <Text style={[styles.modalTitle, { color: colors.textPrimary }]}>Monitor Email</Text>
              <TouchableOpacity onPress={() => setShowAddEmailModal(false)}>
                <Text style={[styles.modalClose, { color: colors.textMuted }]}>✕</Text>
              </TouchableOpacity>
            </View>
            <View style={styles.modalContent}>
              <Text style={[styles.modalDescription, { color: colors.textSecondary }]}>
                Enter an email address to monitor for data breaches. We use
                k-anonymity — your full email is never sent to any external service.
              </Text>
              <TextInput
                style={[styles.emailInput, {
                  backgroundColor: colors.surface,
                  borderColor: colors.border,
                  color: colors.textPrimary,
                }]}
                value={emailInput}
                onChangeText={setEmailInput}
                placeholder="user@example.com"
                placeholderTextColor={colors.textMuted}
                keyboardType="email-address"
                autoCapitalize="none"
                autoCorrect={false}
                autoFocus
              />
              <TouchableOpacity
                style={[styles.addButton, { backgroundColor: colors.primary }, isAddingEmail && styles.addButtonDisabled]}
                onPress={handleAddEmail}
                disabled={isAddingEmail}
              >
                {isAddingEmail ? <ActivityIndicator color="#FFF" /> : <Text style={styles.addButtonText}>Add to Monitoring</Text>}
              </TouchableOpacity>
              <View style={[styles.privacyNote, { backgroundColor: colors.surfaceElevated, borderColor: colors.border }]}>
                <Text style={styles.privacyIcon}>🔒</Text>
                <Text style={[styles.privacyText, { color: colors.textMuted }]}>
                  Only the first 5 characters of a SHA-1 hash are sent to the
                  breach database. Your email address never leaves your device.
                </Text>
              </View>
            </View>
          </KeyboardAvoidingView>
        </SafeAreaView>
      </Modal>
    </SafeAreaView>
  );
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  safeArea: { flex: 1 },
  header: { paddingHorizontal: 16, paddingTop: 20, paddingBottom: 8 },
  headerRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  headerTitle: { fontSize: 26, fontWeight: '800', letterSpacing: -0.3 },
  markAllText: { fontSize: 13, fontWeight: '600' },
  segmentedControl: {
    flexDirection: 'row', marginHorizontal: 16, marginBottom: 8,
    borderRadius: 10, padding: 3, borderWidth: 1,
  },
  segment: {
    flex: 1, flexDirection: 'row', alignItems: 'center',
    justifyContent: 'center', paddingVertical: 8, borderRadius: 8, gap: 6,
  },
  segmentActive: {},
  segmentText: { fontSize: 14, fontWeight: '600' },
  badge: {
    borderRadius: 10, minWidth: 18, height: 18,
    alignItems: 'center', justifyContent: 'center', paddingHorizontal: 4,
  },
  badgeText: { color: '#FFFFFF', fontSize: 10, fontWeight: '700' },
  filterScroll: { maxHeight: 44, marginBottom: 4 },
  filterContent: { paddingHorizontal: 16, gap: 8, alignItems: 'center' },
  filterChip: { paddingHorizontal: 14, paddingVertical: 6, borderRadius: 20, borderWidth: 1 },
  filterChipText: { fontSize: 13, fontWeight: '600' },
  loadingContainer: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  scrollView: { flex: 1 },
  scrollContent: { paddingHorizontal: 16, paddingBottom: 32, paddingTop: 8, flexGrow: 1 },
  alertItem: {},
  separator: { height: 8 },
  emptyState: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingVertical: 64 },
  emptyIcon: { fontSize: 48, marginBottom: 16 },
  emptyTitle: { fontSize: 20, fontWeight: '700', marginBottom: 8 },
  emptySubtitle: { fontSize: 14, textAlign: 'center', marginBottom: 24, paddingHorizontal: 32 },
  addEmailButton: { borderRadius: 12, paddingHorizontal: 24, paddingVertical: 12 },
  addEmailButtonText: { color: '#FFFFFF', fontSize: 15, fontWeight: '700' },
  addEmailInline: {
    marginBottom: 12, paddingVertical: 10, borderRadius: 10,
    borderWidth: 1, borderStyle: 'dashed', alignItems: 'center',
  },
  addEmailInlineText: { fontSize: 14, fontWeight: '600' },
  modalSafeArea: { flex: 1 },
  modalHeader: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    paddingHorizontal: 20, paddingVertical: 16, borderBottomWidth: 1,
  },
  modalTitle: { fontSize: 18, fontWeight: '700' },
  modalClose: { fontSize: 18, padding: 4 },
  modalContent: { padding: 20 },
  modalDescription: { fontSize: 14, lineHeight: 20, marginBottom: 20 },
  emailInput: { borderRadius: 12, borderWidth: 1, paddingHorizontal: 16, height: 52, fontSize: 16, marginBottom: 16 },
  addButton: { borderRadius: 12, height: 52, alignItems: 'center', justifyContent: 'center', marginBottom: 20 },
  addButtonDisabled: { opacity: 0.5 },
  addButtonText: { color: '#FFFFFF', fontSize: 16, fontWeight: '700' },
  privacyNote: { flexDirection: 'row', borderRadius: 10, padding: 12, gap: 10, borderWidth: 1 },
  privacyIcon: { fontSize: 16 },
  privacyText: { fontSize: 12, lineHeight: 17, flex: 1 },
});

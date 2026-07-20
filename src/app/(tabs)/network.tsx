/**
 * network.tsx — Network Safety Screen
 *
 * Displays:
 *  - Current network status card (SSID, encryption type, SecurityBadge)
 *  - MITM detection card with status, last scan timestamp, "Scan Now" button
 *  - DoH card with toggle switch, provider selector, latency display
 *  - Active network threats list
 *  - Auto-refresh every 30s while screen is visible
 *
 * Requirements: 27.1, 27.2, 27.3, 27.4, 27.5
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  Switch,
  StyleSheet,
  SafeAreaView,
  ActivityIndicator,
  RefreshControl,
} from 'react-native';
import { SecurityBadge } from '../../components/SecurityBadge';
import { networkService } from '../../services/NetworkService';
import { networkInspector } from '../../modules/network/NetworkInspector';
import { sessionLockService } from '../../services/SessionLockService';
import {
  NetworkStatus, MITMResult, DNSStatus, NetworkScanResult, DoHProvider,
} from '../../types/index';
import { useTheme } from '../../theme/ThemeContext';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface NetworkScreenState {
  networkStatus: NetworkStatus | null;
  mitmResult: MITMResult | null;
  dnsStatus: DNSStatus | null;
  scanResult: NetworkScanResult | null;
  lastScanTime: number | null;
  isLoading: boolean;
  isScanning: boolean;
  isRefreshing: boolean;
  error: string | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function encryptionToStatus(
  encryption: NetworkStatus['encryption'] | undefined,
  isSecure: boolean,
): 'safe' | 'warning' | 'critical' {
  if (!isSecure) return 'critical';
  if (encryption === 'WPA3') return 'safe';
  if (encryption === 'WPA2') return 'safe';
  if (encryption === 'WPA') return 'warning';
  return 'warning';
}

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleTimeString();
}

const DOH_PROVIDERS: { key: DoHProvider; label: string; description: string }[] = [
  { key: 'cloudflare', label: 'Cloudflare', description: '1.1.1.1 · Privacy-first' },
  { key: 'google', label: 'Google', description: '8.8.8.8 · High reliability' },
  { key: 'quad9', label: 'Quad9', description: '9.9.9.9 · Malware blocking' },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function NetworkScreen() {
  const { colors } = useTheme();
  const [state, setState] = useState<NetworkScreenState>({
    networkStatus: null,
    mitmResult: null,
    dnsStatus: null,
    scanResult: null,
    lastScanTime: null,
    isLoading: true,
    isScanning: false,
    isRefreshing: false,
    error: null,
  });
  const [dohEnabled, setDohEnabled] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState<DoHProvider>('cloudflare');
  const autoRefreshRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // -------------------------------------------------------------------------
  // Data loading
  // -------------------------------------------------------------------------

  const loadNetworkData = useCallback(async (isRefresh = false) => {
    setState((prev) => ({
      ...prev,
      isLoading: !isRefresh,
      isRefreshing: isRefresh,
      error: null,
    }));

    try {
      const [networkStatus, mitmResult, dnsStatus] = await Promise.all([
        networkService.getNetworkStatus(),
        networkService.detectMITM(),
        networkService.getDNSStatus(),
      ]);

      setState((prev) => ({
        ...prev,
        networkStatus,
        mitmResult,
        dnsStatus,
        isLoading: false,
        isRefreshing: false,
      }));

      setDohEnabled(dnsStatus.enabled);
      setSelectedProvider(dnsStatus.provider);
    } catch {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        isRefreshing: false,
        error: 'Failed to load network data.',
      }));
    }
  }, []);

  // -------------------------------------------------------------------------
  // Full scan
  // -------------------------------------------------------------------------

  const runFullScan = useCallback(async () => {
    setState((prev) => ({ ...prev, isScanning: true, error: null }));
    try {
      // Use Phase 2 NetworkInspector for deep scan (ARP, rogue AP, SSL anomaly)
      const report = await networkInspector.inspect();

      setState((prev) => ({
        ...prev,
        scanResult: report.scanResult,
        mitmResult: report.mitm,
        networkStatus: report.wifiAssessment
          ? {
              connected: true,
              type: 'wifi',
              ssid: report.wifiAssessment.ssid,
              isSecure: report.wifiAssessment.isSecure,
              encryption: report.wifiAssessment.encryption,
              signalStrength: report.wifiAssessment.signalStrength,
            }
          : prev.networkStatus,
        lastScanTime: report.timestamp,
        isScanning: false,
      }));
    } catch {
      setState((prev) => ({
        ...prev,
        isScanning: false,
        error: 'Scan failed. Please try again.',
      }));
    }
  }, []);

  // -------------------------------------------------------------------------
  // Auto-refresh every 30s (Requirement 8.4)
  // -------------------------------------------------------------------------

  useEffect(() => {
    void loadNetworkData();
    networkService.startAutoRefresh();

    autoRefreshRef.current = setInterval(() => {
      void loadNetworkData(true);
    }, 30_000);

    return () => {
      networkService.stopAutoRefresh();
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current);
      }
    };
  }, [loadNetworkData]);

  // -------------------------------------------------------------------------
  // DoH toggle
  // -------------------------------------------------------------------------

  const handleDohToggle = useCallback(async (enabled: boolean) => {
    setDohEnabled(enabled);
    if (enabled) {
      await networkService.configureDNSOverHTTPS(selectedProvider);
    }
    const dnsStatus = await networkService.getDNSStatus();
    setState((prev) => ({ ...prev, dnsStatus }));
  }, [selectedProvider]);

  const handleProviderSelect = useCallback(async (provider: DoHProvider) => {
    setSelectedProvider(provider);
    if (dohEnabled) {
      await networkService.configureDNSOverHTTPS(provider);
      const dnsStatus = await networkService.getDNSStatus();
      setState((prev) => ({ ...prev, dnsStatus }));
    }
  }, [dohEnabled]);

  // -------------------------------------------------------------------------
  // Session activity
  // -------------------------------------------------------------------------

  const handleInteraction = useCallback(() => {
    sessionLockService.resetTimer();
  }, []);

  // -------------------------------------------------------------------------
  // Loading state
  // -------------------------------------------------------------------------

  if (state.isLoading) {
    return (
      <SafeAreaView style={[styles.safeArea, { backgroundColor: colors.background }]}>
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={colors.primary} />
          <Text style={[styles.loadingText, { color: colors.textMuted }]}>Analyzing network…</Text>
        </View>
      </SafeAreaView>
    );
  }

  const { networkStatus, mitmResult, dnsStatus, scanResult, lastScanTime } = state;

  // -------------------------------------------------------------------------
  // Main render
  // -------------------------------------------------------------------------

  return (
    <SafeAreaView style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.scrollContent}
        refreshControl={
          <RefreshControl refreshing={state.isRefreshing} onRefresh={() => loadNetworkData(true)} tintColor={colors.primary} />
        }
        onScrollBeginDrag={handleInteraction}
        showsVerticalScrollIndicator={false}
      >
        <View style={styles.header}>
          <Text style={[styles.headerTitle, { color: colors.textPrimary }]} accessibilityRole="header">Network Safety</Text>
          {lastScanTime && <Text style={[styles.headerSubtitle, { color: colors.textMuted }]}>Last scan: {formatTimestamp(lastScanTime)}</Text>}
        </View>

        {state.error && (
          <View style={[styles.errorBanner, { backgroundColor: `${colors.danger}18`, borderColor: `${colors.danger}35` }]} accessibilityRole="alert">
            <Text style={[styles.errorText, { color: colors.danger }]}>{state.error}</Text>
          </View>
        )}

        {/* Network Status Card */}
        <View style={[styles.card, { backgroundColor: colors.surface, borderColor: colors.border }]}>
          <View style={styles.cardHeader}>
            <Text style={[styles.cardTitle, { color: colors.textPrimary }]}>Current Network</Text>
            {networkStatus && (
              <SecurityBadge status={!networkStatus.connected ? 'warning' : encryptionToStatus(networkStatus.encryption, networkStatus.isSecure)} />
            )}
          </View>
          {networkStatus ? (
            <View style={styles.networkDetails}>
              <NetworkDetailRow icon="📶" label="Status" value={networkStatus.connected ? 'Connected' : 'Disconnected'} valueColor={networkStatus.connected ? colors.safe : colors.danger} colors={colors} />
              {networkStatus.ssid && <NetworkDetailRow icon="🌐" label="Network" value={networkStatus.ssid} colors={colors} />}
              <NetworkDetailRow icon="🔒" label="Encryption" value={networkStatus.encryption ?? 'Unknown'} valueColor={networkStatus.isSecure ? colors.safe : colors.danger} colors={colors} />
              <NetworkDetailRow icon="📡" label="Type" value={networkStatus.type.toUpperCase()} colors={colors} />
              {networkStatus.ipAddress && <NetworkDetailRow icon="🖥️" label="IP Address" value={networkStatus.ipAddress} monospace colors={colors} />}
            </View>
          ) : (
            <Text style={[styles.noDataText, { color: colors.textMuted }]}>Network information unavailable</Text>
          )}
        </View>

        {/* MITM Detection Card */}
        <View style={[styles.card, { backgroundColor: colors.surface, borderColor: colors.border }]}>
          <View style={styles.cardHeader}>
            <Text style={[styles.cardTitle, { color: colors.textPrimary }]}>MITM Detection</Text>
            {mitmResult && (
              <SecurityBadge status={mitmResult.detected ? (mitmResult.riskLevel === 'high' ? 'critical' : 'warning') : 'safe'} />
            )}
          </View>
          {mitmResult ? (
            <View>
              <NetworkDetailRow icon={mitmResult.detected ? '⚠️' : '✅'} label="Status" value={mitmResult.detected ? 'Threat Detected' : 'No Threats'} valueColor={mitmResult.detected ? colors.danger : colors.safe} colors={colors} />
              {mitmResult.detected && mitmResult.indicators.length > 0 && (
                <View style={styles.indicatorList}>
                  {mitmResult.indicators.map((indicator, idx) => (
                    <View key={idx} style={styles.indicatorItem}>
                      <Text style={[styles.indicatorBullet, { color: colors.danger }]}>•</Text>
                      <Text style={[styles.indicatorText, { color: colors.textSecondary }]}>{indicator}</Text>
                    </View>
                  ))}
                </View>
              )}
            </View>
          ) : (
            <Text style={[styles.noDataText, { color: colors.textMuted }]}>Run a scan to check for MITM threats</Text>
          )}
          <TouchableOpacity
            style={[styles.scanButton, { borderColor: colors.primary }, state.isScanning && styles.scanButtonDisabled]}
            onPress={() => { handleInteraction(); void runFullScan(); }}
            disabled={state.isScanning}
          >
            {state.isScanning
              ? <ActivityIndicator size="small" color={colors.primary} />
              : <Text style={[styles.scanButtonText, { color: colors.primary }]}>🔍 Scan Now</Text>
            }
          </TouchableOpacity>
        </View>

        {/* DoH Card */}
        <View style={[styles.card, { backgroundColor: colors.surface, borderColor: colors.border }]}>
          <View style={styles.cardHeader}>
            <Text style={[styles.cardTitle, { color: colors.textPrimary }]}>DNS-over-HTTPS</Text>
            <Switch
              value={dohEnabled}
              onValueChange={(v) => { handleInteraction(); void handleDohToggle(v); }}
              trackColor={{ false: colors.border, true: `${colors.primary}80` }}
              thumbColor={dohEnabled ? colors.primary : colors.textMuted}
            />
          </View>
          <Text style={[styles.cardDescription, { color: colors.textSecondary }]}>
            Route DNS queries through HTTPS to prevent eavesdropping and hijacking.
          </Text>
          {dohEnabled && dnsStatus && (
            <NetworkDetailRow icon="⚡" label="Latency" value={dnsStatus.latency > 0 ? `${dnsStatus.latency}ms` : 'Measuring…'}
              valueColor={dnsStatus.latency < 100 ? colors.safe : dnsStatus.latency < 300 ? colors.warning : colors.danger}
              colors={colors}
            />
          )}
          <Text style={[styles.providerLabel, { color: colors.textMuted }]}>Provider</Text>
          <View style={styles.providerList}>
            {DOH_PROVIDERS.map((provider) => (
              <TouchableOpacity
                key={provider.key}
                style={[
                  styles.providerOption,
                  { backgroundColor: colors.surfaceElevated, borderColor: colors.border },
                  selectedProvider === provider.key && { borderColor: colors.primary, backgroundColor: `${colors.primary}18` },
                  !dohEnabled && styles.providerOptionDisabled,
                ]}
                onPress={() => { if (!dohEnabled) return; handleInteraction(); void handleProviderSelect(provider.key); }}
                disabled={!dohEnabled}
              >
                <View style={[styles.providerRadio, { borderColor: selectedProvider === provider.key ? colors.primary : colors.border }]}>
                  {selectedProvider === provider.key && <View style={[styles.providerRadioFill, { backgroundColor: colors.primary }]} />}
                </View>
                <View style={styles.providerInfo}>
                  <Text style={[styles.providerName, { color: dohEnabled ? colors.textPrimary : colors.textMuted }]}>{provider.label}</Text>
                  <Text style={[styles.providerDescription, { color: colors.textMuted }]}>{provider.description}</Text>
                </View>
              </TouchableOpacity>
            ))}
          </View>
        </View>

        {/* Active Threats */}
        {scanResult && scanResult.threats.length > 0 && (
          <View style={[styles.card, { backgroundColor: colors.surface, borderColor: colors.border }]}>
            <Text style={[styles.cardTitle, { color: colors.textPrimary }]}>Active Threats</Text>
            <View style={styles.threatList}>
              {scanResult.threats.map((threat, idx) => (
                <View key={idx} style={[styles.threatItem, { backgroundColor: colors.surfaceElevated }]}>
                  <View style={[styles.threatAccent, { backgroundColor: threat.severity === 'high' ? colors.danger : threat.severity === 'medium' ? colors.warning : colors.neutral }]} />
                  <View style={styles.threatContent}>
                    <Text style={[styles.threatType, { color: colors.textSecondary }]}>{threat.type.replace(/_/g, ' ').toUpperCase()}</Text>
                    <Text style={[styles.threatDescription, { color: colors.textPrimary }]}>{threat.description}</Text>
                  </View>
                </View>
              ))}
            </View>
            {scanResult.recommendations.length > 0 && (
              <View style={[styles.recommendations, { borderTopColor: colors.border }]}>
                <Text style={[styles.recommendationsTitle, { color: colors.textMuted }]}>Recommendations</Text>
                {scanResult.recommendations.map((rec, idx) => (
                  <View key={idx} style={styles.recommendationItem}>
                    <Text style={[styles.recommendationBullet, { color: colors.primary }]}>→</Text>
                    <Text style={[styles.recommendationText, { color: colors.textSecondary }]}>{rec}</Text>
                  </View>
                ))}
              </View>
            )}
          </View>
        )}

        {scanResult && scanResult.threats.length === 0 && (
          <View style={[styles.allClearCard, { backgroundColor: `${colors.safe}12`, borderColor: `${colors.safe}30` }]}>
            <Text style={styles.allClearIcon}>✅</Text>
            <Text style={[styles.allClearTitle, { color: colors.safe }]}>Network Secure</Text>
            <Text style={[styles.allClearSubtitle, { color: colors.textMuted }]}>No threats detected on this network</Text>
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface NetworkDetailRowProps {
  icon: string;
  label: string;
  value: string;
  valueColor?: string;
  monospace?: boolean;
  colors: ReturnType<typeof useTheme>['colors'];
}

const NetworkDetailRow: React.FC<NetworkDetailRowProps> = ({
  icon, label, value, valueColor, monospace, colors,
}) => (
  <View style={detailStyles.row}>
    <Text style={detailStyles.icon} accessibilityElementsHidden>{icon}</Text>
    <Text style={[detailStyles.label, { color: colors.textMuted }]}>{label}</Text>
    <Text style={[
      detailStyles.value,
      { color: valueColor ?? colors.textPrimary },
      monospace ? detailStyles.monospace : undefined,
    ]}>
      {value}
    </Text>
  </View>
);

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  safeArea: { flex: 1 },
  scrollView: { flex: 1 },
  scrollContent: { paddingHorizontal: 16, paddingBottom: 32 },
  loadingContainer: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 16 },
  loadingText: { fontSize: 14 },
  header: { paddingTop: 20, paddingBottom: 8 },
  headerTitle: { fontSize: 26, fontWeight: '800', letterSpacing: -0.3 },
  headerSubtitle: { fontSize: 12, marginTop: 3 },
  errorBanner: { borderRadius: 10, padding: 12, marginVertical: 8, borderWidth: 1 },
  errorText: { fontSize: 13, textAlign: 'center' },
  card: { borderRadius: 16, padding: 16, marginBottom: 16, borderWidth: 1 },
  cardHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 },
  cardTitle: { fontSize: 16, fontWeight: '700' },
  cardDescription: { fontSize: 13, lineHeight: 18, marginBottom: 12 },
  networkDetails: { gap: 4 },
  noDataText: { fontSize: 13, fontStyle: 'italic', marginBottom: 8 },
  indicatorList: { marginTop: 8, gap: 4 },
  indicatorItem: { flexDirection: 'row', gap: 8 },
  indicatorBullet: { fontSize: 14 },
  indicatorText: { fontSize: 13, flex: 1, lineHeight: 18 },
  scanButton: { marginTop: 12, height: 44, borderRadius: 10, borderWidth: 1, alignItems: 'center', justifyContent: 'center' },
  scanButtonDisabled: { opacity: 0.5 },
  scanButtonText: { fontSize: 14, fontWeight: '700' },
  providerLabel: { fontSize: 11, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 0.8, marginTop: 12, marginBottom: 8 },
  providerList: { gap: 8 },
  providerOption: { flexDirection: 'row', alignItems: 'center', padding: 12, borderRadius: 10, borderWidth: 1, gap: 12 },
  providerOptionDisabled: { opacity: 0.4 },
  providerRadio: { width: 18, height: 18, borderRadius: 9, borderWidth: 2, alignItems: 'center', justifyContent: 'center' },
  providerRadioFill: { width: 8, height: 8, borderRadius: 4 },
  providerInfo: { flex: 1 },
  providerName: { fontSize: 14, fontWeight: '600' },
  providerDescription: { fontSize: 12, marginTop: 2 },
  threatList: { gap: 8, marginTop: 8 },
  threatItem: { flexDirection: 'row', borderRadius: 8, overflow: 'hidden' },
  threatAccent: { width: 4 },
  threatContent: { flex: 1, padding: 10 },
  threatType: { fontSize: 10, fontWeight: '700', letterSpacing: 0.5, marginBottom: 4 },
  threatDescription: { fontSize: 13, lineHeight: 18 },
  recommendations: { marginTop: 16, paddingTop: 12, borderTopWidth: 1 },
  recommendationsTitle: { fontSize: 11, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 },
  recommendationItem: { flexDirection: 'row', gap: 8, marginBottom: 6 },
  recommendationBullet: { fontSize: 13, fontWeight: '700' },
  recommendationText: { fontSize: 13, flex: 1, lineHeight: 18 },
  allClearCard: { borderRadius: 16, padding: 24, alignItems: 'center', borderWidth: 1, marginBottom: 16 },
  allClearIcon: { fontSize: 32, marginBottom: 8 },
  allClearTitle: { fontSize: 18, fontWeight: '700', marginBottom: 4 },
  allClearSubtitle: { fontSize: 13 },
});

const detailStyles = StyleSheet.create({
  row: { flexDirection: 'row', alignItems: 'center', paddingVertical: 8, gap: 10 },
  icon: { fontSize: 16, width: 24, textAlign: 'center' },
  label: { fontSize: 13, width: 90 },
  value: { fontSize: 13, fontWeight: '600', flex: 1 },
  monospace: { fontFamily: 'monospace', fontSize: 12 },
});

/**
 * settings.tsx — Settings Screen
 *
 * Allows the user to:
 *  - Toggle dark / light theme
 *  - Configure API keys stored securely in the device keychain
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
  Alert,
  ActivityIndicator,
  Switch,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { securePrefs } from '../../services/SecurePrefs';
import { useTheme } from '../../theme/ThemeContext';

export default function SettingsScreen() {
  const { colors, isDark, toggleTheme } = useTheme();

  const [hibpKey, setHibpKey] = useState('');
  const [threatKey, setThreatKey] = useState('');
  const [hibpSaved, setHibpSaved] = useState(false);
  const [threatSaved, setThreatSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    (async () => {
      const h = await securePrefs.get('hibp_api_key');
      const t = await securePrefs.get('threat_intel_api_key');
      setHibpSaved(!!h);
      setThreatSaved(!!t);
    })();
  }, []);

  const saveHIBP = useCallback(async () => {
    if (!hibpKey.trim()) return;
    setSaving(true);
    try {
      await securePrefs.set('hibp_api_key', hibpKey.trim());
      setHibpSaved(true);
      setHibpKey('');
      Alert.alert('Saved', 'HIBP API key saved to secure storage.');
    } catch {
      Alert.alert('Error', 'Failed to save key.');
    } finally {
      setSaving(false);
    }
  }, [hibpKey]);

  const saveThreatIntel = useCallback(async () => {
    if (!threatKey.trim()) return;
    setSaving(true);
    try {
      await securePrefs.set('threat_intel_api_key', threatKey.trim());
      setThreatSaved(true);
      setThreatKey('');
      Alert.alert('Saved', 'Threat Intel API key saved to secure storage.');
    } catch {
      Alert.alert('Error', 'Failed to save key.');
    } finally {
      setSaving(false);
    }
  }, [threatKey]);

  const deleteHIBP = useCallback(async () => {
    Alert.alert('Remove Key', 'Remove the HIBP API key?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Remove', style: 'destructive', onPress: async () => {
          await securePrefs.delete('hibp_api_key');
          setHibpSaved(false);
        },
      },
    ]);
  }, []);

  const deleteThreatIntel = useCallback(async () => {
    Alert.alert('Remove Key', 'Remove the Threat Intel API key?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Remove', style: 'destructive', onPress: async () => {
          await securePrefs.delete('threat_intel_api_key');
          setThreatSaved(false);
        },
      },
    ]);
  }, []);

  return (
    <SafeAreaView style={[styles.safe, { backgroundColor: colors.background }]}>
      <ScrollView
        contentContainerStyle={styles.scroll}
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}
      >
        <Text style={[styles.heading, { color: colors.textPrimary }]}>Settings</Text>
        <Text style={[styles.subheading, { color: colors.textMuted }]}>
          Manage your app preferences and API keys.
        </Text>

        {/* ── Appearance ─────────────────────────────────────────────── */}
        <SectionLabel label="Appearance" colors={colors} />

        <View style={[styles.card, { backgroundColor: colors.surface, borderColor: colors.border }]}>
          <View style={styles.rowBetween}>
            <View style={styles.rowLeft}>
              <Text style={styles.rowEmoji}>{isDark ? '🌙' : '☀️'}</Text>
              <View>
                <Text style={[styles.rowTitle, { color: colors.textPrimary }]}>
                  {isDark ? 'Dark Mode' : 'Light Mode'}
                </Text>
                <Text style={[styles.rowDesc, { color: colors.textMuted }]}>
                  {isDark ? 'Switch to light theme' : 'Switch to dark theme'}
                </Text>
              </View>
            </View>
            <Switch
              value={isDark}
              onValueChange={toggleTheme}
              trackColor={{ false: colors.border, true: `${colors.primary}70` }}
              thumbColor={isDark ? colors.primary : colors.textMuted}
              accessibilityLabel="Toggle dark mode"
              accessibilityRole="switch"
            />
          </View>
        </View>

        {/* ── API Keys ───────────────────────────────────────────────── */}
        <SectionLabel label="API Keys" colors={colors} />
        <Text style={[styles.sectionDesc, { color: colors.textMuted }]}>
          Keys are stored in your device's secure enclave — never in code or plain storage.
        </Text>

        {/* HIBP */}
        <View style={[styles.card, { backgroundColor: colors.surface, borderColor: colors.border }]}>
          <View style={styles.cardHeader}>
            <Text style={[styles.cardTitle, { color: colors.textPrimary }]}>
              🔍 HaveIBeenPwned
            </Text>
            {hibpSaved && (
              <View style={[styles.savedBadge, {
                backgroundColor: `${colors.safe}18`,
                borderColor: `${colors.safe}40`,
              }]}>
                <Text style={[styles.savedBadgeText, { color: colors.safe }]}>✓ SET</Text>
              </View>
            )}
          </View>
          <Text style={[styles.cardDesc, { color: colors.textSecondary }]}>
            Required for breach monitoring.{' '}
            <Text style={{ color: colors.primary }}>haveibeenpwned.com/API/Key</Text>
          </Text>

          {hibpSaved ? (
            <TouchableOpacity
              style={[styles.btnDanger, {
                borderColor: `${colors.danger}55`,
                backgroundColor: `${colors.danger}0E`,
              }]}
              onPress={deleteHIBP}
            >
              <Text style={[styles.btnDangerText, { color: colors.danger }]}>Remove Key</Text>
            </TouchableOpacity>
          ) : (
            <>
              <TextInput
                style={[styles.input, {
                  backgroundColor: colors.surfaceElevated,
                  borderColor: colors.border,
                  color: colors.textPrimary,
                }]}
                value={hibpKey}
                onChangeText={setHibpKey}
                placeholder="Paste your HIBP API key"
                placeholderTextColor={colors.textMuted}
                autoCapitalize="none"
                autoCorrect={false}
                secureTextEntry
              />
              <TouchableOpacity
                style={[styles.btn, { backgroundColor: colors.primary }, !hibpKey.trim() && styles.btnDisabled]}
                onPress={saveHIBP}
                disabled={!hibpKey.trim() || saving}
              >
                {saving
                  ? <ActivityIndicator color="#fff" />
                  : <Text style={styles.btnText}>Save Key</Text>
                }
              </TouchableOpacity>
            </>
          )}
        </View>

        {/* Threat Intel */}
        <View style={[styles.card, { backgroundColor: colors.surface, borderColor: colors.border }]}>
          <View style={styles.cardHeader}>
            <Text style={[styles.cardTitle, { color: colors.textPrimary }]}>
              🛡️ Threat Intelligence
            </Text>
            {threatSaved && (
              <View style={[styles.savedBadge, {
                backgroundColor: `${colors.safe}18`,
                borderColor: `${colors.safe}40`,
              }]}>
                <Text style={[styles.savedBadgeText, { color: colors.safe }]}>✓ SET</Text>
              </View>
            )}
          </View>
          <Text style={[styles.cardDesc, { color: colors.textSecondary }]}>
            Required for IP/domain reputation checks.{' '}
            <Text style={{ color: colors.primary }}>virustotal.com</Text>
          </Text>

          {threatSaved ? (
            <TouchableOpacity
              style={[styles.btnDanger, {
                borderColor: `${colors.danger}55`,
                backgroundColor: `${colors.danger}0E`,
              }]}
              onPress={deleteThreatIntel}
            >
              <Text style={[styles.btnDangerText, { color: colors.danger }]}>Remove Key</Text>
            </TouchableOpacity>
          ) : (
            <>
              <TextInput
                style={[styles.input, {
                  backgroundColor: colors.surfaceElevated,
                  borderColor: colors.border,
                  color: colors.textPrimary,
                }]}
                value={threatKey}
                onChangeText={setThreatKey}
                placeholder="Paste your VirusTotal API key"
                placeholderTextColor={colors.textMuted}
                autoCapitalize="none"
                autoCorrect={false}
                secureTextEntry
              />
              <TouchableOpacity
                style={[styles.btn, { backgroundColor: colors.primary }, !threatKey.trim() && styles.btnDisabled]}
                onPress={saveThreatIntel}
                disabled={!threatKey.trim() || saving}
              >
                {saving
                  ? <ActivityIndicator color="#fff" />
                  : <Text style={styles.btnText}>Save Key</Text>
                }
              </TouchableOpacity>
            </>
          )}
        </View>

        {/* Info */}
        <View style={[styles.infoBox, {
          backgroundColor: colors.surfaceElevated,
          borderColor: colors.border,
        }]}>
          <Text style={[styles.infoText, { color: colors.textMuted }]}>
            🔒 Keys are stored using{'\n'}
            iOS Keychain / Android Keystore{'\n'}
            and are never transmitted or logged.
          </Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

// ---------------------------------------------------------------------------
// SectionLabel
// ---------------------------------------------------------------------------

function SectionLabel({ label, colors }: { label: string; colors: ReturnType<typeof useTheme>['colors'] }) {
  return (
    <Text style={[sectionLabelStyles.text, { color: colors.textMuted }]}>{label.toUpperCase()}</Text>
  );
}

const sectionLabelStyles = StyleSheet.create({
  text: {
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 1,
    marginBottom: 8,
    marginTop: 4,
    paddingHorizontal: 4,
  },
});

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  safe: { flex: 1 },
  scroll: { padding: 20, paddingBottom: 40 },
  heading: { fontSize: 28, fontWeight: '800', marginBottom: 4, letterSpacing: -0.3 },
  subheading: { fontSize: 13, lineHeight: 18, marginBottom: 24 },
  sectionDesc: { fontSize: 12, lineHeight: 17, marginBottom: 10, paddingHorizontal: 4 },

  card: {
    borderRadius: 16,
    padding: 16,
    marginBottom: 12,
    borderWidth: 1,
  },
  cardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 6,
  },
  cardTitle: { fontSize: 15, fontWeight: '700' },
  cardDesc: { fontSize: 13, lineHeight: 18, marginBottom: 14 },

  rowBetween: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  rowLeft: { flexDirection: 'row', alignItems: 'center', gap: 12, flex: 1 },
  rowEmoji: { fontSize: 22 },
  rowTitle: { fontSize: 15, fontWeight: '600' },
  rowDesc: { fontSize: 12, marginTop: 1 },

  savedBadge: {
    borderRadius: 8,
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderWidth: 1,
  },
  savedBadgeText: { fontSize: 11, fontWeight: '700' },

  input: {
    borderRadius: 10,
    borderWidth: 1,
    paddingHorizontal: 14,
    paddingVertical: 12,
    fontSize: 14,
    marginBottom: 10,
    fontFamily: 'monospace',
  },
  btn: {
    borderRadius: 10,
    height: 44,
    alignItems: 'center',
    justifyContent: 'center',
  },
  btnDisabled: { opacity: 0.4 },
  btnText: { color: '#fff', fontWeight: '700', fontSize: 15 },
  btnDanger: {
    borderRadius: 10,
    height: 44,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
  },
  btnDangerText: { fontWeight: '600', fontSize: 15 },

  infoBox: {
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
    borderWidth: 1,
    marginTop: 8,
  },
  infoText: { fontSize: 12, textAlign: 'center', lineHeight: 20 },
});

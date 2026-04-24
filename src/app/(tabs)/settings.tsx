/**
 * settings.tsx — Settings Screen
 *
 * Allows the user to configure API keys stored securely in the device keychain.
 * Keys are never shown in plaintext after saving — only a masked indicator.
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
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { securePrefs } from '../../services/SecurePrefs';
import { colors } from '../../theme/colors';

export default function SettingsScreen() {
  const [hibpKey, setHibpKey] = useState('');
  const [threatKey, setThreatKey] = useState('');
  const [hibpSaved, setHibpSaved] = useState(false);
  const [threatSaved, setThreatSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  // Load saved state on mount (just check if keys exist, don't show values)
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
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">

        <Text style={styles.heading}>Settings</Text>
        <Text style={styles.subheading}>API keys are stored in your device's secure enclave — never in code or plain storage.</Text>

        {/* HIBP */}
        <View style={styles.card}>
          <View style={styles.cardHeader}>
            <Text style={styles.cardTitle}>🔍 HaveIBeenPwned</Text>
            {hibpSaved && (
              <View style={styles.savedBadge}>
                <Text style={styles.savedBadgeText}>✓ SET</Text>
              </View>
            )}
          </View>
          <Text style={styles.cardDesc}>
            Required for breach monitoring. Get a key at{' '}
            <Text style={styles.link}>haveibeenpwned.com/API/Key</Text>
          </Text>

          {hibpSaved ? (
            <TouchableOpacity style={styles.btnDanger} onPress={deleteHIBP}>
              <Text style={styles.btnDangerText}>Remove Key</Text>
            </TouchableOpacity>
          ) : (
            <>
              <TextInput
                style={styles.input}
                value={hibpKey}
                onChangeText={setHibpKey}
                placeholder="Paste your HIBP API key"
                placeholderTextColor={colors.textMuted}
                autoCapitalize="none"
                autoCorrect={false}
                secureTextEntry
              />
              <TouchableOpacity
                style={[styles.btn, !hibpKey.trim() && styles.btnDisabled]}
                onPress={saveHIBP}
                disabled={!hibpKey.trim() || saving}
              >
                {saving ? <ActivityIndicator color="#fff" /> : <Text style={styles.btnText}>Save Key</Text>}
              </TouchableOpacity>
            </>
          )}
        </View>

        {/* Threat Intel */}
        <View style={styles.card}>
          <View style={styles.cardHeader}>
            <Text style={styles.cardTitle}>🛡️ Threat Intelligence</Text>
            {threatSaved && (
              <View style={styles.savedBadge}>
                <Text style={styles.savedBadgeText}>✓ SET</Text>
              </View>
            )}
          </View>
          <Text style={styles.cardDesc}>
            Required for IP/domain reputation checks. Get a free key at{' '}
            <Text style={styles.link}>virustotal.com</Text>
          </Text>

          {threatSaved ? (
            <TouchableOpacity style={styles.btnDanger} onPress={deleteThreatIntel}>
              <Text style={styles.btnDangerText}>Remove Key</Text>
            </TouchableOpacity>
          ) : (
            <>
              <TextInput
                style={styles.input}
                value={threatKey}
                onChangeText={setThreatKey}
                placeholder="Paste your VirusTotal API key"
                placeholderTextColor={colors.textMuted}
                autoCapitalize="none"
                autoCorrect={false}
                secureTextEntry
              />
              <TouchableOpacity
                style={[styles.btn, !threatKey.trim() && styles.btnDisabled]}
                onPress={saveThreatIntel}
                disabled={!threatKey.trim() || saving}
              >
                {saving ? <ActivityIndicator color="#fff" /> : <Text style={styles.btnText}>Save Key</Text>}
              </TouchableOpacity>
            </>
          )}
        </View>

        {/* Info */}
        <View style={styles.infoBox}>
          <Text style={styles.infoText}>
            🔒 Keys are stored using {'\n'}
            iOS Keychain / Android Keystore{'\n'}
            and are never transmitted or logged.
          </Text>
        </View>

      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: colors.background },
  scroll: { padding: 20 },
  heading: { color: colors.textPrimary, fontSize: 28, fontWeight: '800', marginBottom: 6 },
  subheading: { color: colors.textMuted, fontSize: 13, lineHeight: 18, marginBottom: 24 },
  card: {
    backgroundColor: colors.surface,
    borderRadius: 16,
    padding: 16,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: colors.border,
  },
  cardHeader: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 },
  cardTitle: { color: colors.textPrimary, fontSize: 16, fontWeight: '700' },
  cardDesc: { color: colors.textSecondary, fontSize: 13, lineHeight: 18, marginBottom: 14 },
  link: { color: colors.primary },
  savedBadge: {
    backgroundColor: `${colors.safe}22`,
    borderRadius: 8,
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderWidth: 1,
    borderColor: `${colors.safe}44`,
  },
  savedBadgeText: { color: colors.safe, fontSize: 11, fontWeight: '700' },
  input: {
    backgroundColor: colors.surfaceElevated,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: colors.border,
    color: colors.textPrimary,
    paddingHorizontal: 14,
    paddingVertical: 12,
    fontSize: 14,
    marginBottom: 10,
    fontFamily: 'monospace',
  },
  btn: {
    backgroundColor: colors.primary,
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
    borderColor: `${colors.danger}66`,
    backgroundColor: `${colors.danger}11`,
  },
  btnDangerText: { color: colors.danger, fontWeight: '600', fontSize: 15 },
  infoBox: {
    backgroundColor: colors.surfaceElevated,
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: colors.border,
    marginTop: 8,
  },
  infoText: { color: colors.textMuted, fontSize: 12, textAlign: 'center', lineHeight: 20 },
});

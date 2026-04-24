/**
 * auth.tsx — Authentication Screen
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  ScrollView,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { router } from 'expo-router';
import { authService } from '../services/AuthService';
import { sessionLockService } from '../services/SessionLockService';
import { securePrefs } from '../services/SecurePrefs';
import { colors } from '../theme/colors';

type Screen = 'loading' | 'setup' | 'biometric' | 'pin' | 'locked';

export default function AuthScreen() {
  const [screen, setScreen] = useState<Screen>('loading');
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [lockRemaining, setLockRemaining] = useState(0);
  const [attempts, setAttempts] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── helpers ──────────────────────────────────────────────────────────────

  const goToDashboard = useCallback(() => {
    sessionLockService.startSession();
    router.replace('/(tabs)');
  }, []);

  const startCountdown = useCallback((ms: number) => {
    setLockRemaining(ms);
    if (timerRef.current) clearInterval(timerRef.current);
    timerRef.current = setInterval(() => {
      setLockRemaining(prev => {
        if (prev <= 1000) {
          clearInterval(timerRef.current!);
          timerRef.current = null;
          setScreen('pin');
          setError('');
          return 0;
        }
        return prev - 1000;
      });
    }, 1000);
  }, []);

  useEffect(() => () => { if (timerRef.current) clearInterval(timerRef.current); }, []);

  // ── init: check if PIN exists ─────────────────────────────────────────────

  useEffect(() => {
    (async () => {
      try {
        const stored = await securePrefs.get('pin_hash');
        if (!stored) {
          setScreen('setup');
        } else {
          setScreen('biometric');
          tryBiometric();
        }
      } catch {
        setScreen('setup');
      }
    })();
  }, []);

  // ── biometric ─────────────────────────────────────────────────────────────

  const tryBiometric = useCallback(async () => {
    setBusy(true);
    setError('');
    try {
      const result = await authService.authenticate();
      if (result.success) {
        goToDashboard();
        return;
      }
      if (result.error === 'biometric_unavailable' || result.error === 'biometric_failed') {
        setScreen('pin');
      } else if (result.error === 'account_locked') {
        setScreen('locked');
      }
    } catch {
      setScreen('pin');
    } finally {
      setBusy(false);
    }
  }, [goToDashboard]);

  // ── PIN setup ─────────────────────────────────────────────────────────────

  const handleSetup = useCallback(async () => {
    if (pin.length < 4) { setError('PIN must be at least 4 digits.'); return; }
    if (pin !== confirmPin) { setError('PINs do not match.'); setConfirmPin(''); return; }

    setBusy(true);
    setError('');
    try {
      await authService.setupPIN(pin);
      const ok = await authService.verifyPIN(pin);
      if (ok) {
        goToDashboard();
      } else {
        setPin('');
        setConfirmPin('');
        setScreen('pin');
        setError('PIN saved. Please enter it to continue.');
      }
    } catch (e) {
      setError('Could not save PIN: ' + (e instanceof Error ? e.message : String(e)));
      setPin('');
      setConfirmPin('');
    } finally {
      setBusy(false);
    }
  }, [pin, confirmPin, goToDashboard]);

  // ── PIN verify ────────────────────────────────────────────────────────────

  const handlePIN = useCallback(async () => {
    if (pin.length < 4) { setError('PIN must be at least 4 digits.'); return; }

    setBusy(true);
    setError('');
    const entered = pin;
    setPin('');

    try {
      const ok = await authService.verifyPIN(entered);
      if (ok) {
        goToDashboard();
        return;
      }

      const count = authService.getFailedAttempts();
      setAttempts(count);

      if (count >= 10) {
        setScreen('locked');
        setError('Account permanently locked.');
      } else if (count >= 5) {
        setScreen('locked');
        startCountdown(300_000);
        setError('Too many attempts. Locked 5 minutes.');
      } else if (count >= 3) {
        setScreen('locked');
        startCountdown(30_000);
        setError('Too many attempts. Locked 30 seconds.');
      } else {
        setError(`Wrong PIN. ${10 - count} attempts left.`);
      }
    } catch (e) {
      setError('Error: ' + (e instanceof Error ? e.message : String(e)));
    } finally {
      setBusy(false);
    }
  }, [pin, goToDashboard, startCountdown]);

  // ── render ────────────────────────────────────────────────────────────────

  const fmt = (ms: number) => {
    const s = Math.ceil(ms / 1000);
    return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
  };

  if (screen === 'loading') {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color={colors.primary} />
      </View>
    );
  }

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">

        {/* Header */}
        <View style={styles.header}>
          <Text style={styles.appName}>AEGIS</Text>
          <Text style={styles.tagline}>Personal Cybersecurity Companion</Text>
        </View>

        {/* Setup */}
        {screen === 'setup' && (
          <View style={styles.card}>
            <Text style={styles.emoji}>🔐</Text>
            <Text style={styles.title}>Create PIN</Text>
            <Text style={styles.subtitle}>Set a PIN to secure your vault (min 4 digits)</Text>

            <TextInput
              style={styles.input}
              value={pin}
              onChangeText={t => { setPin(t); setError(''); }}
              placeholder="New PIN"
              placeholderTextColor={colors.textMuted}
              secureTextEntry
              keyboardType="number-pad"
              maxLength={12}
              returnKeyType="next"
            />
            <TextInput
              style={styles.input}
              value={confirmPin}
              onChangeText={t => { setConfirmPin(t); setError(''); }}
              placeholder="Confirm PIN"
              placeholderTextColor={colors.textMuted}
              secureTextEntry
              keyboardType="number-pad"
              maxLength={12}
              returnKeyType="done"
              onSubmitEditing={handleSetup}
            />

            {!!error && <Text style={styles.error}>{error}</Text>}

            {busy
              ? <ActivityIndicator color={colors.primary} style={styles.loader} />
              : <TouchableOpacity
                  style={[styles.btn, pin.length < 4 && styles.btnDisabled]}
                  onPress={handleSetup}
                  disabled={pin.length < 4}
                >
                  <Text style={styles.btnText}>Create PIN</Text>
                </TouchableOpacity>
            }
          </View>
        )}

        {/* Biometric */}
        {screen === 'biometric' && (
          <View style={styles.card}>
            <Text style={styles.emoji}>🔐</Text>
            <Text style={styles.title}>Authenticate</Text>
            <Text style={styles.subtitle}>Use biometrics or PIN to unlock Aegis</Text>

            {!!error && <Text style={styles.error}>{error}</Text>}

            {busy
              ? <ActivityIndicator color={colors.primary} style={styles.loader} />
              : <>
                  <TouchableOpacity style={styles.btn} onPress={tryBiometric}>
                    <Text style={styles.btnText}>Use Biometrics</Text>
                  </TouchableOpacity>
                  <TouchableOpacity style={styles.btnSecondary} onPress={() => { setBusy(false); setScreen('pin'); }}>
                    <Text style={styles.btnSecondaryText}>Use PIN Instead</Text>
                  </TouchableOpacity>
                </>
            }
          </View>
        )}

        {/* PIN entry */}
        {screen === 'pin' && (
          <View style={styles.card}>
            <Text style={styles.emoji}>🔑</Text>
            <Text style={styles.title}>Enter PIN</Text>
            {attempts > 0 && (
              <Text style={styles.warn}>{attempts} failed attempt{attempts !== 1 ? 's' : ''}</Text>
            )}

            <TextInput
              style={styles.input}
              value={pin}
              onChangeText={t => { setPin(t); setError(''); }}
              placeholder="Enter PIN"
              placeholderTextColor={colors.textMuted}
              secureTextEntry
              keyboardType="number-pad"
              maxLength={12}
              autoFocus
              returnKeyType="done"
              onSubmitEditing={handlePIN}
            />

            {!!error && <Text style={styles.error}>{error}</Text>}

            {busy
              ? <ActivityIndicator color={colors.primary} style={styles.loader} />
              : <>
                  <TouchableOpacity
                    style={[styles.btn, pin.length < 4 && styles.btnDisabled]}
                    onPress={handlePIN}
                    disabled={pin.length < 4}
                  >
                    <Text style={styles.btnText}>Unlock</Text>
                  </TouchableOpacity>
                  <TouchableOpacity style={styles.btnSecondary} onPress={() => { setScreen('biometric'); tryBiometric(); }}>
                    <Text style={styles.btnSecondaryText}>Use Biometrics</Text>
                  </TouchableOpacity>
                </>
            }
          </View>
        )}

        {/* Locked */}
        {screen === 'locked' && (
          <View style={styles.card}>
            <Text style={styles.emoji}>🔒</Text>
            <Text style={[styles.title, { color: colors.danger }]}>
              {lockRemaining === 0 ? 'Account Locked' : 'Too Many Attempts'}
            </Text>
            {lockRemaining > 0
              ? <Text style={styles.countdown}>{fmt(lockRemaining)}</Text>
              : <Text style={styles.subtitle}>Contact support to recover access.</Text>
            }
            {!!error && <Text style={styles.error}>{error}</Text>}
          </View>
        )}

        <Text style={styles.footer}>🛡️ Zero-trust · AES-256-GCM · OWASP MASVS L2</Text>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: colors.background },
  center: { flex: 1, backgroundColor: colors.background, alignItems: 'center', justifyContent: 'center' },
  scroll: { flexGrow: 1, paddingHorizontal: 24, paddingVertical: 32 },
  header: { alignItems: 'center', marginBottom: 40 },
  appName: { color: colors.primary, fontSize: 36, fontWeight: '900', letterSpacing: 8, fontFamily: 'monospace' },
  tagline: { color: colors.textMuted, fontSize: 13, marginTop: 6 },
  card: { alignItems: 'center', paddingVertical: 8 },
  emoji: { fontSize: 56, marginBottom: 16 },
  title: { color: colors.textPrimary, fontSize: 24, fontWeight: '700', marginBottom: 8 },
  subtitle: { color: colors.textSecondary, fontSize: 14, textAlign: 'center', lineHeight: 20, marginBottom: 24, paddingHorizontal: 16 },
  warn: { color: colors.warning, fontSize: 13, fontWeight: '600', marginBottom: 12 },
  input: {
    width: '100%', height: 56, backgroundColor: colors.surface,
    borderRadius: 12, borderWidth: 1, borderColor: colors.border,
    paddingHorizontal: 16, color: colors.textPrimary, fontSize: 20,
    letterSpacing: 8, textAlign: 'center', marginBottom: 12, fontFamily: 'monospace',
  },
  error: { color: colors.danger, fontSize: 13, textAlign: 'center', marginBottom: 12 },
  loader: { marginVertical: 20 },
  btn: {
    width: '100%', height: 52, backgroundColor: colors.primary,
    borderRadius: 12, alignItems: 'center', justifyContent: 'center', marginBottom: 12,
  },
  btnDisabled: { opacity: 0.4 },
  btnText: { color: '#fff', fontSize: 16, fontWeight: '700' },
  btnSecondary: {
    width: '100%', height: 48, borderRadius: 12,
    alignItems: 'center', justifyContent: 'center',
    borderWidth: 1, borderColor: colors.border,
  },
  btnSecondaryText: { color: colors.textSecondary, fontSize: 15, fontWeight: '600' },
  countdown: { color: colors.warning, fontSize: 48, fontWeight: '700', fontFamily: 'monospace', marginVertical: 16 },
  footer: { color: colors.textMuted, fontSize: 11, textAlign: 'center', marginTop: 40 },
});

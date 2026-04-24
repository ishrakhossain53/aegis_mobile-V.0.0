/**
 * _layout.tsx — Root Layout and App Initialization
 *
 * This is the root layout for the Aegis app. It:
 *  1. Initializes RASPGuard before rendering any screen content (Requirement 26.2)
 *  2. Registers a background monitoring task for threat detection (Requirement 26.3)
 *  3. Wraps all protected tab screens with session lock enforcement (Requirement 26.1)
 *  4. Redirects to the auth screen immediately when the session becomes locked (Requirement 26.4)
 *
 * Navigation structure:
 *  - /auth          → Authentication screen (public)
 *  - /(tabs)/*      → Protected tab screens (require active session)
 *
 * Session lock enforcement:
 *  - Subscribes to SessionLockService.onLock() on mount
 *  - When the session locks, immediately navigates to /auth via router.replace
 *  - Unsubscribes on unmount to prevent memory leaks
 *
 * RASP initialization:
 *  - Calls raspGuard.initialize() during the splash/loading phase
 *  - No screen content is rendered until initialization completes
 *
 * Background threat monitoring:
 *  - Calls threatMonitorService.startMonitoring() after RASP initialization
 *  - Note: expo-task-manager / expo-background-fetch are not in the project
 *    dependencies. Monitoring runs as a foreground interval task via
 *    ThreatMonitorService's built-in 60-second polling loop. This is the
 *    appropriate approach for the Expo managed workflow without those packages.
 *
 * Requirements: 26.1, 26.2, 26.3, 26.4
 */

import React, { useEffect, useState, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ActivityIndicator,
} from 'react-native';
import { Stack, router } from 'expo-router';
import { raspGuard } from '../rasp/RASPGuard';
import { sessionLockService } from '../services/SessionLockService';
import { threatMonitorService } from '../services/ThreatMonitorService';
import { threatAgent } from '../modules/threat/ThreatAgent';
import { threatStore } from '../modules/threat/ThreatStore';
import { networkStore } from '../modules/network/NetworkStore';
import { colors } from '../theme/colors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type InitState =
  | 'initializing' // RASP + background task setup in progress
  | 'ready'        // Initialization complete — render navigation
  | 'error';       // Initialization failed (RASP violation or unexpected error)

// ---------------------------------------------------------------------------
// Root Layout Component
// ---------------------------------------------------------------------------

export default function RootLayout() {
  const [initState, setInitState] = useState<InitState>('initializing');
  const [initError, setInitError] = useState<string | null>(null);

  // -------------------------------------------------------------------------
  // Session lock handler
  // Redirects to /auth immediately when the session transitions to locked.
  // Requirement 26.4
  // -------------------------------------------------------------------------

  const handleSessionLock = useCallback(() => {
    router.replace('/auth');
  }, []);

  // -------------------------------------------------------------------------
  // App initialization
  // Runs once on mount before any screen content is rendered.
  // Requirements 26.2, 26.3
  // -------------------------------------------------------------------------

  useEffect(() => {
    let isMounted = true;

    async function initialize() {
      try {
        // Step 1: Initialize RASP Guard before rendering any screen content.
        // This performs a code-signature check and logs any integrity violations.
        // Requirement 26.2
        await raspGuard.initialize();

        if (!isMounted) return;

        // Step 2: Register the background task for threat monitoring.
        // ThreatMonitorService runs a 60-second polling loop internally.
        // expo-task-manager / expo-background-fetch are not in the project
        // dependencies, so we use the service's built-in interval mechanism.
        // Requirement 26.3
        await threatMonitorService.startMonitoring();

        if (!isMounted) return;

        // Step 3: Hydrate Phase 2 stores from encrypted SQLite cache.
        // These run in parallel — failures are non-fatal (stores degrade gracefully).
        await Promise.allSettled([
          threatStore.hydrate(),
          networkStore.hydrate(),
        ]);

        if (!isMounted) return;

        // Step 4: Register Phase 2 background threat agent task.
        // Gracefully degrades when expo-task-manager is not installed.
        threatAgent.registerBackgroundTask();

        if (!isMounted) return;

        // Step 5: Subscribe to session lock events so we can redirect to /auth.
        // Requirement 26.4
        sessionLockService.onLock(handleSessionLock);

        // Initialization complete — allow navigation to render.
        setInitState('ready');
      } catch (err) {
        if (!isMounted) return;
        const message =
          err instanceof Error ? err.message : 'App initialization failed.';
        setInitError(message);
        setInitState('error');
      }
    }

    void initialize();

    return () => {
      isMounted = false;
      // Clean up: unsubscribe from lock events and stop background monitoring.
      sessionLockService.offLock(handleSessionLock);
      threatMonitorService.stopMonitoring();
    };
  }, [handleSessionLock]);

  // -------------------------------------------------------------------------
  // Splash / loading screen
  // Shown while RASP and background task initialization are in progress.
  // No protected screen content is rendered until initState === 'ready'.
  // Requirement 26.2
  // -------------------------------------------------------------------------

  if (initState === 'initializing') {
    return (
      <View
        style={styles.splashContainer}
        accessibilityLabel="Initializing Aegis security…"
        accessibilityRole="none"
      >
        <Text style={styles.splashAppName} accessibilityRole="header">
          AEGIS
        </Text>
        <Text style={styles.splashTagline}>Personal Cybersecurity Companion</Text>
        <ActivityIndicator
          size="large"
          color={colors.primary}
          style={styles.splashLoader}
          accessibilityLabel="Loading…"
        />
        <Text style={styles.splashStatus}>Initializing security…</Text>
      </View>
    );
  }

  // -------------------------------------------------------------------------
  // Error screen
  // Shown when RASP initialization or background task setup fails.
  // -------------------------------------------------------------------------

  if (initState === 'error') {
    return (
      <View
        style={styles.errorContainer}
        accessibilityLabel="Initialization error"
        accessibilityRole="none"
      >
        <Text style={styles.errorIcon} accessibilityElementsHidden>
          🔒
        </Text>
        <Text style={styles.errorTitle} accessibilityRole="header">
          Security Check Failed
        </Text>
        <Text style={styles.errorMessage} accessibilityRole="alert">
          {initError ?? 'An unexpected error occurred during initialization.'}
        </Text>
        <Text style={styles.errorHint}>
          Please restart the application. If this issue persists, contact support.
        </Text>
      </View>
    );
  }

  // -------------------------------------------------------------------------
  // Main navigation stack
  // Rendered only after successful initialization (Requirement 26.2).
  //
  // Stack screens:
  //  - auth:   Public authentication screen (no header)
  //  - (tabs): Protected tab group — all tab screens are wrapped by this
  //            layout which enforces session lock (Requirement 26.1)
  // -------------------------------------------------------------------------

  return (
    <Stack screenOptions={{ headerShown: false }}>
      <Stack.Screen
        name="auth"
        options={{
          headerShown: false,
          // Prevent back-navigation to protected screens from auth
          gestureEnabled: false,
        }}
      />
      <Stack.Screen
        name="(tabs)"
        options={{
          headerShown: false,
          // Prevent swiping back to auth from protected tabs
          gestureEnabled: false,
        }}
      />
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  // Splash / loading screen
  splashContainer: {
    flex: 1,
    backgroundColor: colors.background,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 32,
  },
  splashAppName: {
    color: colors.primary,
    fontSize: 40,
    fontWeight: '900',
    letterSpacing: 10,
    fontFamily: 'monospace',
    marginBottom: 8,
  },
  splashTagline: {
    color: colors.textMuted,
    fontSize: 13,
    letterSpacing: 0.5,
    marginBottom: 48,
  },
  splashLoader: {
    marginBottom: 16,
  },
  splashStatus: {
    color: colors.textMuted,
    fontSize: 13,
    letterSpacing: 0.3,
  },

  // Error screen
  errorContainer: {
    flex: 1,
    backgroundColor: colors.background,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 32,
  },
  errorIcon: {
    fontSize: 56,
    marginBottom: 24,
  },
  errorTitle: {
    color: colors.danger,
    fontSize: 22,
    fontWeight: '700',
    marginBottom: 12,
    textAlign: 'center',
  },
  errorMessage: {
    color: colors.textSecondary,
    fontSize: 14,
    textAlign: 'center',
    lineHeight: 20,
    marginBottom: 16,
  },
  errorHint: {
    color: colors.textMuted,
    fontSize: 12,
    textAlign: 'center',
    lineHeight: 18,
  },
});

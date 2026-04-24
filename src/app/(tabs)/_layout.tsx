/**
 * (tabs)/_layout.tsx — Tab Navigator Layout
 *
 * Defines the bottom tab bar for all protected tab screens.
 * This layout is rendered inside the root _layout.tsx Stack, which
 * enforces session lock before this layout is ever shown.
 *
 * Tabs:
 *  - index    → Security Dashboard (🛡️)
 *  - vault    → Credential Vault (🔑)
 *  - network  → Network Safety (📡)
 *  - alerts   → Alerts (🔔)
 *  - audit    → App Audit (🔍)
 *
 * Session activity tracking:
 *  - Each tab press resets the SessionLockService inactivity timer so that
 *    navigating between tabs counts as user interaction (Requirement 2.5).
 *
 * Requirements: 26.1
 */

import React, { useCallback } from 'react';
import { Text } from 'react-native';
import { Tabs } from 'expo-router';
import { sessionLockService } from '../../services/SessionLockService';
import { colors } from '../../theme/colors';

export default function TabsLayout() {
  // Reset the session inactivity timer on every tab press so that tab
  // navigation counts as user interaction (Requirement 2.5).
  const handleTabPress = useCallback(() => {
    sessionLockService.resetTimer();
  }, []);

  return (
    <Tabs
      screenOptions={{
        headerShown: false,
        tabBarStyle: {
          backgroundColor: colors.surface,
          borderTopColor: colors.border,
          borderTopWidth: 1,
        },
        tabBarActiveTintColor: colors.primary,
        tabBarInactiveTintColor: colors.textMuted,
        tabBarLabelStyle: {
          fontSize: 11,
          fontWeight: '600',
        },
      }}
      screenListeners={{
        tabPress: handleTabPress,
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: 'Dashboard',
          tabBarIcon: ({ color }) => (
            // Shield emoji as tab icon — no native icon library dependency
            <TabIcon emoji="🛡️" color={color} />
          ),
          tabBarAccessibilityLabel: 'Security Dashboard tab',
        }}
      />
      <Tabs.Screen
        name="vault"
        options={{
          title: 'Vault',
          tabBarIcon: ({ color }) => (
            <TabIcon emoji="🔑" color={color} />
          ),
          tabBarAccessibilityLabel: 'Credential Vault tab',
        }}
      />
      <Tabs.Screen
        name="network"
        options={{
          title: 'Network',
          tabBarIcon: ({ color }) => (
            <TabIcon emoji="📡" color={color} />
          ),
          tabBarAccessibilityLabel: 'Network Safety tab',
        }}
      />
      <Tabs.Screen
        name="alerts"
        options={{
          title: 'Alerts',
          tabBarIcon: ({ color }) => (
            <TabIcon emoji="🔔" color={color} />
          ),
          tabBarAccessibilityLabel: 'Security Alerts tab',
        }}
      />
      <Tabs.Screen
        name="audit"
        options={{
          title: 'Audit',
          tabBarIcon: ({ color }) => (
            <TabIcon emoji="🔍" color={color} />
          ),
          tabBarAccessibilityLabel: 'App Permission Audit tab',
        }}
      />
      <Tabs.Screen
        name="settings"
        options={{
          title: 'Settings',
          tabBarIcon: ({ color }) => (
            <TabIcon emoji="⚙️" color={color} />
          ),
          tabBarAccessibilityLabel: 'Settings tab',
        }}
      />
    </Tabs>
  );
}

// ---------------------------------------------------------------------------
// TabIcon helper
// ---------------------------------------------------------------------------

/**
 * Simple emoji-based tab icon.
 * Uses opacity to communicate active/inactive state since emoji characters
 * cannot be tinted with a color prop directly.
 *
 * @param emoji  - The emoji character to display.
 * @param color  - The tint color provided by the Tabs navigator (active or inactive).
 */
function TabIcon({ emoji, color }: { emoji: string; color: string }) {
  const isActive = color === colors.primary;
  return (
    <Text
      // eslint-disable-next-line react-native/no-inline-styles
      style={{ fontSize: 20, opacity: isActive ? 1 : 0.5 }}
      accessibilityElementsHidden
    >
      {emoji}
    </Text>
  );
}

/**
 * (tabs)/_layout.tsx — Tab Navigator Layout
 *
 * Defines the bottom tab bar for all protected tab screens.
 * Responds to dark/light theme changes via ThemeContext.
 *
 * Requirements: 26.1
 */

import React, { useCallback } from 'react';
import { Text, View, StyleSheet } from 'react-native';
import { Tabs } from 'expo-router';
import { sessionLockService } from '../../services/SessionLockService';
import { useTheme } from '../../theme/ThemeContext';

export default function TabsLayout() {
  const { colors, isDark } = useTheme();

  const handleTabPress = useCallback(() => {
    sessionLockService.resetTimer();
  }, []);

  return (
    <Tabs
      screenOptions={{
        headerShown: false,
        tabBarStyle: {
          backgroundColor: colors.tabBar,
          borderTopColor: colors.tabBarBorder,
          borderTopWidth: StyleSheet.hairlineWidth,
          height: 60,
          paddingBottom: 8,
          paddingTop: 6,
          elevation: isDark ? 0 : 8,
          shadowColor: '#000',
          shadowOffset: { width: 0, height: -2 },
          shadowOpacity: isDark ? 0 : 0.06,
          shadowRadius: 8,
        },
        tabBarActiveTintColor: colors.primary,
        tabBarInactiveTintColor: colors.textMuted,
        tabBarLabelStyle: {
          fontSize: 10,
          fontWeight: '600',
          letterSpacing: 0.2,
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
          tabBarIcon: ({ color, focused }) => (
            <TabIcon emoji="🛡️" color={color} focused={focused} />
          ),
          tabBarAccessibilityLabel: 'Security Dashboard tab',
        }}
      />
      <Tabs.Screen
        name="vault"
        options={{
          title: 'Vault',
          tabBarIcon: ({ color, focused }) => (
            <TabIcon emoji="🔑" color={color} focused={focused} />
          ),
          tabBarAccessibilityLabel: 'Credential Vault tab',
        }}
      />
      <Tabs.Screen
        name="network"
        options={{
          title: 'Network',
          tabBarIcon: ({ color, focused }) => (
            <TabIcon emoji="📡" color={color} focused={focused} />
          ),
          tabBarAccessibilityLabel: 'Network Safety tab',
        }}
      />
      <Tabs.Screen
        name="alerts"
        options={{
          title: 'Alerts',
          tabBarIcon: ({ color, focused }) => (
            <TabIcon emoji="🔔" color={color} focused={focused} />
          ),
          tabBarAccessibilityLabel: 'Security Alerts tab',
        }}
      />
      <Tabs.Screen
        name="audit"
        options={{
          title: 'Audit',
          tabBarIcon: ({ color, focused }) => (
            <TabIcon emoji="🔍" color={color} focused={focused} />
          ),
          tabBarAccessibilityLabel: 'App Permission Audit tab',
        }}
      />
      <Tabs.Screen
        name="settings"
        options={{
          title: 'Settings',
          tabBarIcon: ({ color, focused }) => (
            <TabIcon emoji="⚙️" color={color} focused={focused} />
          ),
          tabBarAccessibilityLabel: 'Settings tab',
        }}
      />
    </Tabs>
  );
}

// ---------------------------------------------------------------------------
// TabIcon
// ---------------------------------------------------------------------------

function TabIcon({
  emoji,
  color,
  focused,
}: {
  emoji: string;
  color: string;
  focused: boolean;
}) {
  return (
    <View style={[tabIconStyles.wrapper, focused && tabIconStyles.wrapperActive]}>
      <Text
        style={[tabIconStyles.emoji, { opacity: focused ? 1 : 0.45 }]}
        accessibilityElementsHidden
      >
        {emoji}
      </Text>
    </View>
  );
}

const tabIconStyles = StyleSheet.create({
  wrapper: {
    width: 32,
    height: 24,
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: 8,
  },
  wrapperActive: {
    // subtle highlight handled by opacity on emoji
  },
  emoji: {
    fontSize: 19,
  },
});

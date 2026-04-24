/**
 * CredentialCard — Aegis Personal Cybersecurity Companion
 *
 * Displays a credential entry with:
 *   - Type icon (emoji-based), title, and truncated username
 *   - Copy button that invokes SecureClipboardService WITHOUT displaying the value
 *   - TOTP type shows a live countdown ring (30s cycle) next to the copy button
 *
 * SECURITY: This component NEVER renders plaintext password, passkey,
 * totpSeed, or apiKey in the UI.
 *
 * Requirements: 13.1, 13.2, 13.3
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ViewStyle,
} from 'react-native';
import { Credential } from '../types/index';
import { secureClipboardService } from '../services/SecureClipboardService';
import { vaultService } from '../services/VaultService';
import { colors } from '../theme/colors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CredentialCardProps {
  credential: Credential;
  onPress?: () => void;
  onLongPress?: () => void;
  onCopy?: (credential: Credential) => void;
  style?: ViewStyle;
}

// ---------------------------------------------------------------------------
// Type icon map
// ---------------------------------------------------------------------------

const TYPE_ICONS: Record<Credential['type'], string> = {
  password: '🔑',
  passkey: '🛡️',
  totp: '🔐',
  apiKey: '🗝️',
};

const TYPE_LABELS: Record<Credential['type'], string> = {
  password: 'Password',
  passkey: 'Passkey',
  totp: 'TOTP',
  apiKey: 'API Key',
};

// ---------------------------------------------------------------------------
// TOTP Countdown Ring
// ---------------------------------------------------------------------------

interface TOTPCountdownProps {
  /** Seconds remaining in the 30s cycle */
  remainingSeconds: number;
}

const TOTPCountdown: React.FC<TOTPCountdownProps> = ({ remainingSeconds }) => {
  const progress = remainingSeconds / 30;
  const isUrgent = remainingSeconds <= 5;
  const ringColor = isUrgent ? '#FF3B30' : '#00FF88';

  // Simple text-based countdown — no SVG dependency needed
  return (
    <View
      style={[styles.totpRing, { borderColor: ringColor }]}
      accessibilityLabel={`TOTP code refreshes in ${remainingSeconds} seconds`}
    >
      <Text style={[styles.totpCountdown, { color: ringColor }]}>
        {remainingSeconds}
      </Text>
    </View>
  );
};

// ---------------------------------------------------------------------------
// CredentialCard
// ---------------------------------------------------------------------------

export const CredentialCard: React.FC<CredentialCardProps> = ({
  credential,
  onPress,
  onLongPress,
  onCopy,
  style,
}) => {
  const [totpRemaining, setTotpRemaining] = useState<number>(0);
  const [copyFeedback, setCopyFeedback] = useState(false);

  // TOTP countdown timer — updates every second
  useEffect(() => {
    if (credential.type !== 'totp') return;

    const updateCountdown = () => {
      const nowSeconds = Math.floor(Date.now() / 1000);
      const remaining = 30 - (nowSeconds % 30);
      setTotpRemaining(remaining);
    };

    updateCountdown();
    const interval = setInterval(updateCountdown, 1000);
    return () => clearInterval(interval);
  }, [credential.type]);

  // Copy handler — retrieves the secret value via VaultService and copies
  // it to the secure clipboard WITHOUT ever rendering it in the UI.
  const handleCopy = useCallback(async () => {
    try {
      // Retrieve the full credential (with decrypted fields) from the vault
      const fullCredential = await vaultService.getCredential(credential.id);
      if (!fullCredential) return;

      let valueToCopy: string | undefined;

      switch (fullCredential.type) {
        case 'password':
          valueToCopy = fullCredential.password;
          break;
        case 'passkey':
          valueToCopy = fullCredential.passkey;
          break;
        case 'totp':
          // For TOTP, generate the current code and copy it
          if (fullCredential.totpSeed) {
            const totpCode = await vaultService.generateTOTP(fullCredential.totpSeed);
            valueToCopy = totpCode.code;
          }
          break;
        case 'apiKey':
          valueToCopy = fullCredential.apiKey;
          break;
      }

      if (valueToCopy) {
        const dataType =
          fullCredential.type === 'totp'
            ? 'totp'
            : fullCredential.type === 'apiKey'
            ? 'apiKey'
            : 'password';
        await secureClipboardService.copy(valueToCopy, dataType);

        // Brief visual feedback
        setCopyFeedback(true);
        setTimeout(() => setCopyFeedback(false), 1500);

        onCopy?.(credential);
      }
    } catch {
      // Silently fail — do not expose error details in UI
    }
  }, [credential, onCopy]);

  const icon = TYPE_ICONS[credential.type];
  const typeLabel = TYPE_LABELS[credential.type];

  return (
    <TouchableOpacity
      onPress={onPress}
      onLongPress={onLongPress}
      activeOpacity={0.75}
      style={[styles.container, style]}
      accessibilityLabel={`${typeLabel}: ${credential.title}${credential.username ? `, ${credential.username}` : ''}`}
      accessibilityRole="button"
      accessibilityHint="Tap to view details, long press for options"
    >
      {/* Left: type icon */}
      <View style={styles.iconContainer} accessibilityElementsHidden>
        <Text style={styles.icon}>{icon}</Text>
      </View>

      {/* Center: title + username */}
      <View style={styles.content}>
        <Text style={styles.title} numberOfLines={1}>
          {credential.title}
        </Text>
        {credential.username ? (
          <Text style={styles.username} numberOfLines={1}>
            {credential.username}
          </Text>
        ) : (
          <Text style={styles.typeLabel}>{typeLabel}</Text>
        )}
      </View>

      {/* Right: TOTP countdown (if applicable) + copy button */}
      <View style={styles.actions}>
        {credential.type === 'totp' && totpRemaining > 0 && (
          <TOTPCountdown remainingSeconds={totpRemaining} />
        )}
        <TouchableOpacity
          onPress={handleCopy}
          style={[styles.copyButton, copyFeedback && styles.copyButtonActive]}
          accessibilityLabel={`Copy ${typeLabel} for ${credential.title}`}
          accessibilityRole="button"
          accessibilityHint="Copies to clipboard and clears after 30 seconds"
        >
          <Text style={styles.copyIcon}>{copyFeedback ? '✓' : '⎘'}</Text>
        </TouchableOpacity>
      </View>
    </TouchableOpacity>
  );
};

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.surface,
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: colors.border,
  },
  iconContainer: {
    width: 40,
    height: 40,
    borderRadius: 10,
    backgroundColor: colors.surfaceElevated,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  icon: {
    fontSize: 20,
  },
  content: {
    flex: 1,
    marginRight: 8,
  },
  title: {
    color: colors.textPrimary,
    fontSize: 15,
    fontWeight: '600',
    marginBottom: 2,
  },
  username: {
    color: colors.textSecondary,
    fontSize: 13,
  },
  typeLabel: {
    color: colors.textMuted,
    fontSize: 12,
  },
  actions: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  totpRing: {
    width: 32,
    height: 32,
    borderRadius: 16,
    borderWidth: 2,
    alignItems: 'center',
    justifyContent: 'center',
  },
  totpCountdown: {
    fontSize: 11,
    fontWeight: '700',
    fontFamily: 'monospace',
  },
  copyButton: {
    width: 36,
    height: 36,
    borderRadius: 8,
    backgroundColor: colors.surfaceElevated,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: colors.border,
  },
  copyButtonActive: {
    backgroundColor: colors.safe,
    borderColor: colors.safe,
  },
  copyIcon: {
    fontSize: 16,
    color: colors.textSecondary,
  },
});

export default CredentialCard;

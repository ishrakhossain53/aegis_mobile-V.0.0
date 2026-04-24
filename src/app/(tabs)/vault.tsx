/**
 * vault.tsx — Vault Screen
 *
 * Encrypted credential vault with:
 *  - Real-time search bar filtering by title/username/URL/tags
 *  - Filter chips: All / Passwords / Passkeys / TOTP / API Keys
 *  - FlatList of CredentialCard components
 *  - FAB to add new credential
 *  - Tap card → credential detail bottom sheet (full decrypt on demand)
 *  - Long-press → edit/delete context menu
 *  - Copy action → SecureClipboardService + toast with countdown
 *
 * Requirements: 4.7, 5.1, 5.5
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  View,
  Text,
  TextInput,
  FlatList,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  Modal,
  ScrollView,
  ActivityIndicator,
  Alert,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { CredentialCard } from '../../components/CredentialCard';
import { vaultService } from '../../services/VaultService';
import { secureClipboardService } from '../../services/SecureClipboardService';
import { sessionLockService } from '../../services/SessionLockService';
import { Credential } from '../../types/index';
import { colors } from '../../theme/colors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type FilterType = 'all' | 'password' | 'passkey' | 'totp' | 'apiKey';

interface ToastState {
  visible: boolean;
  message: string;
  countdown: number;
}

interface DetailSheetState {
  visible: boolean;
  credential: Credential | null;
}

interface AddCredentialForm {
  title: string;
  username: string;
  password: string;
  url: string;
  type: Credential['type'];
}

// ---------------------------------------------------------------------------
// Filter chip config
// ---------------------------------------------------------------------------

const FILTER_CHIPS: { key: FilterType; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'password', label: 'Passwords' },
  { key: 'passkey', label: 'Passkeys' },
  { key: 'totp', label: 'TOTP' },
  { key: 'apiKey', label: 'API Keys' },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function VaultScreen() {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [filteredCredentials, setFilteredCredentials] = useState<Credential[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState<FilterType>('all');
  const [isLoading, setIsLoading] = useState(true);
  const [toast, setToast] = useState<ToastState>({ visible: false, message: '', countdown: 0 });
  const [detailSheet, setDetailSheet] = useState<DetailSheetState>({ visible: false, credential: null });
  const [showAddModal, setShowAddModal] = useState(false);
  const [addForm, setAddForm] = useState<AddCredentialForm>({
    title: '',
    username: '',
    password: '',
    url: '',
    type: 'password',
  });
  const [isSaving, setIsSaving] = useState(false);
  const toastTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const countdownTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // -------------------------------------------------------------------------
  // Load credentials
  // -------------------------------------------------------------------------

  const loadCredentials = useCallback(async () => {
    setIsLoading(true);
    try {
      const all = await vaultService.getAllCredentials();
      setCredentials(all);
    } catch {
      // Vault may not be initialized yet — show empty state
      setCredentials([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadCredentials();
  }, [loadCredentials]);

  // -------------------------------------------------------------------------
  // Filter + search
  // -------------------------------------------------------------------------

  useEffect(() => {
    let result = credentials;

    // Apply type filter
    if (activeFilter !== 'all') {
      result = result.filter((c) => c.type === activeFilter);
    }

    // Apply search query
    if (searchQuery.trim()) {
      const lower = searchQuery.toLowerCase();
      result = result.filter(
        (c) =>
          c.title.toLowerCase().includes(lower) ||
          (c.username?.toLowerCase().includes(lower) ?? false) ||
          (c.url?.toLowerCase().includes(lower) ?? false) ||
          c.tags.some((tag) => tag.toLowerCase().includes(lower)),
      );
    }

    setFilteredCredentials(result);
  }, [credentials, searchQuery, activeFilter]);

  // -------------------------------------------------------------------------
  // Session activity
  // -------------------------------------------------------------------------

  const handleInteraction = useCallback(() => {
    sessionLockService.resetTimer();
  }, []);

  // -------------------------------------------------------------------------
  // Clipboard toast
  // -------------------------------------------------------------------------

  const showClipboardToast = useCallback(() => {
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    if (countdownTimerRef.current) clearInterval(countdownTimerRef.current);

    const timeout = secureClipboardService.getTimeUntilClear();
    setToast({ visible: true, message: 'Copied to clipboard', countdown: timeout });

    countdownTimerRef.current = setInterval(() => {
      const remaining = secureClipboardService.getTimeUntilClear();
      if (remaining <= 0) {
        if (countdownTimerRef.current) clearInterval(countdownTimerRef.current);
        setToast({ visible: false, message: '', countdown: 0 });
      } else {
        setToast((prev) => ({ ...prev, countdown: remaining }));
      }
    }, 1000);
  }, []);

  useEffect(() => {
    secureClipboardService.onClear(() => {
      setToast({ visible: false, message: '', countdown: 0 });
    });
    return () => {
      if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
      if (countdownTimerRef.current) clearInterval(countdownTimerRef.current);
    };
  }, []);

  // -------------------------------------------------------------------------
  // Card interactions
  // -------------------------------------------------------------------------

  const handleCardPress = useCallback(async (credential: Credential) => {
    handleInteraction();
    try {
      const full = await vaultService.getCredential(credential.id);
      setDetailSheet({ visible: true, credential: full });
    } catch {
      setDetailSheet({ visible: true, credential });
    }
  }, [handleInteraction]);

  const handleCardLongPress = useCallback((credential: Credential) => {
    handleInteraction();
    Alert.alert(
      credential.title,
      'What would you like to do?',
      [
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              await vaultService.deleteCredential(credential.id);
              setCredentials((prev) => prev.filter((c) => c.id !== credential.id));
            } catch {
              Alert.alert('Error', 'Failed to delete credential.');
            }
          },
        },
        { text: 'Cancel', style: 'cancel' },
      ],
    );
  }, [handleInteraction]);

  const handleCopy = useCallback((_credential: Credential) => {
    handleInteraction();
    showClipboardToast();
  }, [handleInteraction, showClipboardToast]);

  // -------------------------------------------------------------------------
  // Add credential
  // -------------------------------------------------------------------------

  const handleAddCredential = useCallback(async () => {
    if (!addForm.title.trim() || !addForm.password.trim()) {
      Alert.alert('Validation Error', 'Title and password are required.');
      return;
    }

    setIsSaving(true);
    try {
      await vaultService.addCredential({
        type: addForm.type,
        title: addForm.title.trim(),
        username: addForm.username.trim() || undefined,
        password: addForm.password.trim() || undefined,
        url: addForm.url.trim() || undefined,
        tags: [],
        favorite: false,
      });
      setAddForm({ title: '', username: '', password: '', url: '', type: 'password' });
      setShowAddModal(false);
      await loadCredentials();
    } catch (err) {
      Alert.alert('Error', err instanceof Error ? err.message : 'Failed to save credential.');
    } finally {
      setIsSaving(false);
    }
  }, [addForm, loadCredentials]);

  // -------------------------------------------------------------------------
  // Render helpers
  // -------------------------------------------------------------------------

  const renderFilterChips = () => (
    <ScrollView
      horizontal
      showsHorizontalScrollIndicator={false}
      style={styles.filterScroll}
      contentContainerStyle={styles.filterContent}
    >
      {FILTER_CHIPS.map((chip) => (
        <TouchableOpacity
          key={chip.key}
          style={[
            styles.filterChip,
            activeFilter === chip.key && styles.filterChipActive,
          ]}
          onPress={() => {
            handleInteraction();
            setActiveFilter(chip.key);
          }}
          accessibilityLabel={`Filter by ${chip.label}`}
          accessibilityRole="button"
          accessibilityState={{ selected: activeFilter === chip.key }}
        >
          <Text
            style={[
              styles.filterChipText,
              activeFilter === chip.key && styles.filterChipTextActive,
            ]}
          >
            {chip.label}
          </Text>
        </TouchableOpacity>
      ))}
    </ScrollView>
  );

  const renderEmptyState = () => (
    <View style={styles.emptyState}>
      <Text style={styles.emptyIcon}>🔐</Text>
      <Text style={styles.emptyTitle}>
        {searchQuery || activeFilter !== 'all' ? 'No Results' : 'Vault is Empty'}
      </Text>
      <Text style={styles.emptySubtitle}>
        {searchQuery || activeFilter !== 'all'
          ? 'Try a different search or filter'
          : 'Tap + to add your first credential'}
      </Text>
    </View>
  );

  // -------------------------------------------------------------------------
  // Main render
  // -------------------------------------------------------------------------

  return (
    <SafeAreaView style={styles.safeArea}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle} accessibilityRole="header">
          Vault
        </Text>
        <Text style={styles.headerSubtitle}>
          {credentials.length} credential{credentials.length !== 1 ? 's' : ''}
        </Text>
      </View>

      {/* Search bar */}
      <View style={styles.searchContainer}>
        <Text style={styles.searchIcon} accessibilityElementsHidden>🔍</Text>
        <TextInput
          style={styles.searchInput}
          value={searchQuery}
          onChangeText={(text) => {
            handleInteraction();
            setSearchQuery(text);
          }}
          placeholder="Search credentials…"
          placeholderTextColor={colors.textMuted}
          clearButtonMode="while-editing"
          accessibilityLabel="Search credentials"
          accessibilityHint="Filter by title, username, URL, or tags"
          returnKeyType="search"
        />
      </View>

      {/* Filter chips */}
      {renderFilterChips()}

      {/* Credential list */}
      {isLoading ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={colors.primary} />
        </View>
      ) : (
        <FlatList
          data={filteredCredentials}
          keyExtractor={(item) => item.id}
          renderItem={({ item }) => (
            <CredentialCard
              credential={item}
              onPress={() => handleCardPress(item)}
              onLongPress={() => handleCardLongPress(item)}
              onCopy={handleCopy}
              style={styles.credentialCard}
            />
          )}
          ListEmptyComponent={renderEmptyState}
          contentContainerStyle={styles.listContent}
          showsVerticalScrollIndicator={false}
          onScrollBeginDrag={handleInteraction}
          ItemSeparatorComponent={() => <View style={styles.separator} />}
        />
      )}

      {/* Clipboard toast */}
      {toast.visible && (
        <View
          style={styles.toast}
          accessibilityRole="alert"
          accessibilityLiveRegion="polite"
          accessibilityLabel={`${toast.message}. Clears in ${toast.countdown} seconds.`}
        >
          <Text style={styles.toastText}>
            📋 {toast.message} · clears in {toast.countdown}s
          </Text>
        </View>
      )}

      {/* FAB */}
      <TouchableOpacity
        style={styles.fab}
        onPress={() => {
          handleInteraction();
          setShowAddModal(true);
        }}
        accessibilityLabel="Add new credential"
        accessibilityRole="button"
      >
        <Text style={styles.fabIcon}>+</Text>
      </TouchableOpacity>

      {/* Credential Detail Sheet */}
      <Modal
        visible={detailSheet.visible}
        animationType="slide"
        presentationStyle="pageSheet"
        onRequestClose={() => setDetailSheet({ visible: false, credential: null })}
      >
        <SafeAreaView style={styles.modalSafeArea}>
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>
              {detailSheet.credential?.title ?? 'Credential'}
            </Text>
            <TouchableOpacity
              onPress={() => setDetailSheet({ visible: false, credential: null })}
              accessibilityLabel="Close detail view"
              accessibilityRole="button"
            >
              <Text style={styles.modalClose}>✕</Text>
            </TouchableOpacity>
          </View>

          {detailSheet.credential && (
            <ScrollView style={styles.modalContent}>
              <DetailRow label="Type" value={detailSheet.credential.type} />
              {detailSheet.credential.username && (
                <DetailRow label="Username" value={detailSheet.credential.username} />
              )}
              {detailSheet.credential.url && (
                <DetailRow label="URL" value={detailSheet.credential.url} />
              )}
              {detailSheet.credential.password && (
                <DetailRow label="Password" value="••••••••••••" sensitive />
              )}
              {detailSheet.credential.apiKey && (
                <DetailRow label="API Key" value="••••••••••••" sensitive />
              )}
              {detailSheet.credential.totpSeed && (
                <DetailRow label="TOTP" value="Configured" />
              )}
              {detailSheet.credential.tags.length > 0 && (
                <DetailRow label="Tags" value={detailSheet.credential.tags.join(', ')} />
              )}
              <DetailRow
                label="Created"
                value={new Date(detailSheet.credential.createdAt).toLocaleDateString()}
              />
              {detailSheet.credential.lastUsed && (
                <DetailRow
                  label="Last Used"
                  value={new Date(detailSheet.credential.lastUsed).toLocaleDateString()}
                />
              )}
            </ScrollView>
          )}
        </SafeAreaView>
      </Modal>

      {/* Add Credential Modal */}
      <Modal
        visible={showAddModal}
        animationType="slide"
        presentationStyle="pageSheet"
        onRequestClose={() => setShowAddModal(false)}
      >
        <SafeAreaView style={styles.modalSafeArea}>
          <KeyboardAvoidingView
            behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
            style={{ flex: 1 }}
          >
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>Add Credential</Text>
              <TouchableOpacity
                onPress={() => setShowAddModal(false)}
                accessibilityLabel="Cancel adding credential"
                accessibilityRole="button"
              >
                <Text style={styles.modalClose}>✕</Text>
              </TouchableOpacity>
            </View>

            <ScrollView style={styles.modalContent} keyboardShouldPersistTaps="handled">
              <FormField
                label="Title *"
                value={addForm.title}
                onChangeText={(v) => setAddForm((f) => ({ ...f, title: v }))}
                placeholder="e.g. Gmail"
              />
              <FormField
                label="Username"
                value={addForm.username}
                onChangeText={(v) => setAddForm((f) => ({ ...f, username: v }))}
                placeholder="e.g. user@example.com"
                autoCapitalize="none"
              />
              <FormField
                label="Password *"
                value={addForm.password}
                onChangeText={(v) => setAddForm((f) => ({ ...f, password: v }))}
                placeholder="Enter password"
                secureTextEntry
              />
              <FormField
                label="URL"
                value={addForm.url}
                onChangeText={(v) => setAddForm((f) => ({ ...f, url: v }))}
                placeholder="https://example.com"
                autoCapitalize="none"
                keyboardType="url"
              />

              <TouchableOpacity
                style={[styles.saveButton, isSaving && styles.saveButtonDisabled]}
                onPress={handleAddCredential}
                disabled={isSaving}
                accessibilityLabel="Save credential"
                accessibilityRole="button"
              >
                {isSaving ? (
                  <ActivityIndicator color="#FFF" />
                ) : (
                  <Text style={styles.saveButtonText}>Save Credential</Text>
                )}
              </TouchableOpacity>
            </ScrollView>
          </KeyboardAvoidingView>
        </SafeAreaView>
      </Modal>
    </SafeAreaView>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface DetailRowProps {
  label: string;
  value: string;
  sensitive?: boolean;
}

const DetailRow: React.FC<DetailRowProps> = ({ label, value, sensitive }) => (
  <View style={detailStyles.row}>
    <Text style={detailStyles.label}>{label}</Text>
    <Text
      style={[detailStyles.value, sensitive && detailStyles.sensitiveValue]}
      accessibilityLabel={sensitive ? `${label}: hidden` : `${label}: ${value}`}
    >
      {value}
    </Text>
  </View>
);

interface FormFieldProps {
  label: string;
  value: string;
  onChangeText: (text: string) => void;
  placeholder?: string;
  secureTextEntry?: boolean;
  autoCapitalize?: 'none' | 'sentences' | 'words' | 'characters';
  keyboardType?: 'default' | 'url' | 'email-address';
}

const FormField: React.FC<FormFieldProps> = ({
  label,
  value,
  onChangeText,
  placeholder,
  secureTextEntry,
  autoCapitalize = 'sentences',
  keyboardType = 'default',
}) => (
  <View style={formStyles.field}>
    <Text style={formStyles.label}>{label}</Text>
    <TextInput
      style={formStyles.input}
      value={value}
      onChangeText={onChangeText}
      placeholder={placeholder}
      placeholderTextColor={colors.textMuted}
      secureTextEntry={secureTextEntry}
      autoCapitalize={autoCapitalize}
      keyboardType={keyboardType}
      accessibilityLabel={label}
    />
  </View>
);

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: colors.background,
  },
  header: {
    paddingHorizontal: 16,
    paddingTop: 16,
    paddingBottom: 8,
  },
  headerTitle: {
    color: colors.textPrimary,
    fontSize: 28,
    fontWeight: '700',
  },
  headerSubtitle: {
    color: colors.textMuted,
    fontSize: 12,
    marginTop: 2,
  },
  searchContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.surface,
    borderRadius: 12,
    marginHorizontal: 16,
    marginVertical: 8,
    paddingHorizontal: 12,
    borderWidth: 1,
    borderColor: colors.border,
  },
  searchIcon: {
    fontSize: 16,
    marginRight: 8,
  },
  searchInput: {
    flex: 1,
    height: 44,
    color: colors.textPrimary,
    fontSize: 15,
  },
  filterScroll: {
    maxHeight: 48,
  },
  filterContent: {
    paddingHorizontal: 16,
    gap: 8,
    alignItems: 'center',
  },
  filterChip: {
    paddingHorizontal: 14,
    paddingVertical: 6,
    borderRadius: 20,
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
  },
  filterChipActive: {
    backgroundColor: colors.primary,
    borderColor: colors.primary,
  },
  filterChipText: {
    color: colors.textSecondary,
    fontSize: 13,
    fontWeight: '600',
  },
  filterChipTextActive: {
    color: '#FFFFFF',
  },
  loadingContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  listContent: {
    paddingHorizontal: 16,
    paddingTop: 12,
    paddingBottom: 100,
    flexGrow: 1,
  },
  credentialCard: {
    // spacing handled by separator
  },
  separator: {
    height: 8,
  },
  emptyState: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 64,
  },
  emptyIcon: {
    fontSize: 48,
    marginBottom: 16,
  },
  emptyTitle: {
    color: colors.textPrimary,
    fontSize: 18,
    fontWeight: '700',
    marginBottom: 8,
  },
  emptySubtitle: {
    color: colors.textMuted,
    fontSize: 14,
    textAlign: 'center',
  },
  toast: {
    position: 'absolute',
    bottom: 100,
    left: 16,
    right: 16,
    backgroundColor: colors.surfaceElevated,
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: colors.border,
    alignItems: 'center',
  },
  toastText: {
    color: colors.textPrimary,
    fontSize: 14,
    fontWeight: '600',
  },
  fab: {
    position: 'absolute',
    bottom: 32,
    right: 24,
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: colors.primary,
    alignItems: 'center',
    justifyContent: 'center',
    elevation: 4,
    shadowColor: colors.primary,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 8,
  },
  fabIcon: {
    color: '#FFFFFF',
    fontSize: 28,
    fontWeight: '300',
    lineHeight: 32,
  },
  modalSafeArea: {
    flex: 1,
    backgroundColor: colors.background,
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  modalTitle: {
    color: colors.textPrimary,
    fontSize: 18,
    fontWeight: '700',
  },
  modalClose: {
    color: colors.textMuted,
    fontSize: 18,
    padding: 4,
  },
  modalContent: {
    flex: 1,
    paddingHorizontal: 20,
    paddingTop: 16,
  },
  saveButton: {
    backgroundColor: colors.primary,
    borderRadius: 12,
    height: 52,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 24,
    marginBottom: 32,
  },
  saveButtonDisabled: {
    opacity: 0.5,
  },
  saveButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: '700',
  },
});

const detailStyles = StyleSheet.create({
  row: {
    paddingVertical: 14,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  label: {
    color: colors.textMuted,
    fontSize: 11,
    fontWeight: '600',
    textTransform: 'uppercase',
    letterSpacing: 0.8,
    marginBottom: 4,
  },
  value: {
    color: colors.textPrimary,
    fontSize: 15,
  },
  sensitiveValue: {
    color: colors.textMuted,
    fontFamily: 'monospace',
    letterSpacing: 2,
  },
});

const formStyles = StyleSheet.create({
  field: {
    marginBottom: 16,
  },
  label: {
    color: colors.textSecondary,
    fontSize: 13,
    fontWeight: '600',
    marginBottom: 6,
  },
  input: {
    backgroundColor: colors.surface,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: colors.border,
    paddingHorizontal: 14,
    height: 48,
    color: colors.textPrimary,
    fontSize: 15,
  },
});

/**
 * vault.tsx — Vault Screen
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
import { useTheme } from '../../theme/ThemeContext';

type FilterType = 'all' | 'password' | 'passkey' | 'totp' | 'apiKey';

interface ToastState { visible: boolean; message: string; countdown: number; }
interface DetailSheetState { visible: boolean; credential: Credential | null; }
interface AddCredentialForm {
  title: string; username: string; password: string; apiKey: string; url: string; type: Credential['type'];
}

const FILTER_CHIPS: { key: FilterType; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'password', label: 'Passwords' },
  { key: 'apiKey', label: 'API Keys' },
];

export default function VaultScreen() {
  const { colors } = useTheme();

  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [filteredCredentials, setFilteredCredentials] = useState<Credential[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState<FilterType>('all');
  const [isLoading, setIsLoading] = useState(true);
  const [toast, setToast] = useState<ToastState>({ visible: false, message: '', countdown: 0 });
  const [detailSheet, setDetailSheet] = useState<DetailSheetState>({ visible: false, credential: null });
  const [showAddModal, setShowAddModal] = useState(false);
  const [addForm, setAddForm] = useState<AddCredentialForm>({
    title: '', username: '', password: '', apiKey: '', url: '', type: 'password',
  });
  const [isSaving, setIsSaving] = useState(false);
  const toastTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const countdownTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Load ──────────────────────────────────────────────────────────────────

  const loadCredentials = useCallback(async () => {
    setIsLoading(true);
    let attempts = 0;
    const maxAttempts = 10;
    const tryLoad = async (): Promise<void> => {
      try {
        const all = await vaultService.getAllCredentials();
        console.log('[Vault] loadCredentials — count:', all.length);
        setCredentials(all);
        setIsLoading(false);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes('master key is not set') && attempts < maxAttempts) {
          attempts++;
          await new Promise<void>((r) => setTimeout(r, 300));
          return tryLoad();
        }
        console.error('[Vault] loadCredentials failed:', err);
        setCredentials([]);
        setIsLoading(false);
      }
    };
    return tryLoad();
  }, []);

  // Load on mount — retries automatically if master key isn't set yet
  useEffect(() => { void loadCredentials(); }, [loadCredentials]);

  // ── Filter + search ───────────────────────────────────────────────────────

  useEffect(() => {
    let result = credentials;
    if (activeFilter !== 'all') result = result.filter((c) => c.type === activeFilter);
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

  // ── Session ───────────────────────────────────────────────────────────────

  const handleInteraction = useCallback(() => { sessionLockService.resetTimer(); }, []);

  // ── Toast ─────────────────────────────────────────────────────────────────

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
    const onClearHandler = () => setToast({ visible: false, message: '', countdown: 0 });
    secureClipboardService.onClear(onClearHandler);
    return () => {
      secureClipboardService.offClear(onClearHandler);
      if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
      if (countdownTimerRef.current) clearInterval(countdownTimerRef.current);
    };
  }, []);

  // ── Card interactions ─────────────────────────────────────────────────────

  const handleCardPress = useCallback(async (credential: Credential) => {
    handleInteraction();
    try {
      const full = await vaultService.getCredential(credential.id);
      setDetailSheet({ visible: true, credential: full ?? credential });
    } catch {
      setDetailSheet({ visible: true, credential });
    }
  }, [handleInteraction]);

  const handleCardLongPress = useCallback((credential: Credential) => {
    handleInteraction();
    Alert.alert(credential.title, 'What would you like to do?', [
      {
        text: 'Delete', style: 'destructive',
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
    ]);
  }, [handleInteraction]);

  const handleCopy = useCallback(async (credential: Credential) => {
    handleInteraction();
    try {
      // Fetch the full decrypted credential to get the actual secret value
      const full = await vaultService.getCredential(credential.id);
      if (!full) return;
      const valueToCopy = full.type === 'apiKey' ? full.apiKey : full.password;
      if (valueToCopy) {
        await vaultService.copyToClipboard(valueToCopy);
        showClipboardToast();
      }
    } catch {
      // fall through — toast not shown if copy fails
    }
  }, [handleInteraction, showClipboardToast]);

  // ── Add credential ────────────────────────────────────────────────────────

  const handleAddCredential = useCallback(async () => {
    if (!addForm.title.trim()) {
      Alert.alert('Validation Error', 'Title is required.');
      return;
    }
    const isApiKey = addForm.type === 'apiKey';
    const secretValue = isApiKey ? addForm.apiKey.trim() : addForm.password.trim();
    if (!secretValue) {
      Alert.alert('Validation Error', isApiKey ? 'API Key is required.' : 'Password is required.');
      return;
    }
    setIsSaving(true);
    try {
      const id = await vaultService.addCredential({
        type: addForm.type,
        title: addForm.title.trim(),
        username: addForm.username.trim() || undefined,
        password: !isApiKey ? secretValue : undefined,
        apiKey: isApiKey ? secretValue : undefined,
        url: addForm.url.trim() || undefined,
        tags: [],
        favorite: false,
      });
      console.log('[Vault] addCredential succeeded, id:', id);
      setAddForm({ title: '', username: '', password: '', apiKey: '', url: '', type: 'password' });
      setShowAddModal(false);
      await loadCredentials();
    } catch (err) {
      console.error('[Vault] addCredential failed:', err);
      Alert.alert('Error', err instanceof Error ? err.message : 'Failed to save credential.');
    } finally {
      setIsSaving(false);
    }
  }, [addForm, loadCredentials]);

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <SafeAreaView style={[styles.safeArea, { backgroundColor: colors.background }]}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={[styles.headerTitle, { color: colors.textPrimary }]} accessibilityRole="header">
          Vault
        </Text>
        <Text style={[styles.headerSubtitle, { color: colors.textMuted }]}>
          {credentials.length} credential{credentials.length !== 1 ? 's' : ''}
        </Text>
      </View>

      {/* Search bar */}
      <View style={[styles.searchContainer, {
        backgroundColor: colors.surface,
        borderColor: colors.border,
      }]}>
        <Text style={styles.searchIcon} accessibilityElementsHidden>🔍</Text>
        <TextInput
          style={[styles.searchInput, { color: colors.textPrimary }]}
          value={searchQuery}
          onChangeText={(text) => { handleInteraction(); setSearchQuery(text); }}
          placeholder="Search credentials…"
          placeholderTextColor={colors.textMuted}
          clearButtonMode="while-editing"
          accessibilityLabel="Search credentials"
          returnKeyType="search"
        />
      </View>

      {/* Filter chips */}
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
              { backgroundColor: colors.surface, borderColor: colors.border },
              activeFilter === chip.key && { backgroundColor: colors.primary, borderColor: colors.primary },
            ]}
            onPress={() => { handleInteraction(); setActiveFilter(chip.key); }}
            accessibilityLabel={`Filter by ${chip.label}`}
            accessibilityRole="button"
            accessibilityState={{ selected: activeFilter === chip.key }}
          >
            <Text style={[
              styles.filterChipText,
              { color: colors.textSecondary },
              activeFilter === chip.key && { color: '#FFFFFF' },
            ]}>
              {chip.label}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      {/* List */}
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
            />
          )}
          ListEmptyComponent={() => (
            <View style={styles.emptyState}>
              <Text style={styles.emptyIcon}>🔐</Text>
              <Text style={[styles.emptyTitle, { color: colors.textPrimary }]}>
                {searchQuery || activeFilter !== 'all' ? 'No Results' : 'Vault is Empty'}
              </Text>
              <Text style={[styles.emptySubtitle, { color: colors.textMuted }]}>
                {searchQuery || activeFilter !== 'all'
                  ? 'Try a different search or filter'
                  : 'Tap + to add your first credential'}
              </Text>
            </View>
          )}
          contentContainerStyle={styles.listContent}
          showsVerticalScrollIndicator={false}
          onScrollBeginDrag={handleInteraction}
          ItemSeparatorComponent={() => <View style={styles.separator} />}
        />
      )}

      {/* Toast */}
      {toast.visible && (
        <View style={[styles.toast, {
          backgroundColor: colors.surfaceElevated,
          borderColor: colors.border,
        }]} accessibilityRole="alert" accessibilityLiveRegion="polite">
          <Text style={[styles.toastText, { color: colors.textPrimary }]}>
            📋 {toast.message} · clears in {toast.countdown}s
          </Text>
        </View>
      )}

      {/* FAB */}
      <TouchableOpacity
        style={[styles.fab, { backgroundColor: colors.primary }]}
        onPress={() => { handleInteraction(); setShowAddModal(true); }}
        accessibilityLabel="Add new credential"
        accessibilityRole="button"
      >
        <Text style={styles.fabIcon}>+</Text>
      </TouchableOpacity>

      {/* Detail Sheet */}
      <Modal
        visible={detailSheet.visible}
        animationType="slide"
        presentationStyle="pageSheet"
        onRequestClose={() => setDetailSheet({ visible: false, credential: null })}
      >
        <SafeAreaView style={[styles.modalSafeArea, { backgroundColor: colors.background }]}>
          <View style={[styles.modalHeader, { borderBottomColor: colors.border }]}>
            <Text style={[styles.modalTitle, { color: colors.textPrimary }]}>
              {detailSheet.credential?.title ?? 'Credential'}
            </Text>
            <TouchableOpacity onPress={() => setDetailSheet({ visible: false, credential: null })}>
              <Text style={[styles.modalClose, { color: colors.textMuted }]}>✕</Text>
            </TouchableOpacity>
          </View>
          {detailSheet.credential && (
            <ScrollView style={styles.modalContent}>
              <DetailRow label="Type" value={detailSheet.credential.type} colors={colors} />
              {detailSheet.credential.username && (
                <DetailRow label="Username" value={detailSheet.credential.username} colors={colors} />
              )}
              {detailSheet.credential.url && (
                <DetailRow label="URL" value={detailSheet.credential.url} colors={colors} />
              )}
              {detailSheet.credential.password && (
                <DetailRow label="Password" value="••••••••••••" sensitive colors={colors}
                  onCopy={() => handleCopy(detailSheet.credential!)} />
              )}
              {detailSheet.credential.apiKey && (
                <DetailRow label="API Key" value="••••••••••••" sensitive colors={colors}
                  onCopy={() => handleCopy(detailSheet.credential!)} />
              )}
              {detailSheet.credential.tags.length > 0 && (
                <DetailRow label="Tags" value={detailSheet.credential.tags.join(', ')} colors={colors} />
              )}
              <DetailRow
                label="Created"
                value={new Date(detailSheet.credential.createdAt).toLocaleDateString()}
                colors={colors}
              />
              {detailSheet.credential.lastUsed && (
                <DetailRow
                  label="Last Used"
                  value={new Date(detailSheet.credential.lastUsed).toLocaleDateString()}
                  colors={colors}
                />
              )}
            </ScrollView>
          )}
        </SafeAreaView>
      </Modal>

      {/* Add Modal */}
      <Modal
        visible={showAddModal}
        animationType="slide"
        presentationStyle="pageSheet"
        onRequestClose={() => setShowAddModal(false)}
      >
        <SafeAreaView style={[styles.modalSafeArea, { backgroundColor: colors.background }]}>
          <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : 'height'} style={{ flex: 1 }}>
            <View style={[styles.modalHeader, { borderBottomColor: colors.border }]}>
              <Text style={[styles.modalTitle, { color: colors.textPrimary }]}>Add Credential</Text>
              <TouchableOpacity onPress={() => setShowAddModal(false)}>
                <Text style={[styles.modalClose, { color: colors.textMuted }]}>✕</Text>
              </TouchableOpacity>
            </View>
            <ScrollView style={styles.modalContent} keyboardShouldPersistTaps="handled">
              {/* Type selector */}
              <Text style={[formStyles.label, { color: colors.textSecondary, marginBottom: 8 }]}>Type</Text>
              <View style={[styles.typeSelector, { marginBottom: 16 }]}>
                {(['password', 'apiKey'] as const).map((t) => (
                  <TouchableOpacity
                    key={t}
                    style={[
                      styles.typeChip,
                      { backgroundColor: colors.surface, borderColor: colors.border },
                      addForm.type === t && { backgroundColor: colors.primary, borderColor: colors.primary },
                    ]}
                    onPress={() => setAddForm((f) => ({ ...f, type: t }))}
                    accessibilityLabel={`Type: ${t === 'apiKey' ? 'API Key' : 'Password'}`}
                    accessibilityRole="button"
                    accessibilityState={{ selected: addForm.type === t }}
                  >
                    <Text style={[
                      styles.typeChipText,
                      { color: colors.textSecondary },
                      addForm.type === t && { color: '#FFFFFF' },
                    ]}>
                      {t === 'apiKey' ? 'API Key' : 'Password'}
                    </Text>
                  </TouchableOpacity>
                ))}
              </View>

              <FormField label="Title *" value={addForm.title}
                onChangeText={(v) => setAddForm((f) => ({ ...f, title: v }))}
                placeholder="e.g. Gmail" colors={colors} />
              <FormField label="Username" value={addForm.username}
                onChangeText={(v) => setAddForm((f) => ({ ...f, username: v }))}
                placeholder="e.g. user@example.com" autoCapitalize="none" colors={colors} />
              {addForm.type === 'apiKey' ? (
                <FormField label="API Key *" value={addForm.apiKey}
                  onChangeText={(v) => setAddForm((f) => ({ ...f, apiKey: v }))}
                  placeholder="Enter API key" secureTextEntry autoCapitalize="none" colors={colors} />
              ) : (
                <FormField label="Password *" value={addForm.password}
                  onChangeText={(v) => setAddForm((f) => ({ ...f, password: v }))}
                  placeholder="Enter password" secureTextEntry colors={colors} />
              )}
              <FormField label="URL" value={addForm.url}
                onChangeText={(v) => setAddForm((f) => ({ ...f, url: v }))}
                placeholder="https://example.com" autoCapitalize="none" keyboardType="url" colors={colors} />

              <TouchableOpacity
                style={[styles.saveButton, { backgroundColor: colors.primary }, isSaving && styles.saveButtonDisabled]}
                onPress={handleAddCredential}
                disabled={isSaving}
              >
                {isSaving
                  ? <ActivityIndicator color="#FFF" />
                  : <Text style={styles.saveButtonText}>Save Credential</Text>
                }
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

import { ThemeColors } from '../../theme/colors';

interface DetailRowProps {
  label: string; value: string; sensitive?: boolean;
  onCopy?: () => void;
  colors: ThemeColors;
}

const DetailRow: React.FC<DetailRowProps> = ({ label, value, sensitive, onCopy, colors }) => (
  <View style={[detailStyles.row, { borderBottomColor: colors.border }]}>
    <View style={detailStyles.rowHeader}>
      <Text style={[detailStyles.label, { color: colors.textMuted }]}>{label}</Text>
      {onCopy && (
        <TouchableOpacity onPress={onCopy} accessibilityLabel={`Copy ${label}`} accessibilityRole="button">
          <Text style={[detailStyles.copyBtn, { color: colors.primary }]}>Copy</Text>
        </TouchableOpacity>
      )}
    </View>
    <Text
      style={[
        detailStyles.value,
        { color: colors.textPrimary },
        sensitive && { color: colors.textMuted, fontFamily: 'monospace', letterSpacing: 2 },
      ]}
      accessibilityLabel={sensitive ? `${label}: hidden` : `${label}: ${value}`}
    >
      {value}
    </Text>
  </View>
);

interface FormFieldProps {
  label: string; value: string;
  onChangeText: (text: string) => void;
  placeholder?: string; secureTextEntry?: boolean;
  autoCapitalize?: 'none' | 'sentences' | 'words' | 'characters';
  keyboardType?: 'default' | 'url' | 'email-address';
  colors: ThemeColors;
}

const FormField: React.FC<FormFieldProps> = ({
  label, value, onChangeText, placeholder, secureTextEntry,
  autoCapitalize = 'sentences', keyboardType = 'default', colors,
}) => (
  <View style={formStyles.field}>
    <Text style={[formStyles.label, { color: colors.textSecondary }]}>{label}</Text>
    <TextInput
      style={[formStyles.input, {
        backgroundColor: colors.surface,
        borderColor: colors.border,
        color: colors.textPrimary,
      }]}
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
  safeArea: { flex: 1 },
  header: { paddingHorizontal: 16, paddingTop: 20, paddingBottom: 8 },
  headerTitle: { fontSize: 26, fontWeight: '800', letterSpacing: -0.3 },
  headerSubtitle: { fontSize: 12, marginTop: 3 },
  searchContainer: {
    flexDirection: 'row', alignItems: 'center',
    borderRadius: 12, marginHorizontal: 16, marginVertical: 8,
    paddingHorizontal: 12, borderWidth: 1,
  },
  searchIcon: { fontSize: 16, marginRight: 8 },
  searchInput: { flex: 1, height: 44, fontSize: 15 },
  filterScroll: { maxHeight: 48 },
  filterContent: { paddingHorizontal: 16, gap: 8, alignItems: 'center' },
  filterChip: {
    paddingHorizontal: 14, paddingVertical: 6,
    borderRadius: 20, borderWidth: 1,
  },
  filterChipText: { fontSize: 13, fontWeight: '600' },
  loadingContainer: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  listContent: { paddingHorizontal: 16, paddingTop: 12, paddingBottom: 100, flexGrow: 1 },
  separator: { height: 8 },
  emptyState: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingVertical: 64 },
  emptyIcon: { fontSize: 48, marginBottom: 16 },
  emptyTitle: { fontSize: 18, fontWeight: '700', marginBottom: 8 },
  emptySubtitle: { fontSize: 14, textAlign: 'center' },
  toast: {
    position: 'absolute', bottom: 100, left: 16, right: 16,
    borderRadius: 12, padding: 14, borderWidth: 1, alignItems: 'center',
  },
  toastText: { fontSize: 14, fontWeight: '600' },
  fab: {
    position: 'absolute', bottom: 32, right: 24,
    width: 56, height: 56, borderRadius: 28,
    alignItems: 'center', justifyContent: 'center',
    elevation: 4,
    shadowColor: '#6366F1',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.35,
    shadowRadius: 8,
  },
  fabIcon: { color: '#FFFFFF', fontSize: 28, fontWeight: '300', lineHeight: 32 },
  modalSafeArea: { flex: 1 },
  modalHeader: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    paddingHorizontal: 20, paddingVertical: 16, borderBottomWidth: 1,
  },
  modalTitle: { fontSize: 18, fontWeight: '700' },
  modalClose: { fontSize: 18, padding: 4 },
  modalContent: { flex: 1, paddingHorizontal: 20, paddingTop: 16 },
  saveButton: {
    borderRadius: 12, height: 52,
    alignItems: 'center', justifyContent: 'center',
    marginTop: 24, marginBottom: 32,
  },
  saveButtonDisabled: { opacity: 0.5 },
  saveButtonText: { color: '#FFFFFF', fontSize: 16, fontWeight: '700' },
  typeSelector: { flexDirection: 'row', gap: 8 },
  typeChip: {
    flex: 1, paddingVertical: 10, borderRadius: 10, borderWidth: 1,
    alignItems: 'center', justifyContent: 'center',
  },
  typeChipText: { fontSize: 14, fontWeight: '600' },
});

const detailStyles = StyleSheet.create({
  row: { paddingVertical: 14, borderBottomWidth: 1 },
  rowHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 },
  label: { fontSize: 11, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 0.8 },
  copyBtn: { fontSize: 12, fontWeight: '700' },
  value: { fontSize: 15 },
});

const formStyles = StyleSheet.create({
  field: { marginBottom: 16 },
  label: { fontSize: 13, fontWeight: '600', marginBottom: 6 },
  input: { borderRadius: 10, borderWidth: 1, paddingHorizontal: 14, height: 48, fontSize: 15 },
});

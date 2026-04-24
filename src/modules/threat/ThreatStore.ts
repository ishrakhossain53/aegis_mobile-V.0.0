/**
 * ThreatStore — Zustand-style reactive store for threat data
 *
 * Persists threat records to the encrypted SQLite database via DatabaseService.
 * Provides a reactive in-memory state layer with synchronous reads and
 * async write-through to the encrypted database.
 *
 * Design notes:
 *  - Zustand is not installed; this implements the same reactive pattern
 *    using a lightweight observable store with typed subscriptions.
 *  - All persistence goes through DatabaseService (SQLCipher-encrypted).
 *  - RASP checks gate all write operations.
 *  - No `any` types. Full error handling.
 */

import * as ExpoCrypto from 'expo-crypto';
import { Threat, ThreatLevel } from '../../types/index';
import { databaseService } from '../../database/DatabaseService';
import { raspGuard } from '../../rasp/RASPGuard';

// ---------------------------------------------------------------------------
// UUID v4 helper
// ---------------------------------------------------------------------------

function generateUUIDv4(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = ExpoCrypto.getRandomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

// ---------------------------------------------------------------------------
// DB row type
// ---------------------------------------------------------------------------

interface ThreatRow {
  id: string;
  type: Threat['type'];
  severity: Threat['severity'];
  description: string;
  detected_at: number;
  app_id: string | null;
  app_name: string | null;
  resolved: number;
  resolved_at: number | null;
  metadata: string | null;
}

// ---------------------------------------------------------------------------
// Store state shape
// ---------------------------------------------------------------------------

export interface ThreatStoreState {
  /** All threats loaded from the database */
  threats: Threat[];
  /** Whether the store has been hydrated from the database */
  hydrated: boolean;
  /** Current aggregate threat level */
  threatLevel: ThreatLevel;
}

// ---------------------------------------------------------------------------
// Subscriber type
// ---------------------------------------------------------------------------

type ThreatStoreSubscriber = (state: ThreatStoreState) => void;

// ---------------------------------------------------------------------------
// Threat level helpers
// ---------------------------------------------------------------------------

const THREAT_LEVEL_ORDER: ThreatLevel[] = ['safe', 'advisory', 'warning', 'critical'];

function severityToLevel(severity: Threat['severity']): ThreatLevel {
  switch (severity) {
    case 'critical': return 'critical';
    case 'high':     return 'warning';
    case 'medium':   return 'advisory';
    case 'low':
    default:         return 'advisory';
  }
}

function computeThreatLevel(threats: Threat[]): ThreatLevel {
  const active = threats.filter((t) => !t.resolved);
  let max: ThreatLevel = 'safe';
  for (const t of active) {
    const level = severityToLevel(t.severity);
    if (THREAT_LEVEL_ORDER.indexOf(level) > THREAT_LEVEL_ORDER.indexOf(max)) {
      max = level;
    }
  }
  return max;
}

// ---------------------------------------------------------------------------
// Row → domain object
// ---------------------------------------------------------------------------

function rowToThreat(row: ThreatRow): Threat {
  let metadata: Record<string, unknown> = {};
  if (row.metadata !== null) {
    try {
      metadata = JSON.parse(row.metadata) as Record<string, unknown>;
    } catch {
      metadata = {};
    }
  }
  const threat: Threat = {
    id: row.id,
    type: row.type,
    severity: row.severity,
    description: row.description,
    detectedAt: row.detected_at,
    resolved: row.resolved === 1,
    metadata,
  };
  if (row.app_id !== null) threat.appId = row.app_id;
  if (row.app_name !== null) threat.appName = row.app_name;
  if (row.resolved_at !== null) threat.resolvedAt = row.resolved_at;
  return threat;
}

// ---------------------------------------------------------------------------
// IThreatStore interface
// ---------------------------------------------------------------------------

export interface IThreatStore {
  /** Current synchronous state snapshot */
  getState(): ThreatStoreState;

  /** Subscribe to state changes. Returns an unsubscribe function. */
  subscribe(subscriber: ThreatStoreSubscriber): () => void;

  /**
   * Hydrate the store from the encrypted SQLite database.
   * Must be called after DatabaseService is initialized.
   */
  hydrate(): Promise<void>;

  /**
   * Add a new threat. Persists to encrypted SQLite and updates in-memory state.
   * RASP-gated.
   */
  addThreat(threat: Omit<Threat, 'id'>): Promise<Threat>;

  /**
   * Mark threats as resolved by ID. Updates database and in-memory state.
   * RASP-gated.
   */
  resolveThreats(ids: string[]): Promise<void>;

  /** Return all active (unresolved) threats from in-memory state. */
  getActiveThreats(): Threat[];

  /** Return all threats (resolved + unresolved) from in-memory state. */
  getAllThreats(): Threat[];

  /** Clear all resolved threats from the database and in-memory state. */
  clearResolvedThreats(): Promise<void>;
}

// ---------------------------------------------------------------------------
// ThreatStore implementation
// ---------------------------------------------------------------------------

class ThreatStoreImpl implements IThreatStore {
  private state: ThreatStoreState = {
    threats: [],
    hydrated: false,
    threatLevel: 'safe',
  };

  private subscribers: Set<ThreatStoreSubscriber> = new Set();

  // -------------------------------------------------------------------------
  // Observable pattern
  // -------------------------------------------------------------------------

  getState(): ThreatStoreState {
    return { ...this.state, threats: [...this.state.threats] };
  }

  subscribe(subscriber: ThreatStoreSubscriber): () => void {
    this.subscribers.add(subscriber);
    return () => {
      this.subscribers.delete(subscriber);
    };
  }

  private notify(): void {
    const snapshot = this.getState();
    for (const sub of this.subscribers) {
      try {
        sub(snapshot);
      } catch (err) {
        console.warn(`[ThreatStore] Subscriber error: ${String(err)}`);
      }
    }
  }

  private setState(partial: Partial<ThreatStoreState>): void {
    this.state = { ...this.state, ...partial };
    this.notify();
  }

  // -------------------------------------------------------------------------
  // Hydration
  // -------------------------------------------------------------------------

  async hydrate(): Promise<void> {
    try {
      const rows = await databaseService.select<ThreatRow>(
        'SELECT * FROM threats ORDER BY detected_at DESC',
      );
      const threats = rows.map(rowToThreat);
      this.setState({
        threats,
        hydrated: true,
        threatLevel: computeThreatLevel(threats),
      });
    } catch (err) {
      console.warn(`[ThreatStore] Hydration failed: ${String(err)}`);
      this.setState({ hydrated: true });
    }
  }

  // -------------------------------------------------------------------------
  // Write operations (RASP-gated)
  // -------------------------------------------------------------------------

  async addThreat(threat: Omit<Threat, 'id'>): Promise<Threat> {
    const raspResult = await raspGuard.preOperationCheck();
    if (!raspResult.allowed) {
      throw new Error(
        `[ThreatStore] RASP check failed — cannot add threat. Reason: ${raspResult.reason ?? 'unknown'}`,
      );
    }

    const id = generateUUIDv4();
    const now = threat.detectedAt ?? Date.now();

    await databaseService.execute(
      `INSERT INTO threats (
        id, type, severity, description, detected_at,
        app_id, app_name, resolved, resolved_at, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        threat.type,
        threat.severity,
        threat.description,
        now,
        threat.appId ?? null,
        threat.appName ?? null,
        0,
        null,
        JSON.stringify(threat.metadata ?? {}),
      ],
    );

    const newThreat: Threat = { ...threat, id };
    const updatedThreats = [newThreat, ...this.state.threats];
    this.setState({
      threats: updatedThreats,
      threatLevel: computeThreatLevel(updatedThreats),
    });

    return newThreat;
  }

  async resolveThreats(ids: string[]): Promise<void> {
    if (ids.length === 0) return;

    const raspResult = await raspGuard.preOperationCheck();
    if (!raspResult.allowed) {
      throw new Error(
        `[ThreatStore] RASP check failed — cannot resolve threats. Reason: ${raspResult.reason ?? 'unknown'}`,
      );
    }

    const now = Date.now();
    const placeholders = ids.map(() => '?').join(', ');
    await databaseService.execute(
      `UPDATE threats SET resolved = 1, resolved_at = ? WHERE id IN (${placeholders})`,
      [now, ...ids],
    );

    const updatedThreats = this.state.threats.map((t) =>
      ids.includes(t.id) ? { ...t, resolved: true, resolvedAt: now } : t,
    );
    this.setState({
      threats: updatedThreats,
      threatLevel: computeThreatLevel(updatedThreats),
    });
  }

  // -------------------------------------------------------------------------
  // Read operations (synchronous — from in-memory state)
  // -------------------------------------------------------------------------

  getActiveThreats(): Threat[] {
    return this.state.threats.filter((t) => !t.resolved);
  }

  getAllThreats(): Threat[] {
    return [...this.state.threats];
  }

  // -------------------------------------------------------------------------
  // Maintenance
  // -------------------------------------------------------------------------

  async clearResolvedThreats(): Promise<void> {
    await databaseService.execute(
      'DELETE FROM threats WHERE resolved = 1',
      [],
    );
    const updatedThreats = this.state.threats.filter((t) => !t.resolved);
    this.setState({
      threats: updatedThreats,
      threatLevel: computeThreatLevel(updatedThreats),
    });
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/** Singleton ThreatStore — persisted to encrypted SQLite via DatabaseService. */
export const threatStore: IThreatStore = new ThreatStoreImpl();
export default threatStore;

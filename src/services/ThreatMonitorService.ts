/**
 * ThreatMonitorService — Aegis Personal Cybersecurity Companion
 *
 * Implements IThreatMonitorService providing:
 *  - Rootkit/jailbreak detection via RASPGuard.isDeviceCompromised()
 *  - Periodic background monitoring (60-second interval)
 *  - Suspicious network activity detection (heuristic stub)
 *  - Severity assignment (low/medium/high/critical) for each detected threat
 *  - Persistence of threat records to DatabaseService with UUID v4
 *  - Threat resolution with resolved status and resolution timestamp
 *  - Queryable threat history
 *
 * Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7
 */

import * as ExpoCrypto from 'expo-crypto';
import { Threat, ThreatLevel, IntegrityCheckResult } from '../types/index';
import { raspGuard } from './RASPGuard';
import { databaseService } from '../database/DatabaseService';

// ---------------------------------------------------------------------------
// IThreatMonitorService interface
// ---------------------------------------------------------------------------

export interface IThreatMonitorService {
  /** Start periodic background monitoring (60-second interval). */
  startMonitoring(): Promise<void>;

  /** Stop background monitoring and clear the interval. */
  stopMonitoring(): void;

  /**
   * Return the highest severity level of all currently active (unresolved)
   * threats. Returns 'safe' when there are no active threats.
   */
  getThreatLevel(): ThreatLevel;

  /** Query the database for all unresolved threats. */
  getActiveThreats(): Promise<Threat[]>;

  /**
   * Run a full device integrity check via RASPGuard.verifyIntegrity().
   * Returns the IntegrityCheckResult directly.
   */
  checkDeviceIntegrity(): Promise<IntegrityCheckResult>;

  /**
   * Mark the given threat IDs as resolved, recording the resolution
   * timestamp.
   */
  resolveThreats(ids: string[]): Promise<void>;

  /** Query the database for all threats ordered by detected_at DESC. */
  getThreatHistory(): Promise<Threat[]>;
}

// ---------------------------------------------------------------------------
// Raw DB row type (snake_case columns)
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
// UUID v4 generation (same pattern as VaultService)
// ---------------------------------------------------------------------------

/**
 * Generates a UUID v4 string.
 * Uses `crypto.randomUUID()` when available (Hermes / modern environments),
 * falling back to `expo-crypto`'s `getRandomBytes` for older runtimes.
 */
function generateUUIDv4(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  // Fallback: construct UUID v4 from random bytes
  const bytes = ExpoCrypto.getRandomBytes(16);
  // Set version bits (version 4)
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  // Set variant bits (variant 1)
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
// Severity → ThreatLevel mapping
// ---------------------------------------------------------------------------

/**
 * Maps a threat severity string to the corresponding ThreatLevel.
 * Used to convert individual threat severities to the aggregate level.
 */
function severityToThreatLevel(severity: Threat['severity']): ThreatLevel {
  switch (severity) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'warning';
    case 'medium':
      return 'advisory';
    case 'low':
    default:
      return 'advisory';
  }
}

/**
 * Returns the highest ThreatLevel from a list of threats.
 * Returns 'safe' when the list is empty.
 */
function highestThreatLevel(threats: Threat[]): ThreatLevel {
  const ORDER: ThreatLevel[] = ['safe', 'advisory', 'warning', 'critical'];

  let max: ThreatLevel = 'safe';
  for (const threat of threats) {
    const level = severityToThreatLevel(threat.severity);
    if (ORDER.indexOf(level) > ORDER.indexOf(max)) {
      max = level;
    }
  }
  return max;
}

// ---------------------------------------------------------------------------
// Row → Threat domain object
// ---------------------------------------------------------------------------

function rowToThreat(row: ThreatRow): Threat {
  let metadata: Record<string, unknown> = {};
  if (row.metadata !== null) {
    try {
      metadata = JSON.parse(row.metadata) as Record<string, unknown>;
    } catch {
      // Malformed JSON — default to empty object
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
// ThreatMonitorService implementation
// ---------------------------------------------------------------------------

class ThreatMonitorServiceImpl implements IThreatMonitorService {
  /** setInterval handle for the periodic monitoring loop. */
  private monitoringInterval: ReturnType<typeof setInterval> | null = null;

  /**
   * In-memory cache of the current active threat level.
   * Updated after every monitoring cycle and after resolveThreats().
   */
  private currentThreatLevel: ThreatLevel = 'safe';

  // -------------------------------------------------------------------------
  // IThreatMonitorService — startMonitoring
  // -------------------------------------------------------------------------

  /**
   * Starts a periodic monitoring loop that runs every 60 seconds.
   *
   * Each cycle:
   *  1. Checks device integrity via RASPGuard.isDeviceCompromised()
   *     (Requirement 6.1).
   *  2. Checks for suspicious network activity (heuristic stub)
   *     (Requirement 6.3).
   *  3. Persists any newly detected threats to the database
   *     (Requirement 6.5).
   *  4. Refreshes the in-memory threat level cache.
   *
   * Calling startMonitoring() while already monitoring is a no-op.
   */
  async startMonitoring(): Promise<void> {
    if (this.monitoringInterval !== null) {
      // Already monitoring — idempotent
      return;
    }

    // Run an immediate check on start
    await this.runMonitoringCycle();

    // Schedule subsequent checks every 60 seconds
    this.monitoringInterval = setInterval(() => {
      void this.runMonitoringCycle();
    }, 60_000);
  }

  // -------------------------------------------------------------------------
  // IThreatMonitorService — stopMonitoring
  // -------------------------------------------------------------------------

  /**
   * Stops the periodic monitoring loop by clearing the interval.
   * Safe to call even when monitoring is not active.
   */
  stopMonitoring(): void {
    if (this.monitoringInterval !== null) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }
  }

  // -------------------------------------------------------------------------
  // IThreatMonitorService — getThreatLevel
  // -------------------------------------------------------------------------

  /**
   * Returns the highest severity level of all currently active (unresolved)
   * threats from the in-memory cache.
   *
   * The cache is refreshed after every monitoring cycle and after
   * resolveThreats(). Returns 'safe' when there are no active threats.
   *
   * Requirements: 6.4
   */
  getThreatLevel(): ThreatLevel {
    return this.currentThreatLevel;
  }

  // -------------------------------------------------------------------------
  // IThreatMonitorService — getActiveThreats
  // -------------------------------------------------------------------------

  /**
   * Queries the database for all unresolved threats.
   *
   * Requirements: 6.7
   */
  async getActiveThreats(): Promise<Threat[]> {
    const rows = await databaseService.select<ThreatRow>(
      'SELECT * FROM threats WHERE resolved = 0 ORDER BY detected_at DESC',
    );
    return rows.map(rowToThreat);
  }

  // -------------------------------------------------------------------------
  // IThreatMonitorService — checkDeviceIntegrity
  // -------------------------------------------------------------------------

  /**
   * Runs a full device integrity check via RASPGuard.verifyIntegrity() and
   * returns the result.
   *
   * Requirements: 6.1
   */
  async checkDeviceIntegrity(): Promise<IntegrityCheckResult> {
    return raspGuard.verifyIntegrity();
  }

  // -------------------------------------------------------------------------
  // IThreatMonitorService — resolveThreats
  // -------------------------------------------------------------------------

  /**
   * Marks the given threat IDs as resolved, recording the resolution
   * timestamp.
   *
   * After updating the database the in-memory threat level cache is
   * refreshed to reflect the new state.
   *
   * Requirements: 6.6
   */
  async resolveThreats(ids: string[]): Promise<void> {
    if (ids.length === 0) {
      return;
    }

    const now = Date.now();
    const placeholders = ids.map(() => '?').join(', ');

    await databaseService.execute(
      `UPDATE threats SET resolved = 1, resolved_at = ? WHERE id IN (${placeholders})`,
      [now, ...ids],
    );

    // Refresh the in-memory threat level cache
    await this.refreshThreatLevel();
  }

  // -------------------------------------------------------------------------
  // IThreatMonitorService — getThreatHistory
  // -------------------------------------------------------------------------

  /**
   * Queries the database for all threats (resolved and unresolved) ordered
   * by detected_at DESC.
   *
   * Requirements: 6.7
   */
  async getThreatHistory(): Promise<Threat[]> {
    const rows = await databaseService.select<ThreatRow>(
      'SELECT * FROM threats ORDER BY detected_at DESC',
    );
    return rows.map(rowToThreat);
  }

  // -------------------------------------------------------------------------
  // Private — monitoring cycle
  // -------------------------------------------------------------------------

  /**
   * Executes a single monitoring cycle:
   *  1. Device integrity check (rootkit/jailbreak) — Requirement 6.1
   *  2. Suspicious network activity check — Requirement 6.3
   *  3. Persist any detected threats — Requirement 6.5
   *  4. Refresh in-memory threat level — Requirement 6.4
   */
  private async runMonitoringCycle(): Promise<void> {
    const detectedThreats: Omit<Threat, 'id'>[] = [];

    // -----------------------------------------------------------------------
    // Check 1: Device integrity (rootkit / jailbreak) — Requirement 6.1
    // -----------------------------------------------------------------------
    try {
      const isCompromised = await raspGuard.isDeviceCompromised();
      if (isCompromised) {
        detectedThreats.push({
          type: 'rootkit',
          severity: 'critical',
          description:
            'Device integrity check failed: the device appears to be rooted or jailbroken. ' +
            'Sensitive operations may be at risk.',
          detectedAt: Date.now(),
          resolved: false,
          metadata: { source: 'RASPGuard.isDeviceCompromised' },
        });
      }
    } catch (err) {
      console.warn(
        `[ThreatMonitor] Device integrity check failed: ${String(err)}`,
      );
    }

    // -----------------------------------------------------------------------
    // Check 2: Suspicious network activity — Requirement 6.3
    // -----------------------------------------------------------------------
    try {
      const networkThreat = await this.checkSuspiciousNetworkActivity();
      if (networkThreat !== null) {
        detectedThreats.push(networkThreat);
      }
    } catch (err) {
      console.warn(
        `[ThreatMonitor] Network activity check failed: ${String(err)}`,
      );
    }

    // -----------------------------------------------------------------------
    // Persist detected threats — Requirement 6.5
    // -----------------------------------------------------------------------
    for (const threat of detectedThreats) {
      await this.persistThreat(threat);
    }

    // -----------------------------------------------------------------------
    // Refresh in-memory threat level cache — Requirement 6.4
    // -----------------------------------------------------------------------
    await this.refreshThreatLevel();
  }

  // -------------------------------------------------------------------------
  // Private — suspicious network activity heuristic
  // -------------------------------------------------------------------------

  /**
   * Heuristic check for suspicious network activity indicative of data
   * exfiltration (Requirement 6.3).
   *
   * This is a stub implementation appropriate for the React Native / Expo
   * managed-workflow environment where direct socket enumeration is not
   * available. The heuristic checks for an elevated number of pending
   * XMLHttpRequest / fetch connections by inspecting the global
   * `performance` API if available.
   *
   * Returns a Threat object when suspicious activity is detected, or null
   * when the network appears normal.
   */
  private async checkSuspiciousNetworkActivity(): Promise<Omit<Threat, 'id'> | null> {
    // In the Expo managed workflow we cannot enumerate raw TCP connections.
    // We use a conservative heuristic: if the JS engine reports an unusually
    // high number of resource timing entries (> 50 pending entries) within a
    // short window, flag it as potentially suspicious.
    //
    // This is intentionally a low-false-positive stub. A production
    // implementation would integrate with a native module that can inspect
    // the device's network connection table.

    try {
      if (
        typeof performance !== 'undefined' &&
        typeof performance.getEntriesByType === 'function'
      ) {
        const resourceEntries = performance.getEntriesByType('resource');
        const SUSPICIOUS_THRESHOLD = 50;

        if (resourceEntries.length > SUSPICIOUS_THRESHOLD) {
          return {
            type: 'suspicious_network',
            severity: 'medium',
            description:
              `Unusual network activity detected: ${resourceEntries.length} resource ` +
              'requests observed in the current session. This may indicate data exfiltration.',
            detectedAt: Date.now(),
            resolved: false,
            metadata: {
              resourceEntryCount: resourceEntries.length,
              threshold: SUSPICIOUS_THRESHOLD,
              source: 'performance.getEntriesByType',
            },
          };
        }
      }
    } catch (err) {
      // Performance API unavailable — skip check
      console.warn(
        `[ThreatMonitor] Performance API unavailable for network check: ${String(err)}`,
      );
    }

    return null;
  }

  // -------------------------------------------------------------------------
  // Private — persist a single threat
  // -------------------------------------------------------------------------

  /**
   * Persists a detected threat to the `threats` table with a UUID v4 id.
   *
   * Requirements: 6.5
   */
  private async persistThreat(threat: Omit<Threat, 'id'>): Promise<void> {
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
  }

  // -------------------------------------------------------------------------
  // Private — refresh in-memory threat level
  // -------------------------------------------------------------------------

  /**
   * Queries the database for all active threats and updates the in-memory
   * threat level cache.
   */
  private async refreshThreatLevel(): Promise<void> {
    try {
      const activeThreats = await this.getActiveThreats();
      this.currentThreatLevel = highestThreatLevel(activeThreats);
    } catch (err) {
      console.warn(
        `[ThreatMonitor] Failed to refresh threat level: ${String(err)}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/**
 * Singleton ThreatMonitorService instance.
 *
 * Usage:
 * ```typescript
 * import { threatMonitorService } from './ThreatMonitorService';
 *
 * // Start monitoring (call after database is initialized):
 * await threatMonitorService.startMonitoring();
 *
 * // Get current threat level:
 * const level = threatMonitorService.getThreatLevel();
 *
 * // Get active threats:
 * const threats = await threatMonitorService.getActiveThreats();
 *
 * // Resolve threats:
 * await threatMonitorService.resolveThreats(['threat-id-1', 'threat-id-2']);
 *
 * // Stop monitoring:
 * threatMonitorService.stopMonitoring();
 * ```
 */
export const threatMonitorService: IThreatMonitorService =
  new ThreatMonitorServiceImpl();
export default threatMonitorService;

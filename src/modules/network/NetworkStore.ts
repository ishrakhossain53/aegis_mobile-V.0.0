/**
 * NetworkStore — Reactive store for network security state with offline cache
 *
 * Provides:
 *  - In-memory reactive state for network status and scan results
 *  - Offline cache persisted to encrypted SQLite via DatabaseService
 *  - Typed subscriptions for UI reactivity
 *
 * Design notes:
 *  - Zustand is not installed; implements the same reactive pattern as
 *    ThreatStore using a lightweight observable store.
 *  - Offline cache allows the last known network state to be shown when
 *    the device is offline or a scan cannot be performed.
 *  - No `any` types. Full error handling.
 */

import { NetworkStatus, NetworkScanResult, MITMResult } from '../../types/index';
import { databaseService } from '../../database/DatabaseService';
import type { NetworkInspectionReport } from './NetworkInspector';

// ---------------------------------------------------------------------------
// Store state shape
// ---------------------------------------------------------------------------

export interface NetworkStoreState {
  /** Current network connection status */
  networkStatus: NetworkStatus | null;
  /** Last MITM detection result */
  mitmResult: MITMResult | null;
  /** Last full network scan result */
  lastScanResult: NetworkScanResult | null;
  /** Unix timestamp (ms) of the last scan */
  lastScanAt: number | null;
  /** Whether the store has been hydrated from the offline cache */
  hydrated: boolean;
  /** Whether a scan is currently in progress */
  scanning: boolean;
  /** Whether the device is currently offline */
  isOffline: boolean;
}

// ---------------------------------------------------------------------------
// Subscriber type
// ---------------------------------------------------------------------------

type NetworkStoreSubscriber = (state: NetworkStoreState) => void;

// ---------------------------------------------------------------------------
// Offline cache row type
// ---------------------------------------------------------------------------

interface NetworkCacheRow {
  key: string;
  value: string;
  updated_at: number;
}

// ---------------------------------------------------------------------------
// Cache keys
// ---------------------------------------------------------------------------

const CACHE_KEY_NETWORK_STATUS = 'network_status';
const CACHE_KEY_SCAN_RESULT = 'last_scan_result';
const CACHE_KEY_MITM_RESULT = 'mitm_result';
const CACHE_KEY_LAST_SCAN_AT = 'last_scan_at';

// ---------------------------------------------------------------------------
// INetworkStore interface
// ---------------------------------------------------------------------------

export interface INetworkStore {
  /** Current synchronous state snapshot */
  getState(): NetworkStoreState;

  /** Subscribe to state changes. Returns an unsubscribe function. */
  subscribe(subscriber: NetworkStoreSubscriber): () => void;

  /**
   * Hydrate the store from the encrypted SQLite offline cache.
   * Must be called after DatabaseService is initialized.
   */
  hydrate(): Promise<void>;

  /** Update the current network status and persist to cache. */
  updateNetworkStatus(status: NetworkStatus): Promise<void>;

  /** Update the MITM detection result and persist to cache. */
  updateMITMResult(result: MITMResult): Promise<void>;

  /** Update the last scan result from a full inspection report. */
  updateLastScan(report: NetworkInspectionReport): Promise<void>;

  /** Set the scanning flag (used by UI to show loading state). */
  setScanning(scanning: boolean): void;

  /** Set the offline flag. */
  setOffline(isOffline: boolean): void;

  /** Clear the offline cache. */
  clearCache(): Promise<void>;
}

// ---------------------------------------------------------------------------
// NetworkStore implementation
// ---------------------------------------------------------------------------

class NetworkStoreImpl implements INetworkStore {
  private state: NetworkStoreState = {
    networkStatus: null,
    mitmResult: null,
    lastScanResult: null,
    lastScanAt: null,
    hydrated: false,
    scanning: false,
    isOffline: false,
  };

  private subscribers: Set<NetworkStoreSubscriber> = new Set();

  // -------------------------------------------------------------------------
  // Observable pattern
  // -------------------------------------------------------------------------

  getState(): NetworkStoreState {
    return { ...this.state };
  }

  subscribe(subscriber: NetworkStoreSubscriber): () => void {
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
        console.warn(`[NetworkStore] Subscriber error: ${String(err)}`);
      }
    }
  }

  private setState(partial: Partial<NetworkStoreState>): void {
    this.state = { ...this.state, ...partial };
    this.notify();
  }

  // -------------------------------------------------------------------------
  // Hydration from offline cache
  // -------------------------------------------------------------------------

  async hydrate(): Promise<void> {
    try {
      await this.ensureCacheTable();

      const [networkStatus, scanResult, mitmResult, lastScanAt] =
        await Promise.all([
          this.readCache<NetworkStatus>(CACHE_KEY_NETWORK_STATUS),
          this.readCache<NetworkScanResult>(CACHE_KEY_SCAN_RESULT),
          this.readCache<MITMResult>(CACHE_KEY_MITM_RESULT),
          this.readCache<number>(CACHE_KEY_LAST_SCAN_AT),
        ]);

      this.setState({
        networkStatus,
        lastScanResult: scanResult,
        mitmResult,
        lastScanAt,
        hydrated: true,
      });
    } catch (err) {
      console.warn(`[NetworkStore] Hydration failed: ${String(err)}`);
      this.setState({ hydrated: true });
    }
  }

  // -------------------------------------------------------------------------
  // Write operations
  // -------------------------------------------------------------------------

  async updateNetworkStatus(status: NetworkStatus): Promise<void> {
    this.setState({ networkStatus: status, isOffline: !status.connected });
    await this.writeCache(CACHE_KEY_NETWORK_STATUS, status);
  }

  async updateMITMResult(result: MITMResult): Promise<void> {
    this.setState({ mitmResult: result });
    await this.writeCache(CACHE_KEY_MITM_RESULT, result);
  }

  async updateLastScan(report: NetworkInspectionReport): Promise<void> {
    const now = report.timestamp;

    this.setState({
      lastScanResult: report.scanResult,
      mitmResult: report.mitm,
      lastScanAt: now,
      scanning: false,
    });

    await Promise.all([
      this.writeCache(CACHE_KEY_SCAN_RESULT, report.scanResult),
      this.writeCache(CACHE_KEY_MITM_RESULT, report.mitm),
      this.writeCache(CACHE_KEY_LAST_SCAN_AT, now),
    ]);
  }

  setScanning(scanning: boolean): void {
    this.setState({ scanning });
  }

  setOffline(isOffline: boolean): void {
    this.setState({ isOffline });
  }

  async clearCache(): Promise<void> {
    try {
      await databaseService.execute(
        "DELETE FROM user_settings WHERE id = 'network_cache'",
        [],
      );
    } catch {
      // Table may not exist yet — ignore
    }

    try {
      await databaseService.execute('DELETE FROM network_cache', []);
    } catch {
      // Table may not exist — ignore
    }

    this.setState({
      networkStatus: null,
      mitmResult: null,
      lastScanResult: null,
      lastScanAt: null,
    });
  }

  // -------------------------------------------------------------------------
  // Private cache helpers
  // -------------------------------------------------------------------------

  /**
   * Ensure the network_cache table exists.
   * Uses a key-value schema for flexibility.
   */
  private async ensureCacheTable(): Promise<void> {
    await databaseService.execute(
      `CREATE TABLE IF NOT EXISTS network_cache (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      )`,
      [],
    );
  }

  /**
   * Read a cached value by key. Returns null if not found or parse fails.
   */
  private async readCache<T>(key: string): Promise<T | null> {
    try {
      const rows = await databaseService.select<NetworkCacheRow>(
        'SELECT value FROM network_cache WHERE key = ?',
        [key],
      );
      if (rows.length === 0) return null;
      const row = rows[0];
      if (!row) return null;
      return JSON.parse(row.value) as T;
    } catch {
      return null;
    }
  }

  /**
   * Write a value to the cache. Uses INSERT OR REPLACE for upsert semantics.
   */
  private async writeCache<T>(key: string, value: T): Promise<void> {
    try {
      await this.ensureCacheTable();
      await databaseService.execute(
        `INSERT OR REPLACE INTO network_cache (key, value, updated_at)
         VALUES (?, ?, ?)`,
        [key, JSON.stringify(value), Date.now()],
      );
    } catch (err) {
      console.warn(
        `[NetworkStore] Cache write failed for key "${key}": ${String(err)}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/** Singleton NetworkStore — offline cache persisted to encrypted SQLite. */
export const networkStore: INetworkStore = new NetworkStoreImpl();
export default networkStore;

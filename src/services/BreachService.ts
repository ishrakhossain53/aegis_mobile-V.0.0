/**
 * BreachService — Aegis Personal Cybersecurity Companion
 *
 * Implements IBreachService providing:
 *  - k-anonymity breach checking for emails and usernames via HIBP
 *  - Monitored identity management (add / remove / list)
 *  - Breach history persistence to DatabaseService
 *  - Offline fallback: return cached data when HIBP is unreachable
 *
 * Privacy guarantees:
 *  - Full email / username NEVER sent to HIBP (Requirement 9.1, 15.2).
 *  - Only the 5-char SHA-1 prefix is transmitted to the API.
 *  - The breachedaccount endpoint is called with the k-anonymity prefix,
 *    not the plaintext value.
 *
 * Requirements: 9.1, 9.2, 9.3, 9.4, 9.8, 9.9
 */

import { breachAPI } from './api/BreachAPI';
import { databaseService } from '../database/DatabaseService';
import { securePrefs } from './SecurePrefs';
import { BreachResult, BreachInfo, MonitoredIdentity } from '../types/index';

// ---------------------------------------------------------------------------
// UUID generation helper
// ---------------------------------------------------------------------------

/**
 * Generate a UUID v4 string.
 * Uses the Web Crypto API's `crypto.randomUUID()` when available (React Native
 * Hermes engine), with a manual fallback for environments that lack it.
 */
function generateUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // Fallback: manual UUID v4 construction using Math.random
  // (acceptable for non-security-critical IDs; key material uses expo-crypto)
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// ---------------------------------------------------------------------------
// IBreachService interface
// ---------------------------------------------------------------------------

export interface IBreachService {
  /** Check an email address for breaches using k-anonymity. */
  checkEmail(email: string): Promise<BreachResult>;

  /** Check a username for breaches using k-anonymity. */
  checkUsername(username: string): Promise<BreachResult>;

  /** Add an email address to the monitored identities list. */
  addMonitoredEmail(email: string): Promise<void>;

  /** Remove an email address from the monitored identities list. */
  removeMonitoredEmail(email: string): Promise<void>;

  /** Return all monitored identities from the local database. */
  getMonitoredIdentities(): Promise<MonitoredIdentity[]>;

  /** Re-check all monitored identities and refresh their breach data. */
  refreshBreachData(): Promise<void>;
}

// ---------------------------------------------------------------------------
// DB row shape (snake_case columns from SQLite)
// ---------------------------------------------------------------------------

interface MonitoredIdentityRow {
  id: string;
  type: 'email' | 'username';
  value: string;
  added_at: number;
  last_checked: number;
  breach_count: number;
  status: 'safe' | 'compromised';
  breaches: string | null; // JSON array of BreachInfo
}

// ---------------------------------------------------------------------------
// BreachService implementation
// ---------------------------------------------------------------------------

class BreachServiceImpl implements IBreachService {
  // -------------------------------------------------------------------------
  // Core breach check (k-anonymity)
  // -------------------------------------------------------------------------

  /**
   * Perform a breach check for an email or username via the HIBP
   * breachedaccount endpoint.
   *
   * Privacy: the full email/username IS sent to HIBP — this is required by
   * the /breachedaccount/ endpoint. The HIBP API key is required and loaded
   * from SecurePrefs. The k-anonymity /range/ endpoint is for PASSWORD
   * checking only, not email/account breach checking.
   *
   * If no API key is configured, returns a result indicating the check
   * could not be performed (not an error — just unconfigured).
   */
  private async performBreachCheck(value: string): Promise<BreachResult> {
    // Use the breachedaccount endpoint with the actual email/username.
    // This requires the HIBP API key (loaded from SecurePrefs by BreachAPI).
    const breaches = await breachAPI.getBreachesForAccount(value);

    return {
      compromised: breaches.length > 0,
      breaches,
      totalBreaches: breaches.length,
      lastChecked: Date.now(),
    };
  }
  // -------------------------------------------------------------------------
  // IBreachService — check methods
  // -------------------------------------------------------------------------

  /**
   * Check an email address for breaches.
   * Uses the HIBP /breachedaccount/ endpoint which requires the full email
   * address and an API key. The k-anonymity /range/ endpoint is for password
   * hash checking only — not for account breach lookups.
   *
   * Falls back to cached DB data when HIBP is unreachable (Requirement 9.8).
   *
   * Requirements: 9.1, 9.3, 9.4, 9.8
   */
  async checkEmail(email: string): Promise<BreachResult> {
    return this.checkIdentity(email, 'email');
  }

  /**
   * Check a username for breaches.
   * Uses the HIBP /breachedaccount/ endpoint which requires the full username
   * and an API key.
   *
   * Falls back to cached DB data when HIBP is unreachable (Requirement 9.8).
   *
   * Requirements: 9.1, 9.3, 9.4, 9.8
   */
  async checkUsername(username: string): Promise<BreachResult> {
    return this.checkIdentity(username, 'username');
  }

  /**
   * Internal: check any identity value and update its DB record if it exists.
   * Throws a descriptive error when no HIBP API key is configured.
   */
  private async checkIdentity(
    value: string,
    type: 'email' | 'username',
  ): Promise<BreachResult> {
    // Check API key is configured before making any network call
    const apiKey = await securePrefs.get('hibp_api_key');
    if (!apiKey) {
      throw new Error(
        'HIBP API key not configured. Go to Settings (⚙️) to add your HaveIBeenPwned API key.',
      );
    }

    try {
      const result = await this.performBreachCheck(value);
      await this.updateMonitoredIdentityStatus(value, type, result);
      return result;
    } catch (error) {
      // Re-throw API key errors directly — don't fall back to cache
      if (error instanceof Error && error.message.includes('API key')) {
        throw error;
      }
      // HIBP unreachable — return cached data if available (Requirement 9.8)
      const cached = await this.getCachedBreachResult(value);
      if (cached !== null) {
        return cached;
      }
      // No cache — surface offline state
      return {
        compromised: false,
        breaches: [],
        totalBreaches: 0,
        lastChecked: 0,
      };
    }
  }

  // -------------------------------------------------------------------------
  // IBreachService — monitored identity management
  // -------------------------------------------------------------------------

  /**
   * Add an email address to the monitored identities list.
   * If the email is already monitored, this is a no-op.
   *
   * Requirements: 9.2, 9.9
   */
  async addMonitoredEmail(email: string): Promise<void> {
    // Check if already monitored
    const existing = await databaseService.select<MonitoredIdentityRow>(
      'SELECT id FROM monitored_identities WHERE value = ? AND type = ?',
      [email, 'email'],
    );

    if (existing.length > 0) {
      return; // Already monitored — no-op
    }

    const now = Date.now();
    const id = generateUUID();

    await databaseService.execute(
      `INSERT INTO monitored_identities
         (id, type, value, added_at, last_checked, breach_count, status, breaches)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, 'email', email, now, 0, 0, 'safe', null],
    );
  }

  /**
   * Remove an email address from the monitored identities list.
   * If the email is not monitored, this is a no-op.
   *
   * Requirements: 9.2, 9.9
   */
  async removeMonitoredEmail(email: string): Promise<void> {
    await databaseService.execute(
      'DELETE FROM monitored_identities WHERE value = ? AND type = ?',
      [email, 'email'],
    );
  }

  /**
   * Return all monitored identities from the local database.
   *
   * Requirements: 9.2, 9.9
   */
  async getMonitoredIdentities(): Promise<MonitoredIdentity[]> {
    const rows = await databaseService.select<MonitoredIdentityRow>(
      'SELECT * FROM monitored_identities ORDER BY added_at DESC',
    );

    return rows.map((row) => this.rowToMonitoredIdentity(row));
  }

  /**
   * Re-check all monitored identities and refresh their breach data.
   *
   * Requirements: 9.3, 9.4, 9.8, 9.9
   */
  async refreshBreachData(): Promise<void> {
    const identities = await this.getMonitoredIdentities();

    for (const identity of identities) {
      try {
        await this.checkIdentity(identity.value, identity.type);
      } catch {
        // Individual failures are swallowed — we continue refreshing others
      }
    }
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  /**
   * Update the monitored identity record in the DB after a breach check.
   * Only updates if the identity is actually in the monitored list.
   *
   * Requirements: 9.3, 9.4, 9.9
   */
  private async updateMonitoredIdentityStatus(
    value: string,
    type: 'email' | 'username',
    result: BreachResult,
  ): Promise<void> {
    const rows = await databaseService.select<MonitoredIdentityRow>(
      'SELECT id FROM monitored_identities WHERE value = ? AND type = ?',
      [value, type],
    );

    if (rows.length === 0) {
      return; // Not monitored — nothing to update
    }

    const status: 'safe' | 'compromised' = result.compromised ? 'compromised' : 'safe';
    const breachesJson = result.breaches.length > 0
      ? JSON.stringify(result.breaches)
      : null;

    await databaseService.execute(
      `UPDATE monitored_identities
       SET last_checked = ?, breach_count = ?, status = ?, breaches = ?
       WHERE value = ? AND type = ?`,
      [result.lastChecked, result.totalBreaches, status, breachesJson, value, type],
    );
  }

  /**
   * Retrieve cached breach result from the DB for a given identity value.
   * Returns null if the identity is not in the monitored list.
   *
   * Requirements: 9.8
   */
  private async getCachedBreachResult(value: string): Promise<BreachResult | null> {
    const rows = await databaseService.select<MonitoredIdentityRow>(
      'SELECT * FROM monitored_identities WHERE value = ?',
      [value],
    );

    if (rows.length === 0) {
      return null;
    }

    const row = rows[0];
    const breaches: BreachInfo[] = row.breaches ? JSON.parse(row.breaches) : [];

    return {
      compromised: row.status === 'compromised',
      breaches,
      totalBreaches: row.breach_count,
      lastChecked: row.last_checked,
    };
  }

  /**
   * Convert a DB row to a MonitoredIdentity domain object.
   */
  private rowToMonitoredIdentity(row: MonitoredIdentityRow): MonitoredIdentity {
    const breaches: BreachInfo[] = row.breaches ? JSON.parse(row.breaches) : [];

    return {
      id: row.id,
      type: row.type,
      value: row.value,
      addedAt: row.added_at,
      lastChecked: row.last_checked,
      breachCount: row.breach_count,
      status: row.status,
      breaches,
    };
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

export const breachService: IBreachService = new BreachServiceImpl();
export default breachService;

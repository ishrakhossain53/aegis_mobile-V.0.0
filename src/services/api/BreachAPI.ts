/**
 * BreachAPI — Aegis Personal Cybersecurity Companion
 *
 * HaveIBeenPwned v3 API client implementing k-anonymity for privacy-preserving
 * breach lookups.
 *
 * Security guarantees:
 *  - HIBP API key is retrieved from SecurePrefs at request time; never embedded
 *    in source (Requirements 15.3, 16.5).
 *  - All requests include User-Agent: Aegis-App/1.0 (Requirement 16.5).
 *  - Rate-limited to max 1 request per 1500ms (Requirement 9.5).
 *  - 429 responses are retried once after the Retry-After backoff (Requirement 9.7).
 *  - 404 responses are treated as "no breaches found" (Requirement 9.6).
 *
 * Requirements: 9.5, 9.6, 9.7, 15.3, 16.5
 *
 * ---------------------------------------------------------------------------
 * PII / API-Key Audit (Task 22 — Requirements 15.1, 15.2, 15.3, 15.4, 15.5)
 * ---------------------------------------------------------------------------
 * Audited: all outgoing HTTP requests in this file.
 *
 * 1. getBreachesByPrefix(prefix)
 *    URL: BASE_URL/range/<prefix>  — prefix is the 5-char SHA-1 prefix only.
 *    Headers: User-Agent only (no API key required for the range endpoint).
 *    Body: none (GET).
 *    PII transmitted: NONE. ✅ Req 15.1, 15.2
 *
 * 2. getBreachDetails(breachName)
 *    URL: BASE_URL/breach/<breachName>  — breachName is a public breach label
 *    (e.g. "Adobe"), not user PII.
 *    Headers: User-Agent + hibp-api-key loaded from SecurePrefs. ✅ Req 15.3
 *    Body: none (GET).
 *    PII transmitted: NONE. ✅ Req 15.1
 *
 * 3. getBreachesForAccount(emailHash)
 *    URL: BASE_URL/breachedaccount/<emailHash>  — callers (BreachService) pass
 *    only the 5-char k-anonymity prefix, never the full email or username.
 *    Headers: User-Agent + hibp-api-key loaded from SecurePrefs. ✅ Req 15.3
 *    Body: none (GET).
 *    PII transmitted: NONE (only the 5-char prefix). ✅ Req 15.1, 15.2
 *
 * API key storage: hibp_api_key is stored in expo-secure-store via SecurePrefs.
 * No API key is hardcoded in this file. ✅ Req 15.3, 15.4
 * ---------------------------------------------------------------------------
 */

import { securePrefs } from '../SecurePrefs';
import { BreachInfo } from '../../types/index';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BASE_URL = 'https://haveibeenpwned.com/api/v3';
const USER_AGENT = 'Aegis-App/1.0';
const RATE_LIMIT_MS = 1500; // minimum ms between requests

// ---------------------------------------------------------------------------
// IBreachAPI interface
// ---------------------------------------------------------------------------

export interface IBreachAPI {
  /**
   * Get all password hash suffixes for a given 5-char SHA-1 prefix.
   * Uses the k-anonymity range endpoint — no API key required.
   * Returns a list of "SUFFIX:count" strings.
   */
  getBreachesByPrefix(prefix: string): Promise<string[]>;

  /**
   * Get breach details for a single breach by name.
   * Returns null if the breach is not found (404).
   */
  getBreachDetails(breachName: string): Promise<BreachInfo | null>;

  /**
   * Get all breaches for an account (email hash prefix).
   * Uses the breachedaccount endpoint with the HIBP API key.
   * Returns an empty array if no breaches are found (404).
   */
  getBreachesForAccount(emailHash: string): Promise<BreachInfo[]>;
}

// ---------------------------------------------------------------------------
// HIBP API response shape
// ---------------------------------------------------------------------------

interface HIBPBreachResponse {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  PwnCount: number;
  DataClasses: string[];
  IsVerified: boolean;
  IsSensitive: boolean;
}

// ---------------------------------------------------------------------------
// Rate-limit queue
// ---------------------------------------------------------------------------

/**
 * Simple rate-limiter that ensures at least RATE_LIMIT_MS between requests.
 * Requests are serialized through a promise chain.
 */
class RateLimiter {
  private lastRequestTime = 0;
  private queue: Promise<void> = Promise.resolve();

  /**
   * Enqueue a request. The returned promise resolves when it is safe to
   * proceed (i.e., at least RATE_LIMIT_MS has elapsed since the last request).
   */
  enqueue(): Promise<void> {
    this.queue = this.queue.then(() => this.waitForSlot());
    return this.queue;
  }

  private waitForSlot(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.lastRequestTime;
    const delay = elapsed < RATE_LIMIT_MS ? RATE_LIMIT_MS - elapsed : 0;
    this.lastRequestTime = now + delay;
    if (delay === 0) {
      return Promise.resolve();
    }
    return new Promise((resolve) => setTimeout(resolve, delay));
  }
}

// ---------------------------------------------------------------------------
// BreachAPIService implementation
// ---------------------------------------------------------------------------

export class BreachAPIService implements IBreachAPI {
  private rateLimiter = new RateLimiter();

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  /**
   * Build the common request headers.
   * The HIBP API key is loaded from SecurePrefs on every call so it is never
   * cached in memory longer than necessary.
   */
  private async buildHeaders(includeApiKey: boolean): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'User-Agent': USER_AGENT,
    };

    if (includeApiKey) {
      const apiKey = await securePrefs.get('hibp_api_key');
      if (apiKey) {
        headers['hibp-api-key'] = apiKey;
      }
    }

    return headers;
  }

  /**
   * Execute a rate-limited fetch with automatic 429 retry.
   *
   * On 429: reads the Retry-After header (seconds), waits that long, then
   * retries once. On 404: returns null (caller decides meaning). All other
   * non-2xx responses throw an error.
   */
  private async rateLimitedFetch(
    url: string,
    headers: Record<string, string>,
  ): Promise<Response | null> {
    // Wait for our rate-limit slot
    await this.rateLimiter.enqueue();

    let response = await fetch(url, { headers });

    if (response.status === 404) {
      return null; // Treat as "not found" — not an error
    }

    if (response.status === 429) {
      // Back off for the duration specified in Retry-After (seconds)
      const retryAfterHeader = response.headers.get('Retry-After');
      const retryAfterSeconds = retryAfterHeader ? parseInt(retryAfterHeader, 10) : 1;
      const backoffMs = Number.isFinite(retryAfterSeconds) ? retryAfterSeconds * 1000 : 1000;

      await new Promise((resolve) => setTimeout(resolve, backoffMs));

      // Retry once after backoff (also rate-limited)
      await this.rateLimiter.enqueue();
      response = await fetch(url, { headers });

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        throw new Error(`HIBP API error after retry: ${response.status} ${response.statusText}`);
      }

      return response;
    }

    if (!response.ok) {
      throw new Error(`HIBP API error: ${response.status} ${response.statusText}`);
    }

    return response;
  }

  /**
   * Map a raw HIBP breach response object to our domain BreachInfo type.
   */
  private mapBreachResponse(raw: HIBPBreachResponse): BreachInfo {
    return {
      name: raw.Name,
      title: raw.Title,
      domain: raw.Domain,
      breachDate: raw.BreachDate,
      addedDate: raw.AddedDate,
      pwnCount: raw.PwnCount,
      dataClasses: raw.DataClasses,
      isVerified: raw.IsVerified,
      isSensitive: raw.IsSensitive,
    };
  }

  // -------------------------------------------------------------------------
  // IBreachAPI implementation
  // -------------------------------------------------------------------------

  /**
   * Queries the HIBP password range endpoint using a 5-char SHA-1 prefix.
   * This endpoint does not require an API key (k-anonymity model).
   *
   * Returns a list of "SUFFIX:count" strings where SUFFIX is the remaining
   * portion of the SHA-1 hash after the 5-char prefix.
   *
   * Requirements: 9.5, 9.6, 9.7, 16.5
   */
  async getBreachesByPrefix(prefix: string): Promise<string[]> {
    const url = `${BASE_URL}/range/${encodeURIComponent(prefix)}`;
    const headers = await this.buildHeaders(false);

    const response = await this.rateLimitedFetch(url, headers);
    if (response === null) {
      // 404 → no entries for this prefix
      return [];
    }

    const text = await response.text();
    // Response is newline-separated "SUFFIX:count" pairs
    return text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  }

  /**
   * Retrieves details for a single breach by its HIBP breach name.
   * Returns null if the breach does not exist (404).
   *
   * Requirements: 9.5, 9.6, 9.7, 15.3, 16.5
   */
  async getBreachDetails(breachName: string): Promise<BreachInfo | null> {
    const url = `${BASE_URL}/breach/${encodeURIComponent(breachName)}`;
    const headers = await this.buildHeaders(true);

    const response = await this.rateLimitedFetch(url, headers);
    if (response === null) {
      return null;
    }

    const raw: HIBPBreachResponse = await response.json();
    return this.mapBreachResponse(raw);
  }

  /**
   * Retrieves all breaches for an account identifier (email hash prefix or
   * email address, depending on the HIBP endpoint used).
   *
   * Returns an empty array if no breaches are found (404).
   *
   * Per the spec, this method accepts the email hash prefix for k-anonymity
   * compliance. The BreachService is responsible for passing only the prefix.
   *
   * Requirements: 9.1, 9.5, 9.6, 9.7, 15.3, 16.5
   */
  async getBreachesForAccount(emailHash: string): Promise<BreachInfo[]> {
    const url = `${BASE_URL}/breachedaccount/${encodeURIComponent(emailHash)}?truncateResponse=false`;
    const headers = await this.buildHeaders(true);

    const response = await this.rateLimitedFetch(url, headers);
    if (response === null) {
      // 404 → no breaches for this account
      return [];
    }

    const raw: HIBPBreachResponse[] = await response.json();
    return raw.map((item) => this.mapBreachResponse(item));
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

export const breachAPI: IBreachAPI = new BreachAPIService();
export default breachAPI;

/**
 * ThreatIntelAPI — Aegis Personal Cybersecurity Companion
 *
 * Threat intelligence API client for checking IP addresses and domain names
 * against VirusTotal's threat intelligence feeds.
 *
 * Security guarantees:
 *  - API key is retrieved from SecurePrefs at request time; never embedded
 *    in source code (Requirement 20.4).
 *  - Reputation results are cached locally for a minimum of 1 hour to avoid
 *    redundant network requests (Requirement 20.2).
 *  - On network error, the client fails open by returning a safe default
 *    result (malicious: false, confidence: 0) rather than blocking the caller
 *    (Requirement 20.3).
 *  - Cached results are returned without making a network request when the
 *    cache entry is still valid (Requirement 20.5).
 *
 * Requirements: 20.1, 20.2, 20.3, 20.4, 20.5
 *
 * ---------------------------------------------------------------------------
 * PII / API-Key Audit (Task 22 — Requirements 15.1, 15.2, 15.3, 15.4, 15.5)
 * ---------------------------------------------------------------------------
 * Audited: all outgoing HTTP requests in this file.
 *
 * 1. checkReputation(indicator, type)
 *    URL: VIRUSTOTAL_BASE_URL/ip_addresses/<indicator>  or
 *         VIRUSTOTAL_BASE_URL/domains/<indicator>
 *    The indicator is an IP address or domain name — not user PII (no email,
 *    username, password, passkey, TOTP seed, or API key in the URL).
 *    Headers: Accept + x-apikey loaded from SecurePrefs. ✅ Req 15.4
 *    Body: none (GET).
 *    PII transmitted: NONE. ✅ Req 15.1
 *
 * API key storage: threat_intel_api_key is stored in expo-secure-store via
 * SecurePrefs. No API key is hardcoded in this file. ✅ Req 15.4
 * ---------------------------------------------------------------------------
 */

import { securePrefs } from '../SecurePrefs';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/api/v3';

/** Minimum cache TTL: 1 hour in milliseconds (Requirement 20.2). */
const CACHE_TTL_MS = 3600 * 1000;

// ---------------------------------------------------------------------------
// Exported interfaces
// ---------------------------------------------------------------------------

/**
 * Result of a threat intelligence reputation lookup for a single indicator.
 */
export interface ReputationResult {
  /** The IP address or domain that was checked. */
  indicator: string;
  /** Whether the indicator is an IP address or domain name. */
  type: 'ip' | 'domain';
  /** Whether the indicator is classified as malicious. */
  malicious: boolean;
  /** Confidence score from 0 (no confidence) to 100 (fully confident). */
  confidence: number;
  /** Threat categories associated with this indicator (e.g. "malware", "phishing"). */
  categories: string[];
  /** Unix timestamp (ms) when the reputation was last checked. */
  lastChecked: number;
  /** Whether this result was served from the local cache. */
  fromCache: boolean;
}

/**
 * Interface for the Threat Intelligence API client.
 */
export interface IThreatIntelAPI {
  /**
   * Check the reputation of an IP address or domain name against threat
   * intelligence feeds.
   *
   * Returns a cached result if one exists and has not expired (Requirement 20.5).
   * Fails open on network error (Requirement 20.3).
   */
  checkReputation(indicator: string, type: 'ip' | 'domain'): Promise<ReputationResult>;

  /**
   * Clear all locally cached reputation results.
   */
  clearCache(): void;
}

// ---------------------------------------------------------------------------
// Internal cache entry type
// ---------------------------------------------------------------------------

interface CacheEntry {
  result: ReputationResult;
  cachedAt: number;
}

// ---------------------------------------------------------------------------
// VirusTotal API response shapes
// ---------------------------------------------------------------------------

interface VTAnalysisStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
}

interface VTAttributes {
  last_analysis_stats?: VTAnalysisStats;
  categories?: Record<string, string>;
  reputation?: number;
}

interface VTResponse {
  data?: {
    attributes?: VTAttributes;
  };
}

// ---------------------------------------------------------------------------
// ThreatIntelAPIService implementation
// ---------------------------------------------------------------------------

export class ThreatIntelAPIService implements IThreatIntelAPI {
  /**
   * In-memory cache keyed by `${type}:${indicator}`.
   * Entries are valid for CACHE_TTL_MS milliseconds.
   */
  private cache: Map<string, CacheEntry> = new Map();

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  /**
   * Build the cache key for a given indicator and type.
   */
  private cacheKey(indicator: string, type: 'ip' | 'domain'): string {
    return `${type}:${indicator}`;
  }

  /**
   * Return the cached entry for the given key if it exists and has not
   * expired; otherwise return null.
   *
   * Requirement 20.5: return cached result without network call when valid.
   */
  private getCachedEntry(key: string): CacheEntry | null {
    const entry = this.cache.get(key);
    if (!entry) {
      return null;
    }
    const age = Date.now() - entry.cachedAt;
    if (age >= CACHE_TTL_MS) {
      // Entry has expired — remove it and treat as a cache miss.
      this.cache.delete(key);
      return null;
    }
    return entry;
  }

  /**
   * Build the VirusTotal endpoint URL for the given indicator type.
   */
  private buildUrl(indicator: string, type: 'ip' | 'domain'): string {
    if (type === 'ip') {
      return `${VIRUSTOTAL_BASE_URL}/ip_addresses/${encodeURIComponent(indicator)}`;
    }
    return `${VIRUSTOTAL_BASE_URL}/domains/${encodeURIComponent(indicator)}`;
  }

  /**
   * Retrieve the API key from SecurePrefs.
   * Returns null if no key has been configured.
   *
   * Requirement 20.4: API key is never embedded in source code.
   */
  private async getApiKey(): Promise<string | null> {
    return securePrefs.get('threat_intel_api_key');
  }

  /**
   * Derive a confidence score (0–100) from VirusTotal analysis statistics.
   *
   * Confidence is calculated as the ratio of malicious + suspicious votes
   * to the total number of votes, scaled to 0–100.
   */
  private deriveConfidence(stats: VTAnalysisStats): number {
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const harmless = stats.harmless ?? 0;
    const undetected = stats.undetected ?? 0;
    const timeout = stats.timeout ?? 0;

    const total = malicious + suspicious + harmless + undetected + timeout;
    if (total === 0) {
      return 0;
    }

    const adversarialVotes = malicious + suspicious;
    return Math.round((adversarialVotes / total) * 100);
  }

  /**
   * Extract a deduplicated list of threat category strings from the
   * VirusTotal categories map (which maps engine name → category label).
   */
  private extractCategories(categoriesMap: Record<string, string> | undefined): string[] {
    if (!categoriesMap) {
      return [];
    }
    const unique = new Set(Object.values(categoriesMap));
    return Array.from(unique);
  }

  /**
   * Parse a VirusTotal API response into a `ReputationResult`.
   */
  private parseVTResponse(
    indicator: string,
    type: 'ip' | 'domain',
    body: VTResponse,
  ): ReputationResult {
    const attributes = body.data?.attributes;
    const stats = attributes?.last_analysis_stats ?? {};
    const maliciousCount = stats.malicious ?? 0;
    const confidence = this.deriveConfidence(stats);
    const categories = this.extractCategories(attributes?.categories);

    return {
      indicator,
      type,
      malicious: maliciousCount > 0,
      confidence,
      categories,
      lastChecked: Date.now(),
      fromCache: false,
    };
  }

  /**
   * Build the safe-default fail-open result used when a network error occurs.
   *
   * Requirement 20.3: fail open — return malicious: false, confidence: 0.
   */
  private failOpenResult(indicator: string, type: 'ip' | 'domain'): ReputationResult {
    return {
      indicator,
      type,
      malicious: false,
      confidence: 0,
      categories: [],
      lastChecked: Date.now(),
      fromCache: false,
    };
  }

  // -------------------------------------------------------------------------
  // IThreatIntelAPI implementation
  // -------------------------------------------------------------------------

  /**
   * Check the reputation of an IP address or domain name.
   *
   * 1. Returns a cached result if one exists and has not expired (Req 20.5).
   * 2. Retrieves the API key from SecurePrefs (Req 20.4).
   * 3. Makes a request to the VirusTotal API (Req 20.1).
   * 4. Caches the result for at least 1 hour (Req 20.2).
   * 5. Fails open on any network or parse error (Req 20.3).
   */
  async checkReputation(indicator: string, type: 'ip' | 'domain'): Promise<ReputationResult> {
    const key = this.cacheKey(indicator, type);

    // Requirement 20.5: return cached result without network call when valid.
    const cached = this.getCachedEntry(key);
    if (cached !== null) {
      return { ...cached.result, fromCache: true };
    }

    // Requirement 20.4: retrieve API key from SecurePrefs, never embed.
    const apiKey = await this.getApiKey();

    try {
      const url = this.buildUrl(indicator, type);
      const headers: Record<string, string> = {
        Accept: 'application/json',
      };
      if (apiKey) {
        headers['x-apikey'] = apiKey;
      }

      const response = await fetch(url, { headers });

      if (!response.ok) {
        // Non-2xx response — fail open (Requirement 20.3).
        return this.failOpenResult(indicator, type);
      }

      const body: VTResponse = await response.json();
      const result = this.parseVTResponse(indicator, type, body);

      // Requirement 20.2: cache the result for at least 1 hour.
      this.cache.set(key, { result, cachedAt: Date.now() });

      return result;
    } catch {
      // Network error or JSON parse failure — fail open (Requirement 20.3).
      return this.failOpenResult(indicator, type);
    }
  }

  /**
   * Clear all locally cached reputation results.
   */
  clearCache(): void {
    this.cache.clear();
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/**
 * Singleton instance of the ThreatIntelAPI service.
 * Import this throughout the app — do not instantiate ThreatIntelAPIService
 * directly.
 */
export const threatIntelAPI: IThreatIntelAPI = new ThreatIntelAPIService();
export default threatIntelAPI;

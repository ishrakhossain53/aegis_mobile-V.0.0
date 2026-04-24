/**
 * DoHResolver — DNS-over-HTTPS client for Aegis.
 *
 * Supports Cloudflare, Google, and Quad9 providers with:
 *  - application/dns-json content type
 *  - TTL-based result caching
 *  - 3-second per-provider timeout with automatic fallback
 *  - System DNS fallback (empty addresses + warning) when all providers fail
 *
 * Requirements: 8.5, 8.6, 8.7, 8.8, 8.9
 *
 * ---------------------------------------------------------------------------
 * PII / API-Key Audit (Task 22 — Requirements 15.1, 15.2, 15.3, 15.4, 15.5)
 * ---------------------------------------------------------------------------
 * Audited: all outgoing HTTP requests in this file.
 *
 * 1. queryProvider(provider, hostname)
 *    URL: <provider-url>?name=<hostname>&type=A
 *    The hostname is a DNS name (e.g. "haveibeenpwned.com") — not user PII.
 *    No email, username, password, passkey, TOTP seed, or API key appears in
 *    the URL, headers, or body.
 *    Headers: Accept: application/dns-json only. No authentication header.
 *    Body: none (GET).
 *    PII transmitted: NONE. ✅ Req 15.1
 *
 * No API keys are required or used by the DoH protocol. ✅ Req 15.4
 * ---------------------------------------------------------------------------
 */

import { DoHProvider } from '../../types/index';

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

export interface DoHResult {
  /** Resolved IP addresses */
  addresses: string[];
  /** TTL in seconds from the DNS response */
  ttl: number;
  /** Which provider served this result */
  provider: DoHProvider;
  /** Whether the result was served from the local cache */
  fromCache: boolean;
}

export interface IDoHResolver {
  resolve(hostname: string): Promise<DoHResult>;
  setProvider(provider: DoHProvider): void;
  getProvider(): DoHProvider;
  clearCache(): void;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface ProviderConfig {
  name: DoHProvider;
  /** Full HTTPS URL for the DoH endpoint */
  url: string;
  /** Bootstrap IP to avoid circular DNS dependency */
  bootstrapIP: string;
}

interface CacheEntry {
  addresses: string[];
  ttl: number;
  cachedAt: number;
  provider: DoHProvider;
}

/** Shape of a single answer record in the application/dns-json response */
interface DoHAnswerRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

/** Minimal shape of the application/dns-json response body */
interface DoHJsonResponse {
  Status: number;
  Answer?: DoHAnswerRecord[];
}

// ---------------------------------------------------------------------------
// Provider registry
// ---------------------------------------------------------------------------

const PROVIDER_ORDER: DoHProvider[] = ['cloudflare', 'google', 'quad9'];

const DOH_PROVIDERS: Record<DoHProvider, ProviderConfig> = {
  cloudflare: {
    name: 'cloudflare',
    url: 'https://cloudflare-dns.com/dns-query',
    bootstrapIP: '1.1.1.1',
  },
  google: {
    name: 'google',
    url: 'https://dns.google/resolve',
    bootstrapIP: '8.8.8.8',
  },
  quad9: {
    name: 'quad9',
    url: 'https://dns.quad9.net/dns-query',
    bootstrapIP: '9.9.9.9',
  },
};

/** DNS A-record type number */
const DNS_TYPE_A = 1;
/** Timeout per provider in milliseconds (Requirement 8.7) */
const PROVIDER_TIMEOUT_MS = 3000;
/** Minimum TTL to cache (seconds) — prevents zero-TTL thrashing */
const MIN_CACHE_TTL_S = 30;

// ---------------------------------------------------------------------------
// DoHResolver implementation
// ---------------------------------------------------------------------------

export class DoHResolver implements IDoHResolver {
  private currentProvider: DoHProvider = 'cloudflare';
  private cache: Map<string, CacheEntry> = new Map();

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  setProvider(provider: DoHProvider): void {
    this.currentProvider = provider;
  }

  getProvider(): DoHProvider {
    return this.currentProvider;
  }

  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Resolve a hostname to IPv4 addresses via DNS-over-HTTPS.
   *
   * Fallback order (Requirement 8.7, 8.8):
   *   configured provider → next provider → next → system DNS (empty addresses)
   */
  async resolve(hostname: string): Promise<DoHResult> {
    // 1. Check cache first (Requirement 8.9)
    const cached = this.getCached(hostname);
    if (cached) {
      return {
        addresses: cached.addresses,
        ttl: cached.ttl,
        provider: cached.provider,
        fromCache: true,
      };
    }

    // 2. Build fallback order starting from the configured provider
    const fallbackOrder = this.buildFallbackOrder(this.currentProvider);

    // 3. Try each provider in order
    for (const provider of fallbackOrder) {
      const result = await this.queryProvider(provider, hostname);
      if (result !== null) {
        // Cache the successful result
        this.cacheResult(hostname, result);
        return { ...result, fromCache: false };
      }
    }

    // 4. All providers failed — fall back to system DNS (Requirement 8.8)
    console.warn(
      '[DoHResolver] All DoH providers unreachable for hostname "%s". ' +
        'Falling back to system DNS.',
      hostname,
    );
    return {
      addresses: [],
      ttl: 0,
      provider: this.currentProvider,
      fromCache: false,
    };
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Returns a fallback order that starts with the configured provider and
   * cycles through the remaining providers in the canonical order.
   */
  private buildFallbackOrder(primary: DoHProvider): DoHProvider[] {
    const rest = PROVIDER_ORDER.filter((p) => p !== primary);
    return [primary, ...rest];
  }

  /**
   * Query a single DoH provider with a 3-second timeout.
   * Returns null on any error (timeout, network failure, bad response).
   */
  private async queryProvider(
    provider: DoHProvider,
    hostname: string,
  ): Promise<Omit<DoHResult, 'fromCache'> | null> {
    const config = DOH_PROVIDERS[provider];
    const url = `${config.url}?name=${encodeURIComponent(hostname)}&type=A`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          Accept: 'application/dns-json',
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        return null;
      }

      const json: DoHJsonResponse = await response.json();

      // SERVFAIL (Status !== 0) or no Answer section → treat as not found
      if (json.Status !== 0 || !json.Answer) {
        return {
          addresses: [],
          ttl: MIN_CACHE_TTL_S,
          provider,
        };
      }

      // Extract A records
      const aRecords = json.Answer.filter((r) => r.type === DNS_TYPE_A);
      const addresses = aRecords.map((r) => r.data);

      // Use the minimum TTL across all A records (conservative caching)
      const ttl =
        aRecords.length > 0
          ? Math.max(MIN_CACHE_TTL_S, Math.min(...aRecords.map((r) => r.TTL)))
          : MIN_CACHE_TTL_S;

      return { addresses, ttl, provider };
    } catch {
      // AbortError (timeout) or network error — try next provider
      return null;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Return a cached entry if it is still within its TTL window.
   * Cache validity: Date.now() < cachedAt + ttl * 1000
   */
  private getCached(hostname: string): CacheEntry | null {
    const entry = this.cache.get(hostname);
    if (!entry) return null;

    const expiresAt = entry.cachedAt + entry.ttl * 1000;
    if (Date.now() < expiresAt) {
      return entry;
    }

    // Expired — evict
    this.cache.delete(hostname);
    return null;
  }

  private cacheResult(
    hostname: string,
    result: Omit<DoHResult, 'fromCache'>,
  ): void {
    this.cache.set(hostname, {
      addresses: result.addresses,
      ttl: result.ttl,
      cachedAt: Date.now(),
      provider: result.provider,
    });
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/** Singleton DoH resolver instance used across the application. */
export const dohResolver: IDoHResolver = new DoHResolver();

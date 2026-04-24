/**
 * Tests for ThreatIntelAPI
 *
 * Requirements: 20.1, 20.2, 20.3, 20.4, 20.5
 */

// ---------------------------------------------------------------------------
// Mock SecurePrefs before importing the service
// ---------------------------------------------------------------------------

jest.mock('../SecurePrefs', () => ({
  securePrefs: {
    get: jest.fn(),
  },
}));

// ---------------------------------------------------------------------------
// Mock global fetch
// ---------------------------------------------------------------------------

const mockFetch = jest.fn<Promise<Response>, [RequestInfo | URL, RequestInit?]>();
global.fetch = mockFetch as typeof fetch;

// ---------------------------------------------------------------------------
// Import after mocks are set up
// ---------------------------------------------------------------------------

import { ThreatIntelAPIService } from './ThreatIntelAPI';
import type { ReputationResult } from './ThreatIntelAPI';
import { securePrefs } from '../SecurePrefs';

// Typed reference to the mocked get function
const mockSecurePrefsGet = securePrefs.get as jest.MockedFunction<typeof securePrefs.get>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Creates a fresh service instance for each test to avoid shared state. */
function makeService(): ThreatIntelAPIService {
  return new ThreatIntelAPIService();
}

/** Build a minimal VirusTotal-style JSON response body. */
function vtResponse(malicious: number, total: number, categories: Record<string, string> = {}): object {
  const harmless = total - malicious;
  return {
    data: {
      attributes: {
        last_analysis_stats: {
          malicious,
          suspicious: 0,
          harmless: harmless >= 0 ? harmless : 0,
          undetected: 0,
          timeout: 0,
        },
        categories,
      },
    },
  };
}

/** Build a mock Response object. */
function mockResponse(body: object, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: jest.fn().mockResolvedValue(body),
    headers: new Headers(),
  } as unknown as Response;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ThreatIntelAPI', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSecurePrefsGet.mockResolvedValue('test-api-key');
  });

  // -------------------------------------------------------------------------
  // Requirement 20.1 — check IP addresses and domains against threat feeds
  // -------------------------------------------------------------------------

  describe('Requirement 20.1 — reputation lookup', () => {
    it('returns a ReputationResult for an IP address', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      const result = await svc.checkReputation('1.2.3.4', 'ip');

      expect(result.indicator).toBe('1.2.3.4');
      expect(result.type).toBe('ip');
      expect(typeof result.malicious).toBe('boolean');
      expect(typeof result.confidence).toBe('number');
      expect(Array.isArray(result.categories)).toBe(true);
      expect(typeof result.lastChecked).toBe('number');
    });

    it('returns a ReputationResult for a domain', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      const result = await svc.checkReputation('example.com', 'domain');

      expect(result.indicator).toBe('example.com');
      expect(result.type).toBe('domain');
    });

    it('marks result as malicious when VirusTotal reports malicious votes', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(10, 70)));

      const result = await svc.checkReputation('evil.com', 'domain');

      expect(result.malicious).toBe(true);
      expect(result.confidence).toBeGreaterThan(0);
    });

    it('marks result as not malicious when no malicious votes', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      const result = await svc.checkReputation('safe.com', 'domain');

      expect(result.malicious).toBe(false);
    });

    it('extracts deduplicated categories from the VirusTotal response', async () => {
      const svc = makeService();
      const categories = { engine1: 'malware', engine2: 'phishing', engine3: 'malware' };
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(5, 70, categories)));

      const result = await svc.checkReputation('bad.com', 'domain');

      // 'malware' appears twice but should be deduplicated
      expect(result.categories).toContain('malware');
      expect(result.categories).toContain('phishing');
      expect(result.categories.filter((c) => c === 'malware').length).toBe(1);
    });

    it('uses the VirusTotal IP endpoint for type=ip', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('8.8.8.8', 'ip');

      const calledUrl = mockFetch.mock.calls[0][0] as string;
      expect(calledUrl).toContain('/ip_addresses/8.8.8.8');
    });

    it('uses the VirusTotal domain endpoint for type=domain', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('example.com', 'domain');

      const calledUrl = mockFetch.mock.calls[0][0] as string;
      expect(calledUrl).toContain('/domains/example.com');
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 20.2 — cache results for minimum 1 hour
  // -------------------------------------------------------------------------

  describe('Requirement 20.2 — 1-hour cache', () => {
    it('makes only one network request for repeated lookups within 1 hour', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValue(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('1.2.3.4', 'ip');
      await svc.checkReputation('1.2.3.4', 'ip');
      await svc.checkReputation('1.2.3.4', 'ip');

      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('makes separate network requests for different indicators', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValue(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('1.2.3.4', 'ip');
      await svc.checkReputation('5.6.7.8', 'ip');

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('makes separate network requests for same indicator with different types', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValue(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('example.com', 'ip');
      await svc.checkReputation('example.com', 'domain');

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('re-fetches after cache expires (1 hour)', async () => {
      jest.useFakeTimers();
      const svc = makeService();
      mockFetch.mockResolvedValue(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('1.2.3.4', 'ip');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Advance time past the 1-hour TTL
      jest.advanceTimersByTime(3600 * 1000 + 1);

      await svc.checkReputation('1.2.3.4', 'ip');
      expect(mockFetch).toHaveBeenCalledTimes(2);

      jest.useRealTimers();
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 20.3 — fail open on network error
  // -------------------------------------------------------------------------

  describe('Requirement 20.3 — fail open on network error', () => {
    it('returns malicious: false, confidence: 0 when fetch throws', async () => {
      const svc = makeService();
      mockFetch.mockRejectedValueOnce(new Error('Network unreachable'));

      const result = await svc.checkReputation('1.2.3.4', 'ip');

      expect(result.malicious).toBe(false);
      expect(result.confidence).toBe(0);
      expect(result.categories).toEqual([]);
      expect(result.indicator).toBe('1.2.3.4');
      expect(result.type).toBe('ip');
    });

    it('returns malicious: false, confidence: 0 on non-2xx HTTP response', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse({}, 500));

      const result = await svc.checkReputation('bad-server.com', 'domain');

      expect(result.malicious).toBe(false);
      expect(result.confidence).toBe(0);
    });

    it('returns malicious: false, confidence: 0 when JSON parse fails', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: jest.fn().mockRejectedValue(new SyntaxError('Unexpected token')),
        headers: new Headers(),
      } as unknown as Response);

      const result = await svc.checkReputation('1.2.3.4', 'ip');

      expect(result.malicious).toBe(false);
      expect(result.confidence).toBe(0);
    });

    it('does not throw when a network error occurs', async () => {
      const svc = makeService();
      mockFetch.mockRejectedValueOnce(new Error('timeout'));

      await expect(svc.checkReputation('1.2.3.4', 'ip')).resolves.toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 20.4 — API key from SecurePrefs, never embedded
  // -------------------------------------------------------------------------

  describe('Requirement 20.4 — API key from SecurePrefs', () => {
    it('retrieves the API key from SecurePrefs on each uncached request', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValue(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('1.2.3.4', 'ip');

      expect(mockSecurePrefsGet).toHaveBeenCalledWith('threat_intel_api_key');
    });

    it('includes the API key in the x-apikey header', async () => {
      const svc = makeService();
      mockSecurePrefsGet.mockResolvedValueOnce('my-secret-key');
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('1.2.3.4', 'ip');

      const callArgs = mockFetch.mock.calls[0];
      const requestInit = callArgs[1] as RequestInit;
      const headers = requestInit.headers as Record<string, string>;
      expect(headers['x-apikey']).toBe('my-secret-key');
    });

    it('proceeds without x-apikey header when no API key is configured', async () => {
      const svc = makeService();
      mockSecurePrefsGet.mockResolvedValueOnce(null);
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      // Should not throw even without an API key
      const result = await svc.checkReputation('1.2.3.4', 'ip');

      const callArgs = mockFetch.mock.calls[0];
      const requestInit = callArgs[1] as RequestInit;
      const headers = requestInit.headers as Record<string, string>;
      expect(headers['x-apikey']).toBeUndefined();
      expect(result).toBeDefined();
    });

    it('does not call SecurePrefs for cached results', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValue(mockResponse(vtResponse(0, 70)));

      // First call — fetches from network and reads API key
      await svc.checkReputation('1.2.3.4', 'ip');
      const firstCallCount = mockSecurePrefsGet.mock.calls.length;

      // Second call — served from cache, should not read API key again
      await svc.checkReputation('1.2.3.4', 'ip');
      expect(mockSecurePrefsGet.mock.calls.length).toBe(firstCallCount);
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 20.5 — return cached result without network call
  // -------------------------------------------------------------------------

  describe('Requirement 20.5 — cached result returned without network call', () => {
    it('returns fromCache: false on first (network) fetch', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      const result = await svc.checkReputation('1.2.3.4', 'ip');

      expect(result.fromCache).toBe(false);
    });

    it('returns fromCache: true on subsequent calls within TTL', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('1.2.3.4', 'ip');
      const cached = await svc.checkReputation('1.2.3.4', 'ip');

      expect(cached.fromCache).toBe(true);
    });

    it('preserves the original result data when returning from cache', async () => {
      const svc = makeService();
      const categories = { engine1: 'malware' };
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(5, 70, categories)));

      const first = await svc.checkReputation('evil.com', 'domain');
      const second = await svc.checkReputation('evil.com', 'domain');

      expect(second.malicious).toBe(first.malicious);
      expect(second.confidence).toBe(first.confidence);
      expect(second.categories).toEqual(first.categories);
      expect(second.indicator).toBe(first.indicator);
      expect(second.type).toBe(first.type);
    });

    it('makes no network request when a valid cache entry exists', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('1.2.3.4', 'ip');
      mockFetch.mockClear();

      await svc.checkReputation('1.2.3.4', 'ip');

      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // clearCache()
  // -------------------------------------------------------------------------

  describe('clearCache()', () => {
    it('forces a new network request after cache is cleared', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValue(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('1.2.3.4', 'ip');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      svc.clearCache();

      await svc.checkReputation('1.2.3.4', 'ip');
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('returns fromCache: false after cache is cleared', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValue(mockResponse(vtResponse(0, 70)));

      await svc.checkReputation('1.2.3.4', 'ip');
      svc.clearCache();

      const result = await svc.checkReputation('1.2.3.4', 'ip');
      expect(result.fromCache).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Confidence score calculation
  // -------------------------------------------------------------------------

  describe('confidence score calculation', () => {
    it('returns confidence 0 when there are no analysis votes', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(
        mockResponse({
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 0,
                harmless: 0,
                undetected: 0,
                timeout: 0,
              },
            },
          },
        }),
      );

      const result = await svc.checkReputation('1.2.3.4', 'ip');
      expect(result.confidence).toBe(0);
    });

    it('returns confidence 100 when all votes are malicious', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(70, 70)));

      const result = await svc.checkReputation('evil.com', 'domain');
      expect(result.confidence).toBe(100);
    });

    it('returns confidence between 0 and 100 for mixed votes', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(35, 70)));

      const result = await svc.checkReputation('mixed.com', 'domain');
      expect(result.confidence).toBeGreaterThan(0);
      expect(result.confidence).toBeLessThan(100);
    });
  });

  // -------------------------------------------------------------------------
  // lastChecked timestamp
  // -------------------------------------------------------------------------

  describe('lastChecked timestamp', () => {
    it('sets lastChecked to approximately the current time', async () => {
      const svc = makeService();
      mockFetch.mockResolvedValueOnce(mockResponse(vtResponse(0, 70)));

      const before = Date.now();
      const result = await svc.checkReputation('1.2.3.4', 'ip');
      const after = Date.now();

      expect(result.lastChecked).toBeGreaterThanOrEqual(before);
      expect(result.lastChecked).toBeLessThanOrEqual(after);
    });
  });
});

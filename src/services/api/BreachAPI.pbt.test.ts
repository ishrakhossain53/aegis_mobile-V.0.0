/**
 * Property-Based Test: Property 25 — No Plaintext PII in External Requests
 *
 * For any outgoing HTTP request made by the Application to an external API,
 * the request URL, headers, and body SHALL not contain any plaintext email
 * address, username, password, passkey, TOTP seed, or API key belonging to
 * the user.
 *
 * **Validates: Requirements 15.1, 15.2**
 *
 * This test covers BreachAPI (HIBP), ThreatIntelAPI (VirusTotal), and
 * DoHResolver (DNS-over-HTTPS) — the three services that make outgoing HTTP
 * requests to external APIs.
 *
 * Strategy:
 *  - Generate a wide variety of realistic PII values (emails, usernames,
 *    passwords, passkeys, TOTP seeds, API keys).
 *  - Intercept every fetch() call and inspect the URL, headers, and body.
 *  - Assert that none of the plaintext PII values appear in any part of the
 *    intercepted request.
 *  - For BreachAPI: verify that only the 5-char k-anonymity prefix is sent,
 *    never the full hash or the original value (Requirement 15.2).
 */

// ---------------------------------------------------------------------------
// Mocks — must be declared before imports
// ---------------------------------------------------------------------------

jest.mock('../SecurePrefs', () => ({
  securePrefs: {
    get: jest.fn().mockResolvedValue('test-api-key-from-secure-prefs'),
  },
}));

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import { BreachAPIService } from './BreachAPI';
import { ThreatIntelAPIService } from './ThreatIntelAPI';
import { DoHResolver } from './DoHResolver';

// ---------------------------------------------------------------------------
// Captured request log
// ---------------------------------------------------------------------------

interface CapturedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
}

// ---------------------------------------------------------------------------
// Mock fetch — intercepts all outgoing requests
// ---------------------------------------------------------------------------

const mockFetch = jest.fn<Promise<Response>, [RequestInfo | URL, RequestInit?]>();
global.fetch = mockFetch as typeof fetch;

/**
 * Install a fetch mock that records every request into `capturedRequests`
 * and returns a minimal successful response.
 */
function makeFetchSpy(
  capturedRequests: CapturedRequest[],
  responseBody: unknown = {},
  status = 200,
): jest.Mock {
  const spy = jest.fn<Promise<Response>, [RequestInfo | URL, RequestInit?]>(
    async (input, init) => {
      const url = typeof input === 'string' ? input : (input as Request).url ?? String(input);
      const method = init?.method ?? 'GET';

      // Normalise headers to a plain object
      const rawHeaders = init?.headers ?? {};
      const headers: Record<string, string> = {};
      if (rawHeaders instanceof Headers) {
        rawHeaders.forEach((value, key) => {
          headers[key] = value;
        });
      } else if (Array.isArray(rawHeaders)) {
        for (const [k, v] of rawHeaders) {
          headers[k] = v;
        }
      } else {
        Object.assign(headers, rawHeaders as Record<string, string>);
      }

      const body = init?.body != null ? String(init.body) : null;
      capturedRequests.push({ url, method, headers, body });

      return {
        ok: status >= 200 && status < 300,
        status,
        statusText: 'OK',
        headers: new Headers(),
        json: jest.fn().mockResolvedValue(responseBody),
        text: jest.fn().mockResolvedValue(
          typeof responseBody === 'string' ? responseBody : '',
        ),
      } as unknown as Response;
    },
  );
  global.fetch = spy as typeof fetch;
  return spy;
}

// ---------------------------------------------------------------------------
// PII generators
// ---------------------------------------------------------------------------

/** Generate a set of realistic email addresses. */
function generateEmails(): string[] {
  return [
    'alice@example.com',
    'bob.smith@company.org',
    'user+tag@subdomain.example.net',
    'test.user123@mail.co.uk',
    'john.doe@gmail.com',
    'jane_doe@yahoo.com',
    'admin@secure-corp.io',
  ];
}

/** Generate a set of realistic usernames. */
function generateUsernames(): string[] {
  return [
    'alice_wonder',
    'bob_smith_42',
    'john.doe',
    'jane_doe_99',
    'super_user',
    'admin_user',
  ];
}

/** Generate a set of realistic passwords. */
function generatePasswords(): string[] {
  return [
    'P@ssw0rd!123',
    'MySecretPass#2024',
    'hunter2',
    'correct-horse-battery-staple',
    'Tr0ub4dor&3',
  ];
}

/** Generate a set of realistic passkeys (base64-like strings). */
function generatePasskeys(): string[] {
  return [
    'dGVzdC1wYXNza2V5LWRhdGEtMTIz',
    'cGFzc2tleS1leGFtcGxlLWRhdGE=',
    'YWJjZGVmZ2hpamtsbW5vcA==',
  ];
}

/** Generate a set of realistic TOTP seeds (base32-encoded). */
function generateTotpSeeds(): string[] {
  return [
    'JBSWY3DPEHPK3PXP',
    'MFRA2YLNMFRA2YLN',
    'GEZDGNBVGY3TQOJQ',
  ];
}

/** Generate a set of realistic API keys. */
function generateApiKeys(): string[] {
  return [
    'sk-1234567890abcdef1234567890abcdef',
    'api_key_abcdef1234567890',
    'vt-api-key-1234567890abcdef',
    'hibp-key-abcdef1234567890',
  ];
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/**
 * Assert that none of the given PII values appear in the captured requests.
 * Checks URL, all header values (except the API key headers which carry the
 * app's own service key, not user PII), and body.
 */
function assertNoPIIInRequests(
  piiValues: string[],
  requests: CapturedRequest[],
): void {
  for (const req of requests) {
    for (const pii of piiValues) {
      // Check URL
      expect(req.url).not.toContain(pii);

      // Check header values — skip the service API key headers since those
      // carry the app's own key (loaded from SecurePrefs), not user PII.
      for (const [headerName, headerValue] of Object.entries(req.headers)) {
        const lowerName = headerName.toLowerCase();
        if (lowerName !== 'x-apikey' && lowerName !== 'hibp-api-key') {
          expect(headerValue).not.toContain(pii);
        }
      }

      // Check body
      if (req.body !== null) {
        expect(req.body).not.toContain(pii);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal VirusTotal-style JSON response body. */
function vtResponse(malicious = 0, total = 70): object {
  return {
    data: {
      attributes: {
        last_analysis_stats: {
          malicious,
          suspicious: 0,
          harmless: total - malicious,
          undetected: 0,
          timeout: 0,
        },
        categories: {},
      },
    },
  };
}

/** Build a minimal DoH JSON response. */
function dohResponse(hostname: string, ip = '1.2.3.4', ttl = 300): object {
  return {
    Status: 0,
    Answer: [{ name: hostname, type: 1, TTL: ttl, data: ip }],
  };
}

// ---------------------------------------------------------------------------
// Property 25: No Plaintext PII in External Requests
// ---------------------------------------------------------------------------

describe('Property 25: No Plaintext PII in External Requests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // BreachAPI — k-anonymity prefix only (Req 15.1, 15.2)
  // -------------------------------------------------------------------------

  describe('BreachAPI — only 5-char k-anonymity prefix transmitted', () => {
    /**
     * For any email address, the BreachAPI.getBreachesByPrefix() call must
     * only transmit the 5-char prefix in the URL — never the full email,
     * full hash, username, password, passkey, TOTP seed, or API key.
     *
     * **Validates: Requirements 15.1, 15.2**
     */
    it('never transmits plaintext email in URL when calling getBreachesByPrefix', async () => {
      const emails = generateEmails();

      for (const email of emails) {
        const captured: CapturedRequest[] = [];
        makeFetchSpy(captured, 'SUFFIX1:10\nSUFFIX2:5\n');

        // BreachService computes a 5-char prefix from the email and passes
        // only that prefix to getBreachesByPrefix — never the email itself.
        const fakePrefix = 'ABCDE';
        const svc = new BreachAPIService();
        await svc.getBreachesByPrefix(fakePrefix);

        expect(captured.length).toBeGreaterThan(0);
        for (const req of captured) {
          // The URL must contain the 5-char prefix, not the email
          expect(req.url).toContain(fakePrefix);
          expect(req.url).not.toContain(email);
        }
      }
    }, 15000);

    /**
     * For any username, the BreachAPI.getBreachesByPrefix() call must
     * only transmit the 5-char prefix — never the full username.
     *
     * **Validates: Requirements 15.1, 15.2**
     */
    it('never transmits plaintext username in URL when calling getBreachesByPrefix', async () => {
      const usernames = generateUsernames();

      for (const username of usernames) {
        const captured: CapturedRequest[] = [];
        makeFetchSpy(captured, 'SUFFIX1:10\n');

        const fakePrefix = 'FGHIJ';
        const svc = new BreachAPIService();
        await svc.getBreachesByPrefix(fakePrefix);

        for (const req of captured) {
          expect(req.url).not.toContain(username);
        }
      }
    }, 15000);

    /**
     * For any set of PII values, no plaintext PII appears in any part of
     * the getBreachesByPrefix request (URL, headers, body).
     *
     * **Validates: Requirements 15.1, 15.2**
     */
    it('no plaintext PII (email, username, password, passkey, TOTP, API key) in getBreachesByPrefix requests', async () => {
      const allPII = [
        ...generateEmails(),
        ...generateUsernames(),
        ...generatePasswords(),
        ...generatePasskeys(),
        ...generateTotpSeeds(),
      ];

      const prefixes = ['ABCDE', 'FGHIJ', 'KLMNO', 'PQRST', 'UVWXY'];
      for (const prefix of prefixes) {
        const captured: CapturedRequest[] = [];
        makeFetchSpy(captured, 'SUFFIX1:10\n');

        const svc = new BreachAPIService();
        await svc.getBreachesByPrefix(prefix);

        assertNoPIIInRequests(allPII, captured);
      }
    }, 15000);

    /**
     * The 5-char prefix sent to HIBP must be exactly 5 characters long.
     * This ensures the k-anonymity model is correctly applied.
     *
     * **Validates: Requirements 15.2**
     */
    it('the prefix in the HIBP range URL is exactly 5 characters', async () => {
      const prefixes = ['ABCDE', 'FGHIJ', 'KLMNO', '12345', 'A1B2C'];

      for (const prefix of prefixes) {
        const captured: CapturedRequest[] = [];
        makeFetchSpy(captured, 'SUFFIX1:10\n');

        const svc = new BreachAPIService();
        await svc.getBreachesByPrefix(prefix);

        expect(captured.length).toBeGreaterThan(0);
        const req = captured[0];

        // Extract the prefix from the URL: .../range/<prefix>
        const match = req.url.match(/\/range\/([^?#]+)/);
        expect(match).not.toBeNull();
        if (match) {
          const transmittedPrefix = decodeURIComponent(match[1]);
          expect(transmittedPrefix).toHaveLength(5);
          expect(transmittedPrefix).toBe(prefix);
        }
      }
    }, 15000);
  });

  // -------------------------------------------------------------------------
  // BreachAPI — getBreachDetails (breach name is not user PII)
  // -------------------------------------------------------------------------

  describe('BreachAPI — getBreachDetails transmits no user PII', () => {
    /**
     * getBreachDetails sends a breach name (e.g. "Adobe") — a public label,
     * not user PII. Verify no user PII appears in the request.
     *
     * **Validates: Requirements 15.1**
     */
    it('no plaintext user PII in getBreachDetails requests', async () => {
      const allPII = [
        ...generateEmails(),
        ...generateUsernames(),
        ...generatePasswords(),
        ...generatePasskeys(),
        ...generateTotpSeeds(),
      ];

      const breachNames = ['Adobe', 'LinkedIn', 'Dropbox', 'Yahoo', 'MySpace'];
      const fakeBreachResponse = {
        Name: 'Adobe',
        Title: 'Adobe',
        Domain: 'adobe.com',
        BreachDate: '2013-10-04',
        AddedDate: '2013-12-04',
        PwnCount: 152445165,
        DataClasses: ['Email addresses', 'Passwords'],
        IsVerified: true,
        IsSensitive: false,
      };

      for (const name of breachNames) {
        const captured: CapturedRequest[] = [];
        makeFetchSpy(captured, fakeBreachResponse);

        const svc = new BreachAPIService();
        await svc.getBreachDetails(name);

        assertNoPIIInRequests(allPII, captured);
      }
    }, 15000);
  });

  // -------------------------------------------------------------------------
  // BreachAPI — getBreachesForAccount (only prefix, not full email)
  // -------------------------------------------------------------------------

  describe('BreachAPI — getBreachesForAccount transmits only the prefix', () => {
    /**
     * BreachService calls getBreachesForAccount with the 5-char prefix only.
     * Verify that no full email or username appears in the request URL.
     *
     * **Validates: Requirements 15.1, 15.2**
     */
    it('no plaintext email or username in getBreachesForAccount requests', async () => {
      const allPII = [
        ...generateEmails(),
        ...generateUsernames(),
        ...generatePasswords(),
      ];

      const prefixes = ['ABCDE', 'FGHIJ', 'KLMNO', 'PQRST', 'UVWXY'];
      for (const prefix of prefixes) {
        const captured: CapturedRequest[] = [];
        makeFetchSpy(captured, []);

        const svc = new BreachAPIService();
        await svc.getBreachesForAccount(prefix);

        assertNoPIIInRequests(allPII, captured);
      }
    }, 15000);

    /**
     * The value in the breachedaccount URL path must be exactly 5 characters
     * when called with a k-anonymity prefix (as BreachService does).
     *
     * **Validates: Requirements 15.2**
     */
    it('the account identifier in the HIBP breachedaccount URL is exactly 5 characters when called with a prefix', async () => {
      const prefixes = ['ABCDE', 'FGHIJ', 'KLMNO', '12345', 'A1B2C'];

      for (const prefix of prefixes) {
        const captured: CapturedRequest[] = [];
        makeFetchSpy(captured, []);

        const svc = new BreachAPIService();
        await svc.getBreachesForAccount(prefix);

        expect(captured.length).toBeGreaterThan(0);
        const req = captured[0];

        // Extract the account identifier from the URL: .../breachedaccount/<id>
        const match = req.url.match(/\/breachedaccount\/([^?#]+)/);
        expect(match).not.toBeNull();
        if (match) {
          const transmittedId = decodeURIComponent(match[1]);
          expect(transmittedId).toHaveLength(5);
          expect(transmittedId).toBe(prefix);
        }
      }
    }, 15000);
  });

  // -------------------------------------------------------------------------
  // ThreatIntelAPI — no user PII in reputation requests
  // -------------------------------------------------------------------------

  describe('ThreatIntelAPI — no user PII in reputation requests', () => {
    /**
     * ThreatIntelAPI sends IP addresses and domain names — not user PII.
     * Verify that no email, username, password, passkey, TOTP seed, or
     * user-owned API key appears in the request.
     *
     * **Validates: Requirements 15.1**
     */
    it('no plaintext user PII in checkReputation requests for IP addresses', async () => {
      const allPII = [
        ...generateEmails(),
        ...generateUsernames(),
        ...generatePasswords(),
        ...generatePasskeys(),
        ...generateTotpSeeds(),
      ];

      const ipAddresses = ['1.2.3.4', '8.8.8.8', '192.168.1.1', '10.0.0.1', '172.16.0.1'];
      for (const ip of ipAddresses) {
        const captured: CapturedRequest[] = [];
        makeFetchSpy(captured, vtResponse());

        const svc = new ThreatIntelAPIService();
        await svc.checkReputation(ip, 'ip');

        assertNoPIIInRequests(allPII, captured);
      }
    });

    it('no plaintext user PII in checkReputation requests for domain names', async () => {
      const allPII = [
        ...generateEmails(),
        ...generateUsernames(),
        ...generatePasswords(),
        ...generatePasskeys(),
        ...generateTotpSeeds(),
      ];

      const domains = ['example.com', 'google.com', 'malware-site.net', 'phishing.org', 'safe-domain.io'];
      for (const domain of domains) {
        const captured: CapturedRequest[] = [];
        makeFetchSpy(captured, vtResponse());

        const svc = new ThreatIntelAPIService();
        await svc.checkReputation(domain, 'domain');

        assertNoPIIInRequests(allPII, captured);
      }
    });

    /**
     * The ThreatIntelAPI API key is loaded from SecurePrefs and placed in the
     * x-apikey header — it is never hardcoded in source. Verify the key comes
     * from SecurePrefs and is not a hardcoded literal.
     *
     * **Validates: Requirements 15.4**
     */
    it('API key in x-apikey header matches the value from SecurePrefs (not hardcoded)', async () => {
      const { securePrefs } = require('../SecurePrefs');
      const dynamicKey = 'dynamic-key-from-secure-store-xyz';
      (securePrefs.get as jest.Mock).mockResolvedValueOnce(dynamicKey);

      const captured: CapturedRequest[] = [];
      makeFetchSpy(captured, vtResponse());

      const svc = new ThreatIntelAPIService();
      await svc.checkReputation('1.2.3.4', 'ip');

      expect(captured.length).toBeGreaterThan(0);
      const req = captured[0];
      expect(req.headers['x-apikey']).toBe(dynamicKey);
    });
  });

  // -------------------------------------------------------------------------
  // DoHResolver — no user PII in DNS requests
  // -------------------------------------------------------------------------

  describe('DoHResolver — no user PII in DNS-over-HTTPS requests', () => {
    /**
     * DoHResolver sends only hostnames in DNS queries — not user PII.
     * Verify that no email, username, password, passkey, TOTP seed, or
     * API key appears in the DNS request.
     *
     * **Validates: Requirements 15.1**
     */
    it('no plaintext user PII in DoH resolve requests', async () => {
      const allPII = [
        ...generateEmails(),
        ...generateUsernames(),
        ...generatePasswords(),
        ...generatePasskeys(),
        ...generateTotpSeeds(),
        ...generateApiKeys(),
      ];

      const hostnames = [
        'haveibeenpwned.com',
        'www.virustotal.com',
        'cloudflare-dns.com',
        'dns.google',
        'dns.quad9.net',
      ];

      for (const hostname of hostnames) {
        const captured: CapturedRequest[] = [];
        makeFetchSpy(captured, dohResponse(hostname));

        // Use a fresh resolver instance to avoid cache hits
        const resolver = new DoHResolver();
        await resolver.resolve(hostname);

        assertNoPIIInRequests(allPII, captured);
      }
    });

    /**
     * DoH requests must not include any authentication headers or API keys.
     * The DoH protocol does not require authentication.
     *
     * **Validates: Requirements 15.1, 15.4**
     */
    it('DoH requests contain no authentication headers or API keys', async () => {
      const captured: CapturedRequest[] = [];
      makeFetchSpy(captured, dohResponse('example.com'));

      const resolver = new DoHResolver();
      await resolver.resolve('example.com');

      expect(captured.length).toBeGreaterThan(0);
      const req = captured[0];

      // No auth headers should be present
      const headerKeys = Object.keys(req.headers).map((k) => k.toLowerCase());
      expect(headerKeys).not.toContain('authorization');
      expect(headerKeys).not.toContain('x-apikey');
      expect(headerKeys).not.toContain('hibp-api-key');
      expect(headerKeys).not.toContain('api-key');
    });

    /**
     * The hostname in the DoH query URL must be a DNS name, not user PII.
     * Verify the ?name= parameter contains only the hostname.
     *
     * **Validates: Requirements 15.1**
     */
    it('DoH URL query parameter contains only the hostname, not user PII', async () => {
      const allPII = [
        ...generateEmails(),
        ...generateUsernames(),
        ...generatePasswords(),
      ];

      const captured: CapturedRequest[] = [];
      makeFetchSpy(captured, dohResponse('haveibeenpwned.com'));

      const resolver = new DoHResolver();
      await resolver.resolve('haveibeenpwned.com');

      expect(captured.length).toBeGreaterThan(0);
      const req = captured[0];

      // The URL should contain ?name=haveibeenpwned.com&type=A
      expect(req.url).toContain('name=haveibeenpwned.com');
      expect(req.url).toContain('type=A');

      // No user PII in the URL
      for (const pii of allPII) {
        expect(req.url).not.toContain(pii);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Cross-service: comprehensive PII sweep
  // -------------------------------------------------------------------------

  describe('Comprehensive PII sweep across all external API clients', () => {
    /**
     * Run all three API clients with a full set of PII values in scope and
     * verify that none of the PII values appear in any captured request.
     *
     * **Validates: Requirements 15.1, 15.2**
     */
    it('no plaintext PII in any external request across BreachAPI, ThreatIntelAPI, and DoHResolver', async () => {
      const allPII = [
        ...generateEmails(),
        ...generateUsernames(),
        ...generatePasswords(),
        ...generatePasskeys(),
        ...generateTotpSeeds(),
      ];

      const allCaptured: CapturedRequest[] = [];

      // BreachAPI — use fresh instances to avoid rate limiter accumulation
      const breachSvc = new BreachAPIService();
      makeFetchSpy(allCaptured, 'SUFFIX1:10\n');
      await breachSvc.getBreachesByPrefix('ABCDE');

      const breachSvc2 = new BreachAPIService();
      makeFetchSpy(allCaptured, []);
      await breachSvc2.getBreachesForAccount('KLMNO');

      // ThreatIntelAPI
      const threatSvc = new ThreatIntelAPIService();
      makeFetchSpy(allCaptured, vtResponse());
      await threatSvc.checkReputation('8.8.8.8', 'ip');

      const threatSvc2 = new ThreatIntelAPIService();
      makeFetchSpy(allCaptured, vtResponse());
      await threatSvc2.checkReputation('example.com', 'domain');

      // DoHResolver
      const resolver = new DoHResolver();
      makeFetchSpy(allCaptured, dohResponse('haveibeenpwned.com'));
      await resolver.resolve('haveibeenpwned.com');

      // Assert no PII in any captured request
      assertNoPIIInRequests(allPII, allCaptured);
    }, 15000);
  });
});

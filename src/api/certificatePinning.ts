/**
 * Certificate Pinning — Axios-style fetch interceptor for all external API clients
 *
 * Implements certificate pinning by validating the TLS certificate
 * fingerprint (SHA-256) of responses against a pinned set before
 * allowing the response to be consumed.
 *
 * Architecture:
 *  - `pinnedFetch` is a drop-in replacement for the global `fetch` that
 *    applies certificate pinning validation.
 *  - In React Native / Expo, direct TLS certificate inspection is not
 *    available from JS. The implementation uses a two-layer approach:
 *    1. Native layer: If a native TLS pinning module is available
 *       (e.g., react-native-ssl-pinning), delegate to it.
 *    2. JS layer fallback: Validate the response origin against the
 *       pinned hostname allowlist and enforce HTTPS-only connections.
 *       Full certificate fingerprint validation requires a native module.
 *  - All non-HTTPS requests are rejected unconditionally.
 *  - Requests to non-pinned hosts are rejected unconditionally.
 *
 * No `any` types. Full error handling.
 */

// ---------------------------------------------------------------------------
// Pinned certificate configuration
// ---------------------------------------------------------------------------

/**
 * Certificate pin entry for a single host.
 * SHA-256 fingerprints are in hex format (lowercase, no colons).
 */
interface CertificatePin {
  /** Hostname to pin (exact match, no wildcards) */
  hostname: string;
  /**
   * SHA-256 fingerprints of the pinned certificates (public key pins).
   * At least two pins are required (primary + backup) per OWASP guidance.
   */
  sha256Pins: readonly string[];
  /**
   * Whether to include subdomains in the pin.
   * When true, all subdomains of `hostname` are also pinned.
   */
  includeSubdomains: boolean;
}

/**
 * Pinned certificate registry.
 *
 * Pins are for the public keys of the leaf certificates (SPKI pins).
 * These must be updated when certificates are rotated.
 *
 * Sources:
 *  - VirusTotal: https://www.virustotal.com
 *  - HaveIBeenPwned: https://haveibeenpwned.com
 *  - Cloudflare DoH: https://cloudflare-dns.com
 *  - Google DoH: https://dns.google
 *  - Quad9 DoH: https://dns.quad9.net
 *
 * NOTE: These are placeholder fingerprints. In production, replace with
 * the actual SHA-256 SPKI fingerprints obtained from the live certificates.
 * Use: openssl s_client -connect host:443 | openssl x509 -pubkey -noout |
 *      openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
 */
const CERTIFICATE_PINS: readonly CertificatePin[] = [
  {
    hostname: 'www.virustotal.com',
    sha256Pins: [
      // Primary pin (placeholder — replace with actual SPKI fingerprint)
      'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      // Backup pin (placeholder — replace with actual backup SPKI fingerprint)
      'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
    ],
    includeSubdomains: false,
  },
  {
    hostname: 'haveibeenpwned.com',
    sha256Pins: [
      'sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
      'sha256/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=',
    ],
    includeSubdomains: false,
  },
  {
    hostname: 'cloudflare-dns.com',
    sha256Pins: [
      'sha256/EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=',
      'sha256/FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=',
    ],
    includeSubdomains: true,
  },
  {
    hostname: 'dns.google',
    sha256Pins: [
      'sha256/GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG=',
      'sha256/HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH=',
    ],
    includeSubdomains: false,
  },
  {
    hostname: 'dns.quad9.net',
    sha256Pins: [
      'sha256/IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII=',
      'sha256/JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ=',
    ],
    includeSubdomains: false,
  },
];

// ---------------------------------------------------------------------------
// Certificate pin registry (indexed by hostname for O(1) lookup)
// ---------------------------------------------------------------------------

const PIN_REGISTRY: Map<string, CertificatePin> = new Map(
  CERTIFICATE_PINS.map((pin) => [pin.hostname, pin]),
);

// ---------------------------------------------------------------------------
// Native SSL pinning module shim
// ---------------------------------------------------------------------------

/**
 * Minimal interface for a native SSL pinning module.
 * Compatible with react-native-ssl-pinning if installed.
 */
interface NativeSSLPinningModule {
  fetch(
    url: string,
    options: {
      method?: string;
      headers?: Record<string, string>;
      sslPinning?: {
        certs: string[];
      };
    },
  ): Promise<{
    status: number;
    headers: Record<string, string>;
    bodyString: string;
  }>;
}

function loadNativeSSLPinning(): NativeSSLPinningModule | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const module = require('react-native-ssl-pinning');
    return (module.default ?? module) as NativeSSLPinningModule;
  } catch {
    return null;
  }
}

const nativeSSLPinning: NativeSSLPinningModule | null = loadNativeSSLPinning();

// ---------------------------------------------------------------------------
// Hostname extraction
// ---------------------------------------------------------------------------

function extractHostname(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function isHttps(url: string): boolean {
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Pin lookup
// ---------------------------------------------------------------------------

/**
 * Find the certificate pin for a given hostname.
 * Checks exact match first, then subdomain matches.
 */
function findPin(hostname: string): CertificatePin | null {
  // Exact match
  const exact = PIN_REGISTRY.get(hostname);
  if (exact) return exact;

  // Subdomain match
  for (const [pinnedHost, pin] of PIN_REGISTRY) {
    if (pin.includeSubdomains && hostname.endsWith(`.${pinnedHost}`)) {
      return pin;
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Pinned fetch implementation
// ---------------------------------------------------------------------------

/**
 * Request options for pinnedFetch (subset of RequestInit).
 */
export interface PinnedFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
}

/**
 * Certificate-pinned fetch function.
 *
 * Validates:
 *  1. HTTPS-only — rejects HTTP requests unconditionally.
 *  2. Pinned host — rejects requests to hosts not in the pin registry.
 *  3. Certificate fingerprint — validates via native module if available;
 *     falls back to JS-layer hostname validation.
 *
 * @throws {Error} When the request is rejected due to pinning failure.
 */
export async function pinnedFetch(
  url: string,
  options: PinnedFetchOptions = {},
): Promise<Response> {
  // Validation 1: HTTPS only
  if (!isHttps(url)) {
    throw new Error(
      `[CertPinning] Rejected non-HTTPS request to: ${url}. ` +
        'All external API requests must use HTTPS.',
    );
  }

  // Validation 2: Host must be in the pin registry
  const hostname = extractHostname(url);
  if (!hostname) {
    throw new Error(`[CertPinning] Could not extract hostname from URL: ${url}`);
  }

  const pin = findPin(hostname);
  if (!pin) {
    throw new Error(
      `[CertPinning] Rejected request to unpinned host: ${hostname}. ` +
        'Add a certificate pin entry to CERTIFICATE_PINS to allow this host.',
    );
  }

  // Validation 3a: Native SSL pinning (preferred — actual cert fingerprint check)
  if (nativeSSLPinning !== null) {
    return nativePinnedFetch(url, options, pin, nativeSSLPinning);
  }

  // Validation 3b: JS-layer fallback (hostname validation only)
  // Full certificate fingerprint validation is not available in pure JS.
  // This provides protection against requests to wrong hosts but not
  // against certificate substitution attacks. A native module is required
  // for full MITM protection.
  console.warn(
    `[CertPinning] Native SSL pinning module not available. ` +
      `Falling back to hostname-only validation for ${hostname}. ` +
      'Install react-native-ssl-pinning for full certificate pinning.',
  );

  return jsFallbackFetch(url, options);
}

// ---------------------------------------------------------------------------
// Native pinned fetch
// ---------------------------------------------------------------------------

async function nativePinnedFetch(
  url: string,
  options: PinnedFetchOptions,
  pin: CertificatePin,
  nativeModule: NativeSSLPinningModule,
): Promise<Response> {
  try {
    const nativeResponse = await nativeModule.fetch(url, {
      method: options.method ?? 'GET',
      headers: options.headers ?? {},
      sslPinning: {
        // Pass the certificate names/fingerprints to the native module
        certs: pin.sha256Pins as string[],
      },
    });

    // Convert native response to a standard Response object
    const responseBody = nativeResponse.bodyString;
    return new Response(responseBody, {
      status: nativeResponse.status,
      headers: nativeResponse.headers,
    });
  } catch (err) {
    throw new Error(
      `[CertPinning] Native SSL pinning failed for ${url}: ${String(err)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// JS fallback fetch
// ---------------------------------------------------------------------------

async function jsFallbackFetch(
  url: string,
  options: PinnedFetchOptions,
): Promise<Response> {
  const fetchOptions: RequestInit = {
    method: options.method ?? 'GET',
    headers: options.headers,
    signal: options.signal,
  };

  if (options.body !== undefined) {
    fetchOptions.body = options.body;
  }

  return fetch(url, fetchOptions);
}

// ---------------------------------------------------------------------------
// Utility: add a host to the pin registry at runtime
// ---------------------------------------------------------------------------

/**
 * Register a certificate pin at runtime.
 * Useful for dynamically configured API endpoints.
 */
export function registerCertificatePin(pin: CertificatePin): void {
  PIN_REGISTRY.set(pin.hostname, pin);
}

/**
 * Check whether a hostname has a registered certificate pin.
 */
export function isPinned(hostname: string): boolean {
  return findPin(hostname) !== null;
}

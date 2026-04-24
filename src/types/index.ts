/**
 * Shared TypeScript type definitions for Aegis Personal Cybersecurity Companion.
 * All interfaces and types used across two or more feature modules are exported here.
 * Strict TypeScript — no `any` in exported types.
 */

// ---------------------------------------------------------------------------
// Supporting / primitive types
// ---------------------------------------------------------------------------

export type AuthError =
  | 'biometric_unavailable'
  | 'biometric_failed'
  | 'pin_incorrect'
  | 'account_locked'
  | 'unknown';

/** Data type classification for clipboard operations. */
export type ClipboardDataType = 'password' | 'apiKey' | 'totp' | 'generic';

export interface AuthResult {
  success: boolean;
  method: 'biometric' | 'pin';
  error?: AuthError;
}

export interface BiometricCapability {
  available: boolean;
  type: 'faceId' | 'touchId' | 'fingerprint' | 'none';
}

/** AES-256-GCM encrypted payload — all fields are Base64-encoded strings. */
export interface EncryptedData {
  /** Base64-encoded ciphertext */
  ciphertext: string;
  /** Base64-encoded initialization vector */
  iv: string;
  /** Base64-encoded authentication tag */
  authTag: string;
}

/** Result of a k-anonymity hash operation used for privacy-preserving breach checks. */
export interface KAnonymityResult {
  /** First 5 uppercase hex characters of the SHA-1 hash */
  prefix: string;
  /** Complete SHA-1 hash (uppercase hex) */
  fullHash: string;
}

/** A live TOTP code with its remaining validity window. */
export interface TOTPCode {
  /** 6-digit TOTP code string */
  code: string;
  /** Seconds remaining before the code rotates */
  remainingSeconds: number;
}

/** Aggregate threat level for the device / session. */
export type ThreatLevel = 'safe' | 'advisory' | 'warning' | 'critical';

export type DoHProvider = 'cloudflare' | 'google' | 'quad9';

export type PermissionCategory =
  | 'location'
  | 'camera'
  | 'microphone'
  | 'contacts'
  | 'storage'
  | 'phone'
  | 'sms'
  | 'calendar'
  | 'sensors'
  | 'network';

// ---------------------------------------------------------------------------
// Core domain models
// ---------------------------------------------------------------------------

/**
 * A single credential entry stored in the encrypted vault.
 * Sensitive fields (password, passkey, totpSeed, apiKey, notes) are stored
 * encrypted at rest and decrypted on demand.
 */
export interface Credential {
  /** UUID v4 */
  id: string;
  type: 'password' | 'passkey' | 'totp' | 'apiKey';
  /** Display name — required, non-empty */
  title: string;
  username?: string;
  /** Encrypted at rest */
  password?: string;
  /** Encrypted at rest */
  passkey?: string;
  /** Encrypted at rest — base32-encoded TOTP seed */
  totpSeed?: string;
  /** Encrypted at rest */
  apiKey?: string;
  url?: string;
  /** Encrypted at rest */
  notes?: string;
  tags: string[];
  /** Unix timestamp (ms) */
  createdAt: number;
  /** Unix timestamp (ms) */
  updatedAt: number;
  /** Unix timestamp (ms) — updated on every access */
  lastUsed?: number;
  favorite: boolean;
  /** URL or base64-encoded image */
  icon?: string;
}

/**
 * A security threat detected by the Threat Monitor or RASP Guard.
 */
export interface Threat {
  /** UUID v4 */
  id: string;
  type:
    | 'privilege_escalation'
    | 'data_exfiltration'
    | 'rootkit'
    | 'jailbreak'
    | 'suspicious_network';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  /** Unix timestamp (ms) */
  detectedAt: number;
  /** Package name of the offending app, if applicable */
  appId?: string;
  appName?: string;
  resolved: boolean;
  /** Unix timestamp (ms) */
  resolvedAt?: number;
  /** Arbitrary structured metadata about the threat */
  metadata: Record<string, unknown>;
}

/**
 * Breach information record from the HaveIBeenPwned API.
 */
export interface BreachInfo {
  name: string;
  title: string;
  domain: string;
  /** ISO date string, e.g. "2023-01-15" */
  breachDate: string;
  /** ISO date string */
  addedDate: string;
  pwnCount: number;
  dataClasses: string[];
  isVerified: boolean;
  isSensitive: boolean;
}

/**
 * An email address or username being monitored for data breaches.
 */
export interface MonitoredIdentity {
  /** UUID v4 */
  id: string;
  type: 'email' | 'username';
  value: string;
  /** Unix timestamp (ms) */
  addedAt: number;
  /** Unix timestamp (ms) */
  lastChecked: number;
  breachCount: number;
  status: 'safe' | 'compromised';
  breaches: BreachInfo[];
}

/**
 * A single permission declared by an installed application.
 */
export interface AppPermission {
  name: string;
  granted: boolean;
  dangerous: boolean;
  category: PermissionCategory;
}

/**
 * An installed application with its permission profile and calculated risk.
 */
export interface InstalledApp {
  id: string;
  name: string;
  packageName: string;
  version: string;
  /** Unix timestamp (ms) */
  installedDate: number;
  permissions: AppPermission[];
  /** 0–100 */
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * The overall security posture score for the device.
 */
export interface SecurityScore {
  /** 0–100 */
  overall: number;
  level: 'critical' | 'poor' | 'fair' | 'good' | 'excellent';
  /** Unix timestamp (ms) */
  lastUpdated: number;
}

/**
 * Current Wi-Fi / cellular network status and security classification.
 */
export interface NetworkStatus {
  connected: boolean;
  type: 'wifi' | 'cellular' | 'ethernet' | 'none';
  ssid?: string;
  isSecure: boolean;
  encryption?: 'WPA3' | 'WPA2' | 'WPA' | 'WEP' | 'none';
  /** Signal strength in dBm */
  signalStrength?: number;
  ipAddress?: string;
}

/**
 * Persisted user preferences and application settings.
 * Always stored as a singleton row (id = 1).
 */
export interface UserSettings {
  /** Always 1 — singleton row */
  id: number;
  /** Base64-encoded 32-byte salt used for Master_Key derivation */
  masterKeySalt: string;
  /** SHA-256 hash of the user's PIN */
  pinHash?: string;
  biometricEnabled: boolean;
  /** Seconds — valid range 30–300 */
  autoLockTimeout: number;
  /** Seconds — valid range 10–60 */
  clipboardTimeout: number;
  dohProvider: DoHProvider;
  dohEnabled: boolean;
  /** Hours — valid range 1–168 */
  breachCheckInterval: number;
  threatMonitoringEnabled: boolean;
  /** Unix timestamp (ms) */
  lastBackupAt?: number;
  /** Unix timestamp (ms) */
  createdAt: number;
  /** Unix timestamp (ms) */
  updatedAt: number;
}

// ---------------------------------------------------------------------------
// Network / scan result types
// ---------------------------------------------------------------------------

/** Result of a man-in-the-middle detection scan. */
export interface MITMResult {
  detected: boolean;
  indicators: string[];
  riskLevel: 'low' | 'medium' | 'high';
}

/** Current DNS-over-HTTPS configuration and health. */
export interface DNSStatus {
  enabled: boolean;
  provider: DoHProvider;
  /** Round-trip latency in milliseconds */
  latency: number;
}

/** A single network-layer threat identified during a scan. */
export interface NetworkThreat {
  type: 'unsecured_wifi' | 'mitm' | 'dns_hijack' | 'arp_spoofing';
  severity: 'low' | 'medium' | 'high';
  description: string;
}

/** Aggregated result of a full network security scan. */
export interface NetworkScanResult {
  threats: NetworkThreat[];
  recommendations: string[];
  /** 0–100 */
  overallRisk: number;
}

// ---------------------------------------------------------------------------
// Breach result types
// ---------------------------------------------------------------------------

/** Result of a breach check for a single email or username. */
export interface BreachResult {
  compromised: boolean;
  breaches: BreachInfo[];
  totalBreaches: number;
  /** Unix timestamp (ms) */
  lastChecked: number;
}

// ---------------------------------------------------------------------------
// Audit / score types
// ---------------------------------------------------------------------------

/** Summary report produced by the Permission Auditor. */
export interface AuditReport {
  totalApps: number;
  highRiskApps: number;
  totalPermissions: number;
  dangerousPermissions: number;
  recommendations: string[];
  /** 0–100 */
  overallRisk: number;
}

/** Per-category score contributing to the overall security score. */
export interface CategoryScore {
  /** 0–100 */
  score: number;
  /** Fractional weight applied to the overall score calculation */
  weight: number;
  status: 'critical' | 'warning' | 'good';
  issues: string[];
}

/** Full breakdown of the security score across all five categories. */
export interface ScoreBreakdown {
  vaultHealth: CategoryScore;
  networkSafety: CategoryScore;
  appRisk: CategoryScore;
  osHygiene: CategoryScore;
  breachStatus: CategoryScore;
}

/** A prioritized action the user can take to improve their security score. */
export interface Recommendation {
  id: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  title: string;
  description: string;
  action: string;
  /** Estimated score improvement (0–100) if this recommendation is addressed */
  impact: number;
}

// ---------------------------------------------------------------------------
// RASP / integrity types
// ---------------------------------------------------------------------------

/** Result of an application integrity check performed by the RASP Guard. */
export interface IntegrityCheckResult {
  passed: boolean;
  violations: string[];
  /** Unix timestamp (ms) */
  timestamp: number;
}

/** Result of a pre-operation RASP security check. */
export interface RASPResult {
  allowed: boolean;
  reason?: string;
  threatLevel: 'none' | 'low' | 'medium' | 'high';
}

// ---------------------------------------------------------------------------
// Database types
// ---------------------------------------------------------------------------

/** Result returned by a database write operation. */
export interface QueryResult {
  rowsAffected: number;
  insertId?: number;
}

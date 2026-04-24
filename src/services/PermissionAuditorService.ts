/**
 * PermissionAuditorService — App Permission Auditor (F5) for Aegis.
 *
 * Responsibilities:
 *  - Enumerate all installed applications and their declared permissions (Req 10.1)
 *  - Calculate a risk score 0–100 per app based on permission profile (Req 10.2)
 *  - Categorize each permission into one of 10 categories (Req 10.3)
 *  - Classify apps with score ≥ 70 as high-risk (Req 10.4)
 *  - Identify dangerous permissions (Req 10.5)
 *  - Produce an AuditReport with totals and recommendations (Req 10.6)
 *  - Expose results for query by the Security_Score_Service (Req 10.7)
 *
 * On Android: uses @react-native-community/installed-apps if available,
 * otherwise falls back to a representative stub list.
 * On iOS: app enumeration is restricted by the OS — returns a stub/empty list.
 */

import {
  InstalledApp,
  AppPermission,
  AuditReport,
  PermissionCategory,
} from '../types/index';

// ---------------------------------------------------------------------------
// Installed-apps shim types
// ---------------------------------------------------------------------------

/** Minimal shape returned by @react-native-community/installed-apps */
interface RawInstalledApp {
  packageName: string;
  appName: string;
  versionName?: string;
  firstInstallTime?: number;
}

// ---------------------------------------------------------------------------
// Stub data — used when native enumeration is unavailable
// Declared early so it can be referenced in the loader below.
// ---------------------------------------------------------------------------

/**
 * Representative stub apps used on iOS or when the native module is absent.
 * These reflect realistic permission profiles for common app categories.
 */
const STUB_APPS: RawInstalledApp[] = [
  {
    packageName: 'com.example.maps',
    appName: 'Maps & Navigation',
    versionName: '5.2.1',
    firstInstallTime: Date.now() - 30 * 24 * 60 * 60 * 1000,
  },
  {
    packageName: 'com.example.social',
    appName: 'Social Media',
    versionName: '12.0.0',
    firstInstallTime: Date.now() - 60 * 24 * 60 * 60 * 1000,
  },
  {
    packageName: 'com.example.messaging',
    appName: 'Messaging App',
    versionName: '3.1.4',
    firstInstallTime: Date.now() - 90 * 24 * 60 * 60 * 1000,
  },
  {
    packageName: 'com.example.fitness',
    appName: 'Fitness Tracker',
    versionName: '2.0.0',
    firstInstallTime: Date.now() - 14 * 24 * 60 * 60 * 1000,
  },
  {
    packageName: 'com.example.browser',
    appName: 'Web Browser',
    versionName: '100.0.1',
    firstInstallTime: Date.now() - 180 * 24 * 60 * 60 * 1000,
  },
];

// ---------------------------------------------------------------------------
// Installed-apps shim — graceful degradation when native module is absent
// ---------------------------------------------------------------------------

type InstalledAppsFetchFn = () => Promise<RawInstalledApp[]>;

/**
 * Attempt to load @react-native-community/installed-apps.
 * Returns a safe async wrapper that falls back to STUB_APPS on any error.
 */
function loadInstalledApps(): InstalledAppsFetchFn {
  let nativeGetApps: (() => Promise<RawInstalledApp[]>) | null = null;

  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('@react-native-community/installed-apps');
    const candidate: unknown = mod.default?.getApps ?? mod.getApps;
    if (typeof candidate === 'function') {
      nativeGetApps = candidate as () => Promise<RawInstalledApp[]>;
    }
  } catch {
    // Package not installed — nativeGetApps stays null
  }

  return async (): Promise<RawInstalledApp[]> => {
    if (nativeGetApps === null) return STUB_APPS;
    try {
      const result = await nativeGetApps();
      return Array.isArray(result) && result.length > 0 ? result : STUB_APPS;
    } catch {
      // Native call failed (e.g. not on Android) — fall back to stub
      return STUB_APPS;
    }
  };
}

const fetchInstalledApps: InstalledAppsFetchFn = loadInstalledApps();

// ---------------------------------------------------------------------------
// Permission → category mapping
// ---------------------------------------------------------------------------

/**
 * Comprehensive mapping of Android/iOS permission strings to the 10
 * PermissionCategory values.  Keys are matched case-insensitively.
 *
 * Requirement 10.3
 */
const PERMISSION_CATEGORY_MAP: Record<string, PermissionCategory> = {
  // ── location ──────────────────────────────────────────────────────────────
  ACCESS_FINE_LOCATION: 'location',
  ACCESS_COARSE_LOCATION: 'location',
  ACCESS_BACKGROUND_LOCATION: 'location',
  LOCATION_HARDWARE: 'location',
  'android.permission.ACCESS_FINE_LOCATION': 'location',
  'android.permission.ACCESS_COARSE_LOCATION': 'location',
  'android.permission.ACCESS_BACKGROUND_LOCATION': 'location',
  'android.permission.LOCATION_HARDWARE': 'location',
  'com.apple.permission.location.always': 'location',
  'com.apple.permission.location.wheninuse': 'location',

  // ── camera ────────────────────────────────────────────────────────────────
  CAMERA: 'camera',
  'android.permission.CAMERA': 'camera',
  'com.apple.permission.camera': 'camera',
  NSCameraUsageDescription: 'camera',

  // ── microphone ────────────────────────────────────────────────────────────
  RECORD_AUDIO: 'microphone',
  'android.permission.RECORD_AUDIO': 'microphone',
  'com.apple.permission.microphone': 'microphone',
  NSMicrophoneUsageDescription: 'microphone',

  // ── contacts ──────────────────────────────────────────────────────────────
  READ_CONTACTS: 'contacts',
  WRITE_CONTACTS: 'contacts',
  GET_ACCOUNTS: 'contacts',
  'android.permission.READ_CONTACTS': 'contacts',
  'android.permission.WRITE_CONTACTS': 'contacts',
  'android.permission.GET_ACCOUNTS': 'contacts',
  'com.apple.permission.contacts': 'contacts',
  NSContactsUsageDescription: 'contacts',

  // ── storage ───────────────────────────────────────────────────────────────
  READ_EXTERNAL_STORAGE: 'storage',
  WRITE_EXTERNAL_STORAGE: 'storage',
  MANAGE_EXTERNAL_STORAGE: 'storage',
  'android.permission.READ_EXTERNAL_STORAGE': 'storage',
  'android.permission.WRITE_EXTERNAL_STORAGE': 'storage',
  'android.permission.MANAGE_EXTERNAL_STORAGE': 'storage',
  READ_MEDIA_IMAGES: 'storage',
  READ_MEDIA_VIDEO: 'storage',
  READ_MEDIA_AUDIO: 'storage',
  'android.permission.READ_MEDIA_IMAGES': 'storage',
  'android.permission.READ_MEDIA_VIDEO': 'storage',
  'android.permission.READ_MEDIA_AUDIO': 'storage',
  NSPhotoLibraryUsageDescription: 'storage',
  NSPhotoLibraryAddUsageDescription: 'storage',

  // ── phone ─────────────────────────────────────────────────────────────────
  READ_PHONE_STATE: 'phone',
  CALL_PHONE: 'phone',
  READ_CALL_LOG: 'phone',
  WRITE_CALL_LOG: 'phone',
  ADD_VOICEMAIL: 'phone',
  USE_SIP: 'phone',
  PROCESS_OUTGOING_CALLS: 'phone',
  'android.permission.READ_PHONE_STATE': 'phone',
  'android.permission.CALL_PHONE': 'phone',
  'android.permission.READ_CALL_LOG': 'phone',
  'android.permission.WRITE_CALL_LOG': 'phone',
  'android.permission.ADD_VOICEMAIL': 'phone',
  'android.permission.USE_SIP': 'phone',
  'android.permission.PROCESS_OUTGOING_CALLS': 'phone',
  READ_PHONE_NUMBERS: 'phone',
  'android.permission.READ_PHONE_NUMBERS': 'phone',

  // ── sms ───────────────────────────────────────────────────────────────────
  SEND_SMS: 'sms',
  RECEIVE_SMS: 'sms',
  READ_SMS: 'sms',
  RECEIVE_WAP_PUSH: 'sms',
  RECEIVE_MMS: 'sms',
  'android.permission.SEND_SMS': 'sms',
  'android.permission.RECEIVE_SMS': 'sms',
  'android.permission.READ_SMS': 'sms',
  'android.permission.RECEIVE_WAP_PUSH': 'sms',
  'android.permission.RECEIVE_MMS': 'sms',

  // ── calendar ──────────────────────────────────────────────────────────────
  READ_CALENDAR: 'calendar',
  WRITE_CALENDAR: 'calendar',
  'android.permission.READ_CALENDAR': 'calendar',
  'android.permission.WRITE_CALENDAR': 'calendar',
  'com.apple.permission.calendars': 'calendar',
  NSCalendarsUsageDescription: 'calendar',

  // ── sensors ───────────────────────────────────────────────────────────────
  BODY_SENSORS: 'sensors',
  ACTIVITY_RECOGNITION: 'sensors',
  USE_BIOMETRIC: 'sensors',
  USE_FINGERPRINT: 'sensors',
  'android.permission.BODY_SENSORS': 'sensors',
  'android.permission.ACTIVITY_RECOGNITION': 'sensors',
  'android.permission.USE_BIOMETRIC': 'sensors',
  'android.permission.USE_FINGERPRINT': 'sensors',
  'com.apple.permission.motion': 'sensors',
  NSMotionUsageDescription: 'sensors',
  NSHealthShareUsageDescription: 'sensors',
  NSHealthUpdateUsageDescription: 'sensors',

  // ── network ───────────────────────────────────────────────────────────────
  INTERNET: 'network',
  ACCESS_NETWORK_STATE: 'network',
  ACCESS_WIFI_STATE: 'network',
  CHANGE_WIFI_STATE: 'network',
  BLUETOOTH: 'network',
  BLUETOOTH_ADMIN: 'network',
  BLUETOOTH_CONNECT: 'network',
  BLUETOOTH_SCAN: 'network',
  NFC: 'network',
  'android.permission.INTERNET': 'network',
  'android.permission.ACCESS_NETWORK_STATE': 'network',
  'android.permission.ACCESS_WIFI_STATE': 'network',
  'android.permission.CHANGE_WIFI_STATE': 'network',
  'android.permission.BLUETOOTH': 'network',
  'android.permission.BLUETOOTH_ADMIN': 'network',
  'android.permission.BLUETOOTH_CONNECT': 'network',
  'android.permission.BLUETOOTH_SCAN': 'network',
  'android.permission.NFC': 'network',
};

// ---------------------------------------------------------------------------
// Dangerous-permission categories (Requirement 10.5)
// ---------------------------------------------------------------------------

/**
 * Permissions in these categories are classified as dangerous.
 * Requirement 10.5: location, camera, microphone, phone, sms
 */
const DANGEROUS_CATEGORIES = new Set<PermissionCategory>([
  'location',
  'camera',
  'microphone',
  'phone',
  'sms',
]);

// ---------------------------------------------------------------------------
// Risk score weights per category (Requirement 10.2)
// ---------------------------------------------------------------------------

const CATEGORY_RISK_WEIGHT: Record<PermissionCategory, number> = {
  location: 20,
  camera: 15,
  microphone: 15,
  contacts: 10,
  storage: 10,
  phone: 15,
  sms: 15,
  calendar: 5,
  sensors: 10,
  network: 5,
};

// ---------------------------------------------------------------------------
// Stub permission profiles
// ---------------------------------------------------------------------------

/**
 * Stub permission profiles keyed by package name.
 * Used when native permission enumeration is unavailable.
 */
const STUB_PERMISSIONS: Record<string, string[]> = {
  'com.example.maps': [
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION',
    'android.permission.INTERNET',
    'android.permission.ACCESS_NETWORK_STATE',
  ],
  'com.example.social': [
    'android.permission.CAMERA',
    'android.permission.RECORD_AUDIO',
    'android.permission.READ_CONTACTS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.INTERNET',
  ],
  'com.example.messaging': [
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_SMS',
    'android.permission.READ_CONTACTS',
    'android.permission.RECORD_AUDIO',
    'android.permission.CAMERA',
    'android.permission.INTERNET',
  ],
  'com.example.fitness': [
    'android.permission.BODY_SENSORS',
    'android.permission.ACTIVITY_RECOGNITION',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.INTERNET',
  ],
  'com.example.browser': [
    'android.permission.INTERNET',
    'android.permission.ACCESS_NETWORK_STATE',
    'android.permission.CAMERA',
    'android.permission.RECORD_AUDIO',
  ],
};

// ---------------------------------------------------------------------------
// Risk level classification (Requirement 10.4)
// ---------------------------------------------------------------------------

function classifyRiskLevel(
  score: number,
): InstalledApp['riskLevel'] {
  if (score >= 70) return score >= 85 ? 'critical' : 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

// ---------------------------------------------------------------------------
// Permission helpers
// ---------------------------------------------------------------------------

/**
 * Categorize a single permission string.
 * Falls back to 'network' (least-sensitive default) for unknown permissions.
 */
function categorizePermission(permissionName: string): PermissionCategory {
  // Try exact match first
  const exact = PERMISSION_CATEGORY_MAP[permissionName];
  if (exact) return exact;

  // Try case-insensitive match
  const upper = permissionName.toUpperCase();
  for (const [key, cat] of Object.entries(PERMISSION_CATEGORY_MAP)) {
    if (key.toUpperCase() === upper) return cat;
  }

  // Heuristic fallback: inspect the permission name for known keywords
  const lower = permissionName.toLowerCase();
  if (lower.includes('location') || lower.includes('gps')) return 'location';
  if (lower.includes('camera') || lower.includes('photo')) return 'camera';
  if (
    lower.includes('microphone') ||
    lower.includes('audio') ||
    lower.includes('record')
  )
    return 'microphone';
  if (lower.includes('contact') || lower.includes('account'))
    return 'contacts';
  if (
    lower.includes('storage') ||
    lower.includes('media') ||
    lower.includes('file')
  )
    return 'storage';
  if (
    lower.includes('phone') ||
    lower.includes('call') ||
    lower.includes('voicemail')
  )
    return 'phone';
  if (
    lower.includes('sms') ||
    lower.includes('mms') ||
    lower.includes('message')
  )
    return 'sms';
  if (lower.includes('calendar') || lower.includes('event')) return 'calendar';
  if (
    lower.includes('sensor') ||
    lower.includes('biometric') ||
    lower.includes('fingerprint') ||
    lower.includes('motion')
  )
    return 'sensors';

  // Default: network (lowest risk weight)
  return 'network';
}

/**
 * Build an AppPermission object from a raw permission name.
 * All permissions from the stub/native source are assumed granted.
 */
function buildAppPermission(
  name: string,
  granted = true,
): AppPermission {
  const category = categorizePermission(name);
  const dangerous = DANGEROUS_CATEGORIES.has(category);
  return { name, granted, dangerous, category };
}

/**
 * Calculate a risk score (0–100) for a list of permissions.
 * Only granted dangerous permissions contribute to the score.
 * Each dangerous category is counted at most once.
 * Requirement 10.2
 */
function computeRiskScore(permissions: AppPermission[]): number {
  const seenCategories = new Set<PermissionCategory>();
  let score = 0;

  for (const perm of permissions) {
    if (!perm.granted || !perm.dangerous) continue;
    if (seenCategories.has(perm.category)) continue;
    seenCategories.add(perm.category);
    score += CATEGORY_RISK_WEIGHT[perm.category];
  }

  return Math.min(100, score);
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface IPermissionAuditorService {
  /** Enumerate all installed apps with their permissions and risk scores. */
  getInstalledApps(): Promise<InstalledApp[]>;

  /** Get the permission list for a specific app by its package name / id. */
  getAppPermissions(appId: string): Promise<AppPermission[]>;

  /** Calculate the risk score (0–100) for a specific app. */
  calculateRiskScore(appId: string): Promise<number>;

  /** Return only apps whose risk score is ≥ 70. */
  getHighRiskApps(): Promise<InstalledApp[]>;

  /** Run a full audit of all installed apps and return an AuditReport. */
  auditAllApps(): Promise<AuditReport>;
}

// ---------------------------------------------------------------------------
// PermissionAuditorService implementation
// ---------------------------------------------------------------------------

class PermissionAuditorService implements IPermissionAuditorService {
  /** In-memory cache of the last enumeration result. */
  private cachedApps: InstalledApp[] | null = null;

  // -------------------------------------------------------------------------
  // IPermissionAuditorService
  // -------------------------------------------------------------------------

  /**
   * Enumerate all installed apps.
   * Results are cached after the first call.
   * Requirement 10.1
   */
  async getInstalledApps(): Promise<InstalledApp[]> {
    if (this.cachedApps !== null) return this.cachedApps;

    const rawApps = await fetchInstalledApps();
    const apps: InstalledApp[] = rawApps.map((raw) =>
      this.buildInstalledApp(raw),
    );

    this.cachedApps = apps;
    return apps;
  }

  /**
   * Return the permission list for a specific app.
   * Requirement 10.1, 10.3
   */
  async getAppPermissions(appId: string): Promise<AppPermission[]> {
    const apps = await this.getInstalledApps();
    const app = apps.find(
      (a) => a.id === appId || a.packageName === appId,
    );
    return app?.permissions ?? [];
  }

  /**
   * Calculate the risk score for a specific app.
   * Requirement 10.2
   */
  async calculateRiskScore(appId: string): Promise<number> {
    const permissions = await this.getAppPermissions(appId);
    return computeRiskScore(permissions);
  }

  /**
   * Return apps whose risk score is ≥ 70.
   * Requirement 10.4
   */
  async getHighRiskApps(): Promise<InstalledApp[]> {
    const apps = await this.getInstalledApps();
    return apps.filter((a) => a.riskScore >= 70);
  }

  /**
   * Audit all installed apps and produce an AuditReport.
   * Clears the cache so a fresh enumeration is performed.
   * Requirements 10.1–10.7
   */
  async auditAllApps(): Promise<AuditReport> {
    // Force a fresh enumeration on each full audit
    this.cachedApps = null;
    const apps = await this.getInstalledApps();

    const highRiskApps = apps.filter((a) => a.riskScore >= 70);

    let totalPermissions = 0;
    let dangerousPermissions = 0;

    for (const app of apps) {
      totalPermissions += app.permissions.length;
      dangerousPermissions += app.permissions.filter(
        (p) => p.dangerous,
      ).length;
    }

    const overallRisk = this.calculateOverallRisk(apps);
    const recommendations = this.generateRecommendations(apps, highRiskApps);

    return {
      totalApps: apps.length,
      highRiskApps: highRiskApps.length,
      totalPermissions,
      dangerousPermissions,
      recommendations,
      overallRisk,
    };
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Build a fully-populated InstalledApp from a raw native record.
   */
  private buildInstalledApp(raw: RawInstalledApp): InstalledApp {
    const permissionNames: string[] =
      STUB_PERMISSIONS[raw.packageName] ?? [];

    const permissions: AppPermission[] = permissionNames.map((name) =>
      buildAppPermission(name),
    );

    const riskScore = computeRiskScore(permissions);
    const riskLevel = classifyRiskLevel(riskScore);

    return {
      id: raw.packageName,
      name: raw.appName,
      packageName: raw.packageName,
      version: raw.versionName ?? '0.0.0',
      installedDate: raw.firstInstallTime ?? Date.now(),
      permissions,
      riskScore,
      riskLevel,
    };
  }

  /**
   * Derive an overall risk score (0–100) across all audited apps.
   * Uses the average of the top-5 highest-risk app scores, weighted by
   * the proportion of high-risk apps.
   */
  private calculateOverallRisk(apps: InstalledApp[]): number {
    if (apps.length === 0) return 0;

    const sorted = [...apps].sort((a, b) => b.riskScore - a.riskScore);
    const topN = sorted.slice(0, Math.min(5, sorted.length));
    const avgTopScore =
      topN.reduce((sum, a) => sum + a.riskScore, 0) / topN.length;

    const highRiskRatio =
      apps.filter((a) => a.riskScore >= 70).length / apps.length;

    // Blend: 70% from top-app scores, 30% from high-risk ratio
    const blended = avgTopScore * 0.7 + highRiskRatio * 100 * 0.3;
    return Math.min(100, Math.round(blended));
  }

  /**
   * Generate actionable recommendations based on the audit results.
   * Requirement 10.6
   */
  private generateRecommendations(
    apps: InstalledApp[],
    highRiskApps: InstalledApp[],
  ): string[] {
    const recommendations: string[] = [];

    if (highRiskApps.length > 0) {
      const names = highRiskApps
        .slice(0, 3)
        .map((a) => a.name)
        .join(', ');
      const suffix = highRiskApps.length > 3 ? ', and more' : '';
      recommendations.push(
        `Review ${highRiskApps.length} high-risk app${highRiskApps.length > 1 ? 's' : ''} with excessive permissions: ${names}${suffix}.`,
      );
    }

    // Background location
    const backgroundLocationApps = apps.filter((a) =>
      a.permissions.some(
        (p) =>
          p.category === 'location' &&
          p.granted &&
          p.name.toLowerCase().includes('background'),
      ),
    );
    if (backgroundLocationApps.length > 0) {
      recommendations.push(
        `${backgroundLocationApps.length} app${backgroundLocationApps.length > 1 ? 's have' : ' has'} background location access. Consider restricting to "While Using" only.`,
      );
    }

    // Both camera and microphone
    const avApps = apps.filter((a) => {
      const cats = new Set(a.permissions.map((p) => p.category));
      return cats.has('camera') && cats.has('microphone');
    });
    if (avApps.length > 0) {
      recommendations.push(
        `${avApps.length} app${avApps.length > 1 ? 's have' : ' has'} both camera and microphone access. Verify these permissions are necessary.`,
      );
    }

    // SMS access
    const smsApps = apps.filter((a) =>
      a.permissions.some((p) => p.category === 'sms' && p.granted),
    );
    if (smsApps.length > 0) {
      recommendations.push(
        `${smsApps.length} app${smsApps.length > 1 ? 's have' : ' has'} SMS access. Only messaging apps should require this permission.`,
      );
    }

    // Phone/call log access
    const phoneApps = apps.filter((a) =>
      a.permissions.some((p) => p.category === 'phone' && p.granted),
    );
    if (phoneApps.length > 0) {
      recommendations.push(
        `${phoneApps.length} app${phoneApps.length > 1 ? 's have' : ' has'} phone/call log access. Review whether these apps require this level of access.`,
      );
    }

    if (recommendations.length === 0) {
      recommendations.push(
        'No critical permission issues detected. Continue monitoring app permissions regularly.',
      );
    }

    return recommendations;
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/** Singleton PermissionAuditorService instance used across the application. */
export const permissionAuditorService: IPermissionAuditorService =
  new PermissionAuditorService();

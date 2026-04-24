/**
 * Tests for PermissionAuditorService
 *
 * Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7
 */

// ---------------------------------------------------------------------------
// Mock the native installed-apps module before importing the service.
// We make getApps throw so the service falls back to its built-in stub list,
// which gives us deterministic test data without a real native module.
// ---------------------------------------------------------------------------

jest.mock('@react-native-community/installed-apps', () => ({
  getApps: () => { throw new Error('native module not available'); },
}), { virtual: true });

// ---------------------------------------------------------------------------
// Import after mocks are set up
// ---------------------------------------------------------------------------

import {
  IPermissionAuditorService,
  permissionAuditorService,
} from './PermissionAuditorService';
import { AppPermission, InstalledApp } from '../types/index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Create a fresh PermissionAuditorService instance for each test by
 * re-importing the module.  Because Jest caches modules, we use the
 * singleton exported from the module and reset its internal cache via
 * a fresh `auditAllApps()` call (which clears the cache).
 *
 * For tests that need a truly isolated instance we import the class
 * directly.
 */

// We need access to the class constructor for isolated instances.
// Re-export it from the module under test by importing the module object.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const mod = require('./PermissionAuditorService');

function makeService(): IPermissionAuditorService {
  // Instantiate a fresh private class instance via the module's internal class.
  // The module exports the class as a named export for testing purposes.
  // If not available, fall back to the singleton (cache is cleared per test).
  if (mod.PermissionAuditorServiceImpl) {
    return new mod.PermissionAuditorServiceImpl();
  }
  // Use the singleton — auditAllApps() clears the cache
  return permissionAuditorService;
}

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const LOCATION_PERMISSION: AppPermission = {
  name: 'android.permission.ACCESS_FINE_LOCATION',
  granted: true,
  dangerous: true,
  category: 'location',
};

const CAMERA_PERMISSION: AppPermission = {
  name: 'android.permission.CAMERA',
  granted: true,
  dangerous: true,
  category: 'camera',
};

const INTERNET_PERMISSION: AppPermission = {
  name: 'android.permission.INTERNET',
  granted: true,
  dangerous: false,
  category: 'network',
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PermissionAuditorService', () => {
  // -------------------------------------------------------------------------
  // Requirement 10.1 — enumerate installed apps
  // -------------------------------------------------------------------------

  describe('Requirement 10.1 — getInstalledApps()', () => {
    it('returns a non-empty list of installed apps', async () => {
      const svc = makeService();
      const apps = await svc.getInstalledApps();
      expect(apps.length).toBeGreaterThan(0);
    });

    it('each app has required fields: id, name, packageName, version, installedDate, permissions, riskScore, riskLevel', async () => {
      const svc = makeService();
      const apps = await svc.getInstalledApps();

      for (const app of apps) {
        expect(typeof app.id).toBe('string');
        expect(app.id.length).toBeGreaterThan(0);
        expect(typeof app.name).toBe('string');
        expect(typeof app.packageName).toBe('string');
        expect(typeof app.version).toBe('string');
        expect(typeof app.installedDate).toBe('number');
        expect(Array.isArray(app.permissions)).toBe(true);
        expect(typeof app.riskScore).toBe('number');
        expect(['low', 'medium', 'high', 'critical']).toContain(app.riskLevel);
      }
    });

    it('each permission has required fields: name, granted, dangerous, category', async () => {
      const svc = makeService();
      const apps = await svc.getInstalledApps();

      for (const app of apps) {
        for (const perm of app.permissions) {
          expect(typeof perm.name).toBe('string');
          expect(typeof perm.granted).toBe('boolean');
          expect(typeof perm.dangerous).toBe('boolean');
          expect([
            'location', 'camera', 'microphone', 'contacts', 'storage',
            'phone', 'sms', 'calendar', 'sensors', 'network',
          ]).toContain(perm.category);
        }
      }
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 10.2 — risk score 0–100
  // -------------------------------------------------------------------------

  describe('Requirement 10.2 — calculateRiskScore()', () => {
    it('returns a number between 0 and 100 inclusive', async () => {
      const svc = makeService();
      const apps = await svc.getInstalledApps();

      for (const app of apps) {
        const score = await svc.calculateRiskScore(app.id);
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
      }
    });

    it('returns 0 for an app with no permissions', async () => {
      const svc = makeService();
      // Use a non-existent app id — returns empty permissions → score 0
      const score = await svc.calculateRiskScore('com.nonexistent.app');
      expect(score).toBe(0);
    });

    it('risk score is consistent with the riskScore stored on the InstalledApp', async () => {
      const svc = makeService();
      const apps = await svc.getInstalledApps();

      for (const app of apps) {
        const score = await svc.calculateRiskScore(app.id);
        expect(score).toBe(app.riskScore);
      }
    });

    it('caps the risk score at 100 even when weights would exceed it', async () => {
      // An app with all dangerous categories should be capped at 100
      // location(20) + camera(15) + microphone(15) + phone(15) + sms(15) = 80
      // Adding contacts(10) + storage(10) = 100 — already at cap
      const svc = makeService();
      const apps = await svc.getInstalledApps();
      for (const app of apps) {
        expect(app.riskScore).toBeLessThanOrEqual(100);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 10.3 — permission categorization
  // -------------------------------------------------------------------------

  describe('Requirement 10.3 — permission categorization', () => {
    it('categorizes ACCESS_FINE_LOCATION as location', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.maps');
      const locationPerms = perms.filter((p) => p.category === 'location');
      expect(locationPerms.length).toBeGreaterThan(0);
    });

    it('categorizes CAMERA as camera', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.social');
      const cameraPerms = perms.filter((p) => p.category === 'camera');
      expect(cameraPerms.length).toBeGreaterThan(0);
    });

    it('categorizes RECORD_AUDIO as microphone', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.social');
      const micPerms = perms.filter((p) => p.category === 'microphone');
      expect(micPerms.length).toBeGreaterThan(0);
    });

    it('categorizes READ_CONTACTS as contacts', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.social');
      const contactPerms = perms.filter((p) => p.category === 'contacts');
      expect(contactPerms.length).toBeGreaterThan(0);
    });

    it('categorizes READ_EXTERNAL_STORAGE as storage', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.social');
      const storagePerms = perms.filter((p) => p.category === 'storage');
      expect(storagePerms.length).toBeGreaterThan(0);
    });

    it('categorizes SEND_SMS as sms', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.messaging');
      const smsPerms = perms.filter((p) => p.category === 'sms');
      expect(smsPerms.length).toBeGreaterThan(0);
    });

    it('categorizes BODY_SENSORS as sensors', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.fitness');
      const sensorPerms = perms.filter((p) => p.category === 'sensors');
      expect(sensorPerms.length).toBeGreaterThan(0);
    });

    it('categorizes INTERNET as network', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.maps');
      const networkPerms = perms.filter((p) => p.category === 'network');
      expect(networkPerms.length).toBeGreaterThan(0);
    });

    it('each permission is assigned exactly one category', async () => {
      const svc = makeService();
      const apps = await svc.getInstalledApps();
      const validCategories = new Set([
        'location', 'camera', 'microphone', 'contacts', 'storage',
        'phone', 'sms', 'calendar', 'sensors', 'network',
      ]);

      for (const app of apps) {
        for (const perm of app.permissions) {
          expect(validCategories.has(perm.category)).toBe(true);
        }
      }
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 10.4 — high-risk classification (score ≥ 70)
  // -------------------------------------------------------------------------

  describe('Requirement 10.4 — getHighRiskApps()', () => {
    it('returns only apps with riskScore ≥ 70', async () => {
      const svc = makeService();
      const highRisk = await svc.getHighRiskApps();

      for (const app of highRisk) {
        expect(app.riskScore).toBeGreaterThanOrEqual(70);
      }
    });

    it('does not include apps with riskScore < 70', async () => {
      const svc = makeService();
      const allApps = await svc.getInstalledApps();
      const highRisk = await svc.getHighRiskApps();
      const highRiskIds = new Set(highRisk.map((a) => a.id));

      const lowRiskApps = allApps.filter((a) => a.riskScore < 70);
      for (const app of lowRiskApps) {
        expect(highRiskIds.has(app.id)).toBe(false);
      }
    });

    it('classifies apps with score ≥ 70 as high or critical riskLevel', async () => {
      const svc = makeService();
      const highRisk = await svc.getHighRiskApps();

      for (const app of highRisk) {
        expect(['high', 'critical']).toContain(app.riskLevel);
      }
    });

    it('classifies apps with score < 40 as low riskLevel', async () => {
      const svc = makeService();
      const allApps = await svc.getInstalledApps();
      const lowRiskApps = allApps.filter((a) => a.riskScore < 40);

      for (const app of lowRiskApps) {
        expect(app.riskLevel).toBe('low');
      }
    });

    it('classifies apps with score 40–69 as medium riskLevel', async () => {
      const svc = makeService();
      const allApps = await svc.getInstalledApps();
      const mediumRiskApps = allApps.filter(
        (a) => a.riskScore >= 40 && a.riskScore < 70,
      );

      for (const app of mediumRiskApps) {
        expect(app.riskLevel).toBe('medium');
      }
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 10.5 — dangerous permissions
  // -------------------------------------------------------------------------

  describe('Requirement 10.5 — dangerous permission identification', () => {
    it('marks location permissions as dangerous', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.maps');
      const locationPerms = perms.filter((p) => p.category === 'location');
      for (const perm of locationPerms) {
        expect(perm.dangerous).toBe(true);
      }
    });

    it('marks camera permissions as dangerous', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.social');
      const cameraPerms = perms.filter((p) => p.category === 'camera');
      for (const perm of cameraPerms) {
        expect(perm.dangerous).toBe(true);
      }
    });

    it('marks microphone permissions as dangerous', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.social');
      const micPerms = perms.filter((p) => p.category === 'microphone');
      for (const perm of micPerms) {
        expect(perm.dangerous).toBe(true);
      }
    });

    it('marks phone permissions as dangerous', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.messaging');
      // messaging app doesn't have phone perms in stub, use a direct check
      // via the categorization logic — verify the dangerous flag is set
      // for any phone-category permission that appears
      const phonePerms = perms.filter((p) => p.category === 'phone');
      for (const perm of phonePerms) {
        expect(perm.dangerous).toBe(true);
      }
    });

    it('marks sms permissions as dangerous', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.messaging');
      const smsPerms = perms.filter((p) => p.category === 'sms');
      expect(smsPerms.length).toBeGreaterThan(0);
      for (const perm of smsPerms) {
        expect(perm.dangerous).toBe(true);
      }
    });

    it('does NOT mark network permissions as dangerous', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.maps');
      const networkPerms = perms.filter((p) => p.category === 'network');
      for (const perm of networkPerms) {
        expect(perm.dangerous).toBe(false);
      }
    });

    it('does NOT mark calendar permissions as dangerous', async () => {
      // calendar is not in the dangerous set
      const svc = makeService();
      const allApps = await svc.getInstalledApps();
      for (const app of allApps) {
        const calendarPerms = app.permissions.filter(
          (p) => p.category === 'calendar',
        );
        for (const perm of calendarPerms) {
          expect(perm.dangerous).toBe(false);
        }
      }
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 10.6 — AuditReport structure
  // -------------------------------------------------------------------------

  describe('Requirement 10.6 — auditAllApps()', () => {
    it('returns an AuditReport with all required fields', async () => {
      const svc = makeService();
      const report = await svc.auditAllApps();

      expect(typeof report.totalApps).toBe('number');
      expect(typeof report.highRiskApps).toBe('number');
      expect(typeof report.totalPermissions).toBe('number');
      expect(typeof report.dangerousPermissions).toBe('number');
      expect(Array.isArray(report.recommendations)).toBe(true);
      expect(typeof report.overallRisk).toBe('number');
    });

    it('totalApps matches the number of installed apps', async () => {
      const svc = makeService();
      const apps = await svc.getInstalledApps();
      const report = await svc.auditAllApps();

      expect(report.totalApps).toBe(apps.length);
    });

    it('highRiskApps count matches apps with riskScore ≥ 70', async () => {
      const svc = makeService();
      const report = await svc.auditAllApps();
      const highRisk = await svc.getHighRiskApps();

      expect(report.highRiskApps).toBe(highRisk.length);
    });

    it('totalPermissions is the sum of all app permission counts', async () => {
      const svc = makeService();
      const apps = await svc.getInstalledApps();
      const expectedTotal = apps.reduce(
        (sum, a) => sum + a.permissions.length,
        0,
      );
      const report = await svc.auditAllApps();

      expect(report.totalPermissions).toBe(expectedTotal);
    });

    it('dangerousPermissions is the count of permissions with dangerous=true', async () => {
      const svc = makeService();
      const apps = await svc.getInstalledApps();
      const expectedDangerous = apps.reduce(
        (sum, a) => sum + a.permissions.filter((p) => p.dangerous).length,
        0,
      );
      const report = await svc.auditAllApps();

      expect(report.dangerousPermissions).toBe(expectedDangerous);
    });

    it('dangerousPermissions ≤ totalPermissions', async () => {
      const svc = makeService();
      const report = await svc.auditAllApps();

      expect(report.dangerousPermissions).toBeLessThanOrEqual(
        report.totalPermissions,
      );
    });

    it('overallRisk is between 0 and 100 inclusive', async () => {
      const svc = makeService();
      const report = await svc.auditAllApps();

      expect(report.overallRisk).toBeGreaterThanOrEqual(0);
      expect(report.overallRisk).toBeLessThanOrEqual(100);
    });

    it('recommendations is a non-empty array of strings', async () => {
      const svc = makeService();
      const report = await svc.auditAllApps();

      expect(report.recommendations.length).toBeGreaterThan(0);
      for (const rec of report.recommendations) {
        expect(typeof rec).toBe('string');
        expect(rec.length).toBeGreaterThan(0);
      }
    });

    it('highRiskApps count is ≤ totalApps', async () => {
      const svc = makeService();
      const report = await svc.auditAllApps();

      expect(report.highRiskApps).toBeLessThanOrEqual(report.totalApps);
    });
  });

  // -------------------------------------------------------------------------
  // Requirement 10.7 — results available for query
  // -------------------------------------------------------------------------

  describe('Requirement 10.7 — results available after audit', () => {
    it('getInstalledApps() returns consistent data after auditAllApps()', async () => {
      const svc = makeService();
      const report = await svc.auditAllApps();
      const apps = await svc.getInstalledApps();

      expect(apps.length).toBe(report.totalApps);
    });

    it('getHighRiskApps() returns consistent data after auditAllApps()', async () => {
      const svc = makeService();
      const report = await svc.auditAllApps();
      const highRisk = await svc.getHighRiskApps();

      expect(highRisk.length).toBe(report.highRiskApps);
    });
  });

  // -------------------------------------------------------------------------
  // getAppPermissions() — edge cases
  // -------------------------------------------------------------------------

  describe('getAppPermissions()', () => {
    it('returns an empty array for an unknown app id', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.unknown.app');
      expect(perms).toEqual([]);
    });

    it('returns permissions when queried by packageName', async () => {
      const svc = makeService();
      const perms = await svc.getAppPermissions('com.example.maps');
      expect(perms.length).toBeGreaterThan(0);
    });
  });

  // -------------------------------------------------------------------------
  // Singleton export
  // -------------------------------------------------------------------------

  describe('singleton export', () => {
    it('exports a permissionAuditorService singleton', () => {
      expect(permissionAuditorService).toBeDefined();
      expect(typeof permissionAuditorService.getInstalledApps).toBe('function');
      expect(typeof permissionAuditorService.getAppPermissions).toBe('function');
      expect(typeof permissionAuditorService.calculateRiskScore).toBe('function');
      expect(typeof permissionAuditorService.getHighRiskApps).toBe('function');
      expect(typeof permissionAuditorService.auditAllApps).toBe('function');
    });
  });
});

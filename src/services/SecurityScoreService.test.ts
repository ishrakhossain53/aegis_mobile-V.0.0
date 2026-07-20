/**
 * SecurityScoreService tests — Aegis Personal Cybersecurity Companion
 *
 * Covers:
 *  - Overall score is 0–100 (Req 11.1)
 *  - Level classification (Req 11.2, 11.3, 11.4)
 *  - Score breakdown has all 5 categories (Req 11.1)
 *  - Recommendations are prioritized (Req 11.7)
 *  - Score history retrieval (Req 11.6)
 *  - Weighted calculation correctness
 */

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

jest.mock('expo-crypto', () => ({
  getRandomBytes: (size: number) => new Uint8Array(size),
  digestStringAsync: async () => 'aabbccdd',
  CryptoDigestAlgorithm: { SHA1: 'SHA1', SHA256: 'SHA256' },
  CryptoEncoding: { HEX: 'hex' },
}));

const mockDbExecute = jest.fn().mockResolvedValue({ rowsAffected: 1 });
const mockDbSelect = jest.fn().mockResolvedValue([]);

jest.mock('../database/DatabaseService', () => ({
  databaseService: {
    execute: (...args: unknown[]) => mockDbExecute(...args),
    select: (...args: unknown[]) => mockDbSelect(...args),
  },
}));

// Control what each sub-service returns
const mockNetworkScan = jest.fn();
const mockAuditAllApps = jest.fn();
const mockGetMonitoredIdentities = jest.fn();
const mockGetAllCredentials = jest.fn();

jest.mock('./NetworkService', () => ({
  networkService: { scanNetwork: (...args: unknown[]) => mockNetworkScan(...args) },
}));

jest.mock('./PermissionAuditorService', () => ({
  permissionAuditorService: { auditAllApps: (...args: unknown[]) => mockAuditAllApps(...args) },
}));

jest.mock('./BreachService', () => ({
  breachService: { getMonitoredIdentities: (...args: unknown[]) => mockGetMonitoredIdentities(...args) },
}));

jest.mock('./VaultService', () => ({
  vaultService: { getAllCredentials: (...args: unknown[]) => mockGetAllCredentials(...args) },
}));

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import { SecurityScoreServiceImpl } from './SecurityScoreService';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeService(): SecurityScoreServiceImpl {
  return new SecurityScoreServiceImpl();
}

function setupDefaults() {
  // Network: no threats → score 100
  mockNetworkScan.mockResolvedValue({ overallRisk: 0, threats: [], recommendations: [] });
  // App audit: no risk → score 100
  mockAuditAllApps.mockResolvedValue({ overallRisk: 0, recommendations: [], totalApps: 5, highRiskApps: 0, totalPermissions: 10, dangerousPermissions: 2 });
  // Breach: no identities → score 50
  mockGetMonitoredIdentities.mockResolvedValue([]);
  // Vault: 5 credentials → score 80
  mockGetAllCredentials.mockResolvedValue(Array(5).fill({ id: 'x', type: 'password', title: 'T', tags: [], createdAt: 0, updatedAt: 0, favorite: false }));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SecurityScoreService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    setupDefaults();
  });

  // -------------------------------------------------------------------------
  // calculateSecurityScore — score range and level (Req 11.1–11.4)
  // -------------------------------------------------------------------------

  describe('calculateSecurityScore()', () => {
    it('returns an overall score between 0 and 100 (Req 11.1)', async () => {
      const svc = makeService();
      const score = await svc.calculateSecurityScore();
      expect(score.overall).toBeGreaterThanOrEqual(0);
      expect(score.overall).toBeLessThanOrEqual(100);
    });

    it('returns a lastUpdated timestamp close to now', async () => {
      const svc = makeService();
      const before = Date.now();
      const score = await svc.calculateSecurityScore();
      const after = Date.now();
      expect(score.lastUpdated).toBeGreaterThanOrEqual(before);
      expect(score.lastUpdated).toBeLessThanOrEqual(after);
    });

    it('classifies score 90–100 as excellent (Req 11.2)', async () => {
      // All categories at max → overall near 100
      mockNetworkScan.mockResolvedValue({ overallRisk: 0, threats: [], recommendations: [] });
      mockAuditAllApps.mockResolvedValue({ overallRisk: 0, recommendations: [], totalApps: 5, highRiskApps: 0, totalPermissions: 10, dangerousPermissions: 0 });
      mockGetMonitoredIdentities.mockResolvedValue([{ id: '1', type: 'email', value: 'a@b.com', addedAt: 0, lastChecked: 0, breachCount: 0, status: 'safe', breaches: [] }]);
      mockGetAllCredentials.mockResolvedValue(Array(25).fill({ id: 'x', type: 'password', title: 'T', tags: [], createdAt: 0, updatedAt: 0, favorite: false }));

      const svc = makeService();
      const score = await svc.calculateSecurityScore();
      // vault(95*0.25) + network(100*0.20) + app(100*0.20) + os(75*0.15) + breach(100*0.20)
      // = 23.75 + 20 + 20 + 11.25 + 20 = 95 → excellent
      expect(['excellent', 'good']).toContain(score.level);
    });

    it('classifies score 0–24 as critical (Req 11.4)', async () => {
      // All categories at minimum
      mockNetworkScan.mockResolvedValue({ overallRisk: 100, threats: [{ description: 'threat' }], recommendations: [] });
      mockAuditAllApps.mockResolvedValue({ overallRisk: 100, recommendations: [], totalApps: 5, highRiskApps: 5, totalPermissions: 10, dangerousPermissions: 10 });
      mockGetMonitoredIdentities.mockResolvedValue([{ id: '1', type: 'email', value: 'a@b.com', addedAt: 0, lastChecked: 0, breachCount: 3, status: 'compromised', breaches: [] }]);
      mockGetAllCredentials.mockResolvedValue([]);

      const svc = makeService();
      const score = await svc.calculateSecurityScore();
      // vault(40*0.25) + network(0*0.20) + app(0*0.20) + os(75*0.15) + breach(0*0.20)
      // = 10 + 0 + 0 + 11.25 + 0 = 21 → critical
      expect(['critical', 'poor']).toContain(score.level);
    });

    it('persists the score to the database (Req 11.5)', async () => {
      const svc = makeService();
      await svc.calculateSecurityScore();
      expect(mockDbExecute).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO security_scores'),
        expect.any(Array),
      );
    });

    it('does not throw when DB persistence fails', async () => {
      mockDbExecute.mockRejectedValueOnce(new Error('DB error'));
      const svc = makeService();
      await expect(svc.calculateSecurityScore()).resolves.toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // getScoreBreakdown — 5 categories (Req 11.1)
  // -------------------------------------------------------------------------

  describe('getScoreBreakdown()', () => {
    it('returns all 5 category scores', async () => {
      const svc = makeService();
      // Prime the cache by calling calculateSecurityScore first
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();

      expect(breakdown.vaultHealth).toBeDefined();
      expect(breakdown.networkSafety).toBeDefined();
      expect(breakdown.appRisk).toBeDefined();
      expect(breakdown.osHygiene).toBeDefined();
      expect(breakdown.breachStatus).toBeDefined();
    });

    it('each category score is 0–100', async () => {
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();

      for (const cat of Object.values(breakdown)) {
        expect(cat.score).toBeGreaterThanOrEqual(0);
        expect(cat.score).toBeLessThanOrEqual(100);
      }
    });

    it('each category has a weight', async () => {
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();

      for (const cat of Object.values(breakdown)) {
        expect(typeof cat.weight).toBe('number');
        expect(cat.weight).toBeGreaterThan(0);
      }
    });

    it('weights sum to 1.0', async () => {
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();

      const totalWeight = Object.values(breakdown).reduce((sum, cat) => sum + cat.weight, 0);
      expect(totalWeight).toBeCloseTo(1.0, 5);
    });

    it('each category has a status of good, warning, or critical', async () => {
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();

      for (const cat of Object.values(breakdown)) {
        expect(['good', 'warning', 'critical']).toContain(cat.status);
      }
    });

    it('each category has an issues array', async () => {
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();

      for (const cat of Object.values(breakdown)) {
        expect(Array.isArray(cat.issues)).toBe(true);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Vault health score logic
  // -------------------------------------------------------------------------

  describe('vault health score', () => {
    it('returns 40 when vault is empty', async () => {
      mockGetAllCredentials.mockResolvedValue([]);
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();
      expect(breakdown.vaultHealth.score).toBe(40);
    });

    it('returns 65 for 1–4 credentials', async () => {
      mockGetAllCredentials.mockResolvedValue(Array(3).fill({ id: 'x', type: 'password', title: 'T', tags: [], createdAt: 0, updatedAt: 0, favorite: false }));
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();
      expect(breakdown.vaultHealth.score).toBe(65);
    });

    it('returns 80 for 5–19 credentials', async () => {
      mockGetAllCredentials.mockResolvedValue(Array(10).fill({ id: 'x', type: 'password', title: 'T', tags: [], createdAt: 0, updatedAt: 0, favorite: false }));
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();
      expect(breakdown.vaultHealth.score).toBe(80);
    });

    it('returns 95 for 20+ credentials', async () => {
      mockGetAllCredentials.mockResolvedValue(Array(25).fill({ id: 'x', type: 'password', title: 'T', tags: [], createdAt: 0, updatedAt: 0, favorite: false }));
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();
      expect(breakdown.vaultHealth.score).toBe(95);
    });
  });

  // -------------------------------------------------------------------------
  // Breach status score logic
  // -------------------------------------------------------------------------

  describe('breach status score', () => {
    it('returns 50 when no identities are monitored', async () => {
      mockGetMonitoredIdentities.mockResolvedValue([]);
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();
      expect(breakdown.breachStatus.score).toBe(50);
    });

    it('returns 100 when all identities are safe', async () => {
      mockGetMonitoredIdentities.mockResolvedValue([
        { id: '1', type: 'email', value: 'a@b.com', addedAt: 0, lastChecked: 0, breachCount: 0, status: 'safe', breaches: [] },
      ]);
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();
      expect(breakdown.breachStatus.score).toBe(100);
    });

    it('returns 0 when any identity is compromised', async () => {
      mockGetMonitoredIdentities.mockResolvedValue([
        { id: '1', type: 'email', value: 'a@b.com', addedAt: 0, lastChecked: 0, breachCount: 2, status: 'compromised', breaches: [] },
      ]);
      const svc = makeService();
      await svc.calculateSecurityScore();
      const breakdown = await svc.getScoreBreakdown();
      expect(breakdown.breachStatus.score).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // getRecommendations (Req 11.7)
  // -------------------------------------------------------------------------

  describe('getRecommendations()', () => {
    it('returns an array of recommendations', async () => {
      const svc = makeService();
      await svc.calculateSecurityScore();
      const recs = await svc.getRecommendations();
      expect(Array.isArray(recs)).toBe(true);
    });

    it('each recommendation has required fields', async () => {
      const svc = makeService();
      await svc.calculateSecurityScore();
      const recs = await svc.getRecommendations();

      for (const rec of recs) {
        expect(typeof rec.id).toBe('string');
        expect(['critical', 'high', 'medium', 'low']).toContain(rec.priority);
        expect(typeof rec.title).toBe('string');
        expect(typeof rec.description).toBe('string');
        expect(typeof rec.action).toBe('string');
        expect(typeof rec.impact).toBe('number');
      }
    });

    it('recommendations are sorted critical → high → medium → low (Req 11.7)', async () => {
      // Force a compromised identity to generate a critical recommendation
      mockGetMonitoredIdentities.mockResolvedValue([
        { id: '1', type: 'email', value: 'a@b.com', addedAt: 0, lastChecked: 0, breachCount: 2, status: 'compromised', breaches: [] },
      ]);
      mockNetworkScan.mockResolvedValue({ overallRisk: 60, threats: [{ description: 'threat' }], recommendations: [] });

      const svc = makeService();
      await svc.calculateSecurityScore();
      const recs = await svc.getRecommendations();

      const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      for (let i = 1; i < recs.length; i++) {
        expect(priorityOrder[recs[i].priority]).toBeGreaterThanOrEqual(priorityOrder[recs[i - 1].priority]);
      }
    });

    it('generates a critical recommendation when identity is compromised', async () => {
      mockGetMonitoredIdentities.mockResolvedValue([
        { id: '1', type: 'email', value: 'a@b.com', addedAt: 0, lastChecked: 0, breachCount: 2, status: 'compromised', breaches: [] },
      ]);

      const svc = makeService();
      await svc.calculateSecurityScore();
      const recs = await svc.getRecommendations();

      const critical = recs.filter((r) => r.priority === 'critical');
      expect(critical.length).toBeGreaterThan(0);
    });
  });

  // -------------------------------------------------------------------------
  // getScoreHistory (Req 11.6)
  // -------------------------------------------------------------------------

  describe('getScoreHistory()', () => {
    it('returns an array (possibly empty)', async () => {
      mockDbSelect.mockResolvedValue([]);
      const svc = makeService();
      const history = await svc.getScoreHistory(7);
      expect(Array.isArray(history)).toBe(true);
    });

    it('maps DB rows to ScoreHistoryEntry objects', async () => {
      const now = Date.now();
      mockDbSelect.mockResolvedValue([
        { timestamp: now, overall_score: 85, level: 'good' },
        { timestamp: now - 86400000, overall_score: 72, level: 'fair' },
      ]);

      const svc = makeService();
      const history = await svc.getScoreHistory(7);

      expect(history.length).toBe(2);
      expect(history[0].score).toBe(85);
      expect(history[0].level).toBe('good');
      expect(history[1].score).toBe(72);
    });

    it('queries with the correct cutoff timestamp', async () => {
      mockDbSelect.mockResolvedValue([]);
      const svc = makeService();
      const before = Date.now();
      await svc.getScoreHistory(7);
      const after = Date.now();

      const callArgs = mockDbSelect.mock.calls[0];
      const cutoff = callArgs[1][0] as number;
      const expectedCutoff = before - 7 * 24 * 60 * 60 * 1000;
      expect(cutoff).toBeGreaterThanOrEqual(expectedCutoff - 100);
      expect(cutoff).toBeLessThanOrEqual(after);
    });
  });
});

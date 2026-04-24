/**
 * SecurityScoreService — Security Score Dashboard (F6) for Aegis.
 *
 * Responsibilities:
 *  - Aggregate weighted category scores from vault health, network safety,
 *    app risk, OS hygiene, and breach status into an overall score 0–100 (Req 11.1)
 *  - Classify the overall score into a security level (Req 11.2, 11.3, 11.4)
 *  - Persist each calculated score to DatabaseService (Req 11.5)
 *  - Provide score history retrieval (Req 11.6)
 *  - Generate prioritized recommendations (Req 11.7)
 *  - Complete full score calculation within 2 seconds (Req 16.3)
 *
 * Category weights (must sum to 1.0):
 *  - vaultHealth:    0.25
 *  - networkSafety:  0.20
 *  - appRisk:        0.20
 *  - osHygiene:      0.15
 *  - breachStatus:   0.20
 *
 * Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 16.3
 */

import {
  SecurityScore,
  ScoreBreakdown,
  CategoryScore,
  Recommendation,
} from '../types/index';
import { databaseService } from '../database/DatabaseService';
import { permissionAuditorService } from './PermissionAuditorService';
import { breachService } from './BreachService';
import { networkService } from './NetworkService';

// ---------------------------------------------------------------------------
// ScoreHistoryEntry type
// ---------------------------------------------------------------------------

export interface ScoreHistoryEntry {
  timestamp: number;
  score: number;
  level: string;
}

// ---------------------------------------------------------------------------
// ISecurityScoreService interface
// ---------------------------------------------------------------------------

export interface ISecurityScoreService {
  calculateSecurityScore(): Promise<SecurityScore>;
  getScoreBreakdown(): Promise<ScoreBreakdown>;
  getRecommendations(): Promise<Recommendation[]>;
  getScoreHistory(days: number): Promise<ScoreHistoryEntry[]>;
}

// ---------------------------------------------------------------------------
// Category weights
// ---------------------------------------------------------------------------

const WEIGHTS = {
  vaultHealth: 0.25,
  networkSafety: 0.20,
  appRisk: 0.20,
  osHygiene: 0.15,
  breachStatus: 0.20,
} as const;

// ---------------------------------------------------------------------------
// DB row shape for security_scores table
// ---------------------------------------------------------------------------

interface SecurityScoreRow {
  id: number;
  timestamp: number;
  overall_score: number;
  level: string;
  vault_health_score: number;
  network_safety_score: number;
  app_risk_score: number;
  os_hygiene_score: number;
  breach_status_score: number;
  breakdown: string | null;
}

// ---------------------------------------------------------------------------
// UUID generation helper
// ---------------------------------------------------------------------------

function generateUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// ---------------------------------------------------------------------------
// Level classification helpers
// ---------------------------------------------------------------------------

/**
 * Classify an overall score (0–100) into a security level.
 *
 * Requirements 11.2, 11.3, 11.4:
 *  - 90–100 → 'excellent'
 *  - 80–89  → 'good'
 *  - 50–79  → 'fair'
 *  - 25–49  → 'poor'
 *  - 0–24   → 'critical'
 */
function classifyLevel(
  score: number,
): SecurityScore['level'] {
  if (score >= 90) return 'excellent';
  if (score >= 80) return 'good';
  if (score >= 50) return 'fair';
  if (score >= 25) return 'poor';
  return 'critical';
}

/**
 * Classify a category score into a status string.
 */
function classifyCategoryStatus(score: number): CategoryScore['status'] {
  if (score >= 70) return 'good';
  if (score >= 40) return 'warning';
  return 'critical';
}

// ---------------------------------------------------------------------------
// SecurityScoreService implementation
// ---------------------------------------------------------------------------

class SecurityScoreServiceImpl implements ISecurityScoreService {
  // -------------------------------------------------------------------------
  // Category score calculators
  // -------------------------------------------------------------------------

  /**
   * Calculate vault health score.
   *
   * Stub at 80 — vault health requires VaultService integration which is
   * complex and out of scope for this task.
   */
  private async calculateVaultHealthScore(): Promise<{
    score: number;
    issues: string[];
  }> {
    // Stub: VaultService integration is deferred
    const score = 80;
    const issues: string[] = [];

    if (score < 100) {
      issues.push('Vault health check is using estimated data. Connect VaultService for accurate results.');
    }

    return { score, issues };
  }

  /**
   * Calculate network safety score.
   *
   * Calls `networkService.scanNetwork()` and derives score from `overallRisk`
   * (score = 100 - overallRisk). Falls back to 70 on failure.
   */
  private async calculateNetworkSafetyScore(): Promise<{
    score: number;
    issues: string[];
  }> {
    try {
      const scanResult = await networkService.scanNetwork();
      const score = Math.max(0, 100 - scanResult.overallRisk);
      const issues = scanResult.threats.map((t) => t.description);
      return { score, issues };
    } catch {
      return {
        score: 70,
        issues: ['Network scan failed. Using estimated score.'],
      };
    }
  }

  /**
   * Calculate app risk score.
   *
   * Calls `permissionAuditorService.auditAllApps()` and derives score from
   * `overallRisk` (score = 100 - overallRisk). Falls back to 70 on failure.
   */
  private async calculateAppRiskScore(): Promise<{
    score: number;
    issues: string[];
  }> {
    try {
      const auditReport = await permissionAuditorService.auditAllApps();
      const score = Math.max(0, 100 - auditReport.overallRisk);
      const issues = auditReport.recommendations.slice(0, 3); // Top 3 issues
      return { score, issues };
    } catch {
      return {
        score: 70,
        issues: ['App permission audit failed. Using estimated score.'],
      };
    }
  }

  /**
   * Calculate OS hygiene score.
   *
   * Stub at 75 — OS hygiene checks require native APIs not available in
   * Expo managed workflow.
   */
  private async calculateOsHygieneScore(): Promise<{
    score: number;
    issues: string[];
  }> {
    // Stub: native OS hygiene APIs not available in Expo managed workflow
    const score = 75;
    const issues: string[] = [];

    if (score < 100) {
      issues.push('OS hygiene check is using estimated data. Native APIs required for full assessment.');
    }

    return { score, issues };
  }

  /**
   * Calculate breach status score.
   *
   * Calls `breachService.getMonitoredIdentities()`:
   *  - If any identity is 'compromised' → score = 0
   *  - If no identities monitored → score = 50
   *  - If all safe → score = 100
   */
  private async calculateBreachStatusScore(): Promise<{
    score: number;
    issues: string[];
  }> {
    try {
      const identities = await breachService.getMonitoredIdentities();

      if (identities.length === 0) {
        return {
          score: 50,
          issues: ['No identities are being monitored for breaches. Add your email to start monitoring.'],
        };
      }

      const compromised = identities.filter((i) => i.status === 'compromised');

      if (compromised.length > 0) {
        const issues = compromised.map(
          (i) => `Identity "${i.value}" has been found in ${i.breachCount} data breach${i.breachCount !== 1 ? 'es' : ''}.`,
        );
        return { score: 0, issues };
      }

      return { score: 100, issues: [] };
    } catch {
      return {
        score: 50,
        issues: ['Breach status check failed. Using estimated score.'],
      };
    }
  }

  // -------------------------------------------------------------------------
  // ISecurityScoreService — calculateSecurityScore
  // -------------------------------------------------------------------------

  /**
   * Calculate the overall security score by aggregating all category scores.
   * Persists the result to the database.
   *
   * Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 16.3
   */
  async calculateSecurityScore(): Promise<SecurityScore> {
    // Run all category calculations in parallel for performance (Req 16.3)
    const [vault, network, appRisk, osHygiene, breach] = await Promise.all([
      this.calculateVaultHealthScore(),
      this.calculateNetworkSafetyScore(),
      this.calculateAppRiskScore(),
      this.calculateOsHygieneScore(),
      this.calculateBreachStatusScore(),
    ]);

    // Weighted overall score (Req 11.1)
    const overall = Math.round(
      vault.score * WEIGHTS.vaultHealth +
      network.score * WEIGHTS.networkSafety +
      appRisk.score * WEIGHTS.appRisk +
      osHygiene.score * WEIGHTS.osHygiene +
      breach.score * WEIGHTS.breachStatus,
    );

    const level = classifyLevel(overall);
    const timestamp = Date.now();

    const score: SecurityScore = {
      overall,
      level,
      lastUpdated: timestamp,
    };

    // Build breakdown for persistence
    const breakdown: ScoreBreakdown = {
      vaultHealth: {
        score: vault.score,
        weight: WEIGHTS.vaultHealth,
        status: classifyCategoryStatus(vault.score),
        issues: vault.issues,
      },
      networkSafety: {
        score: network.score,
        weight: WEIGHTS.networkSafety,
        status: classifyCategoryStatus(network.score),
        issues: network.issues,
      },
      appRisk: {
        score: appRisk.score,
        weight: WEIGHTS.appRisk,
        status: classifyCategoryStatus(appRisk.score),
        issues: appRisk.issues,
      },
      osHygiene: {
        score: osHygiene.score,
        weight: WEIGHTS.osHygiene,
        status: classifyCategoryStatus(osHygiene.score),
        issues: osHygiene.issues,
      },
      breachStatus: {
        score: breach.score,
        weight: WEIGHTS.breachStatus,
        status: classifyCategoryStatus(breach.score),
        issues: breach.issues,
      },
    };

    // Persist to database (Req 11.5)
    await this.persistScore(timestamp, score, breakdown);

    return score;
  }

  // -------------------------------------------------------------------------
  // ISecurityScoreService — getScoreBreakdown
  // -------------------------------------------------------------------------

  /**
   * Calculate and return the full per-category score breakdown.
   * Triggers a fresh score calculation.
   *
   * Requirements: 11.1
   */
  async getScoreBreakdown(): Promise<ScoreBreakdown> {
    const [vault, network, appRisk, osHygiene, breach] = await Promise.all([
      this.calculateVaultHealthScore(),
      this.calculateNetworkSafetyScore(),
      this.calculateAppRiskScore(),
      this.calculateOsHygieneScore(),
      this.calculateBreachStatusScore(),
    ]);

    return {
      vaultHealth: {
        score: vault.score,
        weight: WEIGHTS.vaultHealth,
        status: classifyCategoryStatus(vault.score),
        issues: vault.issues,
      },
      networkSafety: {
        score: network.score,
        weight: WEIGHTS.networkSafety,
        status: classifyCategoryStatus(network.score),
        issues: network.issues,
      },
      appRisk: {
        score: appRisk.score,
        weight: WEIGHTS.appRisk,
        status: classifyCategoryStatus(appRisk.score),
        issues: appRisk.issues,
      },
      osHygiene: {
        score: osHygiene.score,
        weight: WEIGHTS.osHygiene,
        status: classifyCategoryStatus(osHygiene.score),
        issues: osHygiene.issues,
      },
      breachStatus: {
        score: breach.score,
        weight: WEIGHTS.breachStatus,
        status: classifyCategoryStatus(breach.score),
        issues: breach.issues,
      },
    };
  }

  // -------------------------------------------------------------------------
  // ISecurityScoreService — getRecommendations
  // -------------------------------------------------------------------------

  /**
   * Generate prioritized recommendations based on current category scores.
   * Returns recommendations sorted by priority (critical first).
   *
   * Requirement: 11.7
   */
  async getRecommendations(): Promise<Recommendation[]> {
    const breakdown = await this.getScoreBreakdown();
    const recommendations: Recommendation[] = [];

    // Breach status recommendations
    if (breakdown.breachStatus.score === 0) {
      recommendations.push({
        id: generateUUID(),
        priority: 'critical',
        category: 'breachStatus',
        title: 'Compromised Identity Detected',
        description: breakdown.breachStatus.issues.join(' '),
        action: 'Review your monitored identities and change passwords for compromised accounts immediately.',
        impact: 20,
      });
    } else if (breakdown.breachStatus.score < 50) {
      recommendations.push({
        id: generateUUID(),
        priority: 'high',
        category: 'breachStatus',
        title: 'Breach Monitoring Inactive',
        description: 'No identities are being monitored for data breaches.',
        action: 'Add your email address to breach monitoring to receive alerts when your data is exposed.',
        impact: 10,
      });
    }

    // Network safety recommendations
    if (breakdown.networkSafety.score < 40) {
      recommendations.push({
        id: generateUUID(),
        priority: 'critical',
        category: 'networkSafety',
        title: 'Critical Network Threat Detected',
        description: breakdown.networkSafety.issues.slice(0, 2).join(' '),
        action: 'Disconnect from the current network and connect to a secure, trusted network.',
        impact: 20,
      });
    } else if (breakdown.networkSafety.score < 70) {
      recommendations.push({
        id: generateUUID(),
        priority: 'high',
        category: 'networkSafety',
        title: 'Network Security Issues Detected',
        description: breakdown.networkSafety.issues.slice(0, 2).join(' '),
        action: 'Enable DNS-over-HTTPS and avoid using unsecured Wi-Fi networks.',
        impact: 15,
      });
    } else if (breakdown.networkSafety.score < 90) {
      recommendations.push({
        id: generateUUID(),
        priority: 'medium',
        category: 'networkSafety',
        title: 'Network Security Can Be Improved',
        description: 'Your network security has minor issues.',
        action: 'Enable DNS-over-HTTPS for enhanced privacy and security.',
        impact: 8,
      });
    }

    // App risk recommendations
    if (breakdown.appRisk.score < 40) {
      recommendations.push({
        id: generateUUID(),
        priority: 'critical',
        category: 'appRisk',
        title: 'High-Risk Apps Detected',
        description: breakdown.appRisk.issues.slice(0, 2).join(' '),
        action: 'Review and uninstall apps with excessive permissions, or revoke unnecessary permissions.',
        impact: 20,
      });
    } else if (breakdown.appRisk.score < 70) {
      recommendations.push({
        id: generateUUID(),
        priority: 'high',
        category: 'appRisk',
        title: 'Apps With Risky Permissions',
        description: breakdown.appRisk.issues.slice(0, 2).join(' '),
        action: 'Review app permissions and revoke access that is not required for core functionality.',
        impact: 15,
      });
    } else if (breakdown.appRisk.score < 90) {
      recommendations.push({
        id: generateUUID(),
        priority: 'medium',
        category: 'appRisk',
        title: 'Some Apps Have Broad Permissions',
        description: 'A few apps have permissions that may not be necessary.',
        action: 'Periodically review app permissions to minimize your attack surface.',
        impact: 8,
      });
    }

    // Vault health recommendations
    if (breakdown.vaultHealth.score < 40) {
      recommendations.push({
        id: generateUUID(),
        priority: 'high',
        category: 'vaultHealth',
        title: 'Vault Health Issues',
        description: breakdown.vaultHealth.issues.join(' '),
        action: 'Review your password vault and ensure all credentials are up to date.',
        impact: 15,
      });
    } else if (breakdown.vaultHealth.score < 70) {
      recommendations.push({
        id: generateUUID(),
        priority: 'medium',
        category: 'vaultHealth',
        title: 'Vault Could Be Improved',
        description: 'Your password vault has some items that need attention.',
        action: 'Add credentials to your vault and ensure passwords are strong and unique.',
        impact: 10,
      });
    } else if (breakdown.vaultHealth.score < 90) {
      recommendations.push({
        id: generateUUID(),
        priority: 'low',
        category: 'vaultHealth',
        title: 'Vault Health Is Good',
        description: 'Your vault is in good shape with minor improvements possible.',
        action: 'Consider adding more credentials to your vault for centralized management.',
        impact: 5,
      });
    }

    // OS hygiene recommendations
    if (breakdown.osHygiene.score < 40) {
      recommendations.push({
        id: generateUUID(),
        priority: 'high',
        category: 'osHygiene',
        title: 'OS Security Issues Detected',
        description: breakdown.osHygiene.issues.join(' '),
        action: 'Update your operating system and ensure device security settings are properly configured.',
        impact: 15,
      });
    } else if (breakdown.osHygiene.score < 70) {
      recommendations.push({
        id: generateUUID(),
        priority: 'medium',
        category: 'osHygiene',
        title: 'OS Security Can Be Improved',
        description: 'Your device OS security has some areas for improvement.',
        action: 'Keep your OS updated and enable all available security features.',
        impact: 10,
      });
    } else if (breakdown.osHygiene.score < 90) {
      recommendations.push({
        id: generateUUID(),
        priority: 'low',
        category: 'osHygiene',
        title: 'OS Security Is Good',
        description: 'Your OS security is in good shape.',
        action: 'Ensure automatic OS updates are enabled to stay protected.',
        impact: 5,
      });
    }

    // Sort by priority: critical → high → medium → low
    const priorityOrder: Record<Recommendation['priority'], number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
    };

    recommendations.sort(
      (a, b) => priorityOrder[a.priority] - priorityOrder[b.priority],
    );

    return recommendations;
  }

  // -------------------------------------------------------------------------
  // ISecurityScoreService — getScoreHistory
  // -------------------------------------------------------------------------

  /**
   * Retrieve score history for the specified number of past days.
   *
   * Requirement: 11.6
   */
  async getScoreHistory(days: number): Promise<ScoreHistoryEntry[]> {
    const cutoffTimestamp = Date.now() - days * 24 * 60 * 60 * 1000;

    const rows = await databaseService.select<SecurityScoreRow>(
      `SELECT timestamp, overall_score, level FROM security_scores
       WHERE timestamp >= ? ORDER BY timestamp DESC`,
      [cutoffTimestamp],
    );

    return rows.map((row) => ({
      timestamp: row.timestamp,
      score: row.overall_score,
      level: row.level,
    }));
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Persist a calculated security score to the `security_scores` table.
   *
   * Requirement: 11.5
   */
  private async persistScore(
    timestamp: number,
    score: SecurityScore,
    breakdown: ScoreBreakdown,
  ): Promise<void> {
    try {
      await databaseService.execute(
        `INSERT INTO security_scores
           (timestamp, overall_score, level, vault_health_score, network_safety_score,
            app_risk_score, os_hygiene_score, breach_status_score, breakdown)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          timestamp,
          score.overall,
          score.level,
          breakdown.vaultHealth.score,
          breakdown.networkSafety.score,
          breakdown.appRisk.score,
          breakdown.osHygiene.score,
          breakdown.breachStatus.score,
          JSON.stringify(breakdown),
        ],
      );
    } catch {
      // Persistence failure should not prevent the score from being returned
      // to the caller. Log silently and continue.
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

export const securityScoreService: ISecurityScoreService =
  new SecurityScoreServiceImpl();
export default securityScoreService;

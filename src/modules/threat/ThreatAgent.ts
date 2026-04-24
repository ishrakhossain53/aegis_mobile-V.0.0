/**
 * ThreatAgent — Background Headless Task & Anomaly Scoring Engine
 *
 * Runs as a background headless task (via Expo TaskManager) performing:
 *  - Rule-based anomaly scoring against device telemetry
 *  - Jailbreak/root detection hooks (delegates to RASPGuard)
 *  - On-device-only processing — no telemetry leaves the device
 *
 * All sensitive operations are gated by RASPGuard.preOperationCheck().
 * No `any` types. Full error handling throughout.
 *
 * Security constraints (Phase 1 carry-over):
 *  - On-device processing only — no raw telemetry transmitted externally
 *  - RASP checks gate every sensitive operation
 *  - Anomaly scores are derived from heuristic rules, not ML models
 */

import { raspGuard } from '../../rasp/RASPGuard';
import { threatStore } from './ThreatStore';
import { Threat } from '../../types/index';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Registered background task name — must match registration in _layout.tsx */
export const THREAT_AGENT_TASK_NAME = 'AEGIS_THREAT_AGENT';

/** Minimum interval between background task executions (seconds) */
export const THREAT_AGENT_MIN_INTERVAL_SECONDS = 60;

// ---------------------------------------------------------------------------
// TaskManager shim — graceful degradation when expo-task-manager is absent
// ---------------------------------------------------------------------------

interface TaskManagerModule {
  defineTask(taskName: string, taskExecutor: () => Promise<unknown>): void;
  TaskManagerTaskBehavior?: {
    BACKGROUND_FETCH_RESULT_NEW_DATA: string;
    BACKGROUND_FETCH_RESULT_FAILED: string;
  };
}

function loadTaskManager(): TaskManagerModule | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('expo-task-manager');
    return (mod.default ?? mod) as TaskManagerModule;
  } catch {
    return null;
  }
}

const TaskManager: TaskManagerModule | null = loadTaskManager();

// ---------------------------------------------------------------------------
// Anomaly rule types
// ---------------------------------------------------------------------------

/**
 * A single anomaly detection rule.
 * Each rule evaluates a snapshot of device telemetry and returns a score
 * contribution (0–100) and an optional threat record to persist.
 */
interface AnomalyRule {
  /** Unique rule identifier */
  id: string;
  /** Human-readable description */
  description: string;
  /** Evaluate the rule against current telemetry. Returns null if no anomaly. */
  evaluate(telemetry: DeviceTelemetry): Promise<AnomalyFinding | null>;
}

/** Snapshot of device telemetry collected at evaluation time */
interface DeviceTelemetry {
  /** Unix timestamp (ms) when the snapshot was taken */
  timestamp: number;
  /** Whether the device is rooted/jailbroken per RASPGuard */
  isDeviceCompromised: boolean;
  /** Whether a debugger is attached per RASPGuard */
  isDebuggerAttached: boolean;
  /** Whether the app is running on an emulator */
  isRunningOnEmulator: boolean;
  /** Whether the code signature is valid */
  isCodeSignatureValid: boolean;
  /** Number of JS performance resource entries (network activity proxy) */
  resourceEntryCount: number;
}

/** Result of a single anomaly rule evaluation */
interface AnomalyFinding {
  /** Score contribution (0–100) — higher means more anomalous */
  scoreContribution: number;
  /** Threat record to persist (without id) */
  threat: Omit<Threat, 'id'>;
}

// ---------------------------------------------------------------------------
// Anomaly scoring rules
// ---------------------------------------------------------------------------

/**
 * Rule: Device compromise (root/jailbreak).
 * Highest severity — contributes 100 to anomaly score.
 */
const deviceCompromiseRule: AnomalyRule = {
  id: 'device_compromise',
  description: 'Detects rooted (Android) or jailbroken (iOS) devices',
  async evaluate(telemetry: DeviceTelemetry): Promise<AnomalyFinding | null> {
    if (!telemetry.isDeviceCompromised) return null;
    return {
      scoreContribution: 100,
      threat: {
        type: 'rootkit',
        severity: 'critical',
        description:
          'Device integrity check failed: the device appears to be rooted or jailbroken. ' +
          'Vault operations are blocked until the device is secured.',
        detectedAt: telemetry.timestamp,
        resolved: false,
        metadata: {
          rule: 'device_compromise',
          source: 'RASPGuard.isDeviceCompromised',
        },
      },
    };
  },
};

/**
 * Rule: Debugger attachment.
 * High severity — contributes 80 to anomaly score.
 */
const debuggerAttachmentRule: AnomalyRule = {
  id: 'debugger_attachment',
  description: 'Detects active debugger attachment to the app process',
  async evaluate(telemetry: DeviceTelemetry): Promise<AnomalyFinding | null> {
    if (!telemetry.isDebuggerAttached) return null;
    return {
      scoreContribution: 80,
      threat: {
        type: 'privilege_escalation',
        severity: 'high',
        description:
          'A debugger is attached to the application process. ' +
          'This may indicate an active reverse-engineering or exploitation attempt.',
        detectedAt: telemetry.timestamp,
        resolved: false,
        metadata: {
          rule: 'debugger_attachment',
          source: 'RASPGuard.isDebuggerAttached',
        },
      },
    };
  },
};

/**
 * Rule: Code signature tampering.
 * High severity — contributes 90 to anomaly score.
 */
const codeSignatureRule: AnomalyRule = {
  id: 'code_signature_invalid',
  description: 'Detects app bundle repackaging via bundle ID mismatch',
  async evaluate(telemetry: DeviceTelemetry): Promise<AnomalyFinding | null> {
    if (telemetry.isCodeSignatureValid) return null;
    return {
      scoreContribution: 90,
      threat: {
        type: 'privilege_escalation',
        severity: 'high',
        description:
          'Application code signature verification failed. ' +
          'The app bundle may have been tampered with or repackaged.',
        detectedAt: telemetry.timestamp,
        resolved: false,
        metadata: {
          rule: 'code_signature_invalid',
          source: 'RASPGuard.verifyCodeSignature',
        },
      },
    };
  },
};

/**
 * Rule: Emulator detection.
 * Medium severity — contributes 50 to anomaly score.
 */
const emulatorDetectionRule: AnomalyRule = {
  id: 'emulator_detected',
  description: 'Detects execution inside an emulator or simulator',
  async evaluate(telemetry: DeviceTelemetry): Promise<AnomalyFinding | null> {
    if (!telemetry.isRunningOnEmulator) return null;
    return {
      scoreContribution: 50,
      threat: {
        type: 'suspicious_network',
        severity: 'medium',
        description:
          'The application is running on an emulator or simulator. ' +
          'This environment may be used for automated analysis or testing.',
        detectedAt: telemetry.timestamp,
        resolved: false,
        metadata: {
          rule: 'emulator_detected',
          source: 'RASPGuard.isRunningOnEmulator',
        },
      },
    };
  },
};

/**
 * Rule: Excessive network activity (data exfiltration heuristic).
 * Medium severity — contributes 40 to anomaly score when threshold exceeded.
 */
const networkActivityRule: AnomalyRule = {
  id: 'excessive_network_activity',
  description: 'Detects unusually high network request volume',
  async evaluate(telemetry: DeviceTelemetry): Promise<AnomalyFinding | null> {
    const THRESHOLD = 50;
    if (telemetry.resourceEntryCount <= THRESHOLD) return null;
    return {
      scoreContribution: 40,
      threat: {
        type: 'data_exfiltration',
        severity: 'medium',
        description:
          `Unusual network activity detected: ${telemetry.resourceEntryCount} resource ` +
          'requests observed. This may indicate data exfiltration.',
        detectedAt: telemetry.timestamp,
        resolved: false,
        metadata: {
          rule: 'excessive_network_activity',
          resourceEntryCount: telemetry.resourceEntryCount,
          threshold: THRESHOLD,
          source: 'performance.getEntriesByType',
        },
      },
    };
  },
};

/** All registered anomaly rules, evaluated in order */
const ANOMALY_RULES: readonly AnomalyRule[] = [
  deviceCompromiseRule,
  debuggerAttachmentRule,
  codeSignatureRule,
  emulatorDetectionRule,
  networkActivityRule,
];

// ---------------------------------------------------------------------------
// ThreatAgent interface
// ---------------------------------------------------------------------------

export interface IThreatAgent {
  /**
   * Register the background headless task with Expo TaskManager.
   * Must be called at the module level (before the app renders).
   */
  registerBackgroundTask(): void;

  /**
   * Collect device telemetry and run all anomaly rules.
   * Persists detected threats to ThreatStore.
   * Returns the computed anomaly score (0–100).
   *
   * RASP-gated: returns 0 and logs a warning if the pre-operation check fails.
   */
  runAnomalyScoring(): Promise<number>;

  /**
   * Collect a fresh DeviceTelemetry snapshot.
   * Exposed for testing purposes.
   */
  collectTelemetry(): Promise<DeviceTelemetry>;
}

// ---------------------------------------------------------------------------
// ThreatAgent implementation
// ---------------------------------------------------------------------------

class ThreatAgentImpl implements IThreatAgent {
  // -------------------------------------------------------------------------
  // Background task registration
  // -------------------------------------------------------------------------

  /**
   * Register the headless background task with Expo TaskManager.
   *
   * This must be called at the module level (outside any React component)
   * so that the task is available when the OS wakes the app in the background.
   *
   * The task runs anomaly scoring and persists any detected threats.
   */
  registerBackgroundTask(): void {
    if (TaskManager === null) {
      console.warn(
        '[ThreatAgent] expo-task-manager not installed — background task registration skipped. ' +
          'Install expo-task-manager to enable background threat monitoring.',
      );
      return;
    }

    TaskManager.defineTask(THREAT_AGENT_TASK_NAME, async () => {
      try {
        await this.runAnomalyScoring();
        return TaskManager.TaskManagerTaskBehavior
          ? TaskManager.TaskManagerTaskBehavior.BACKGROUND_FETCH_RESULT_NEW_DATA
          : 'newData';
      } catch (err) {
        console.warn(
          `[ThreatAgent] Background task error: ${String(err)}`,
        );
        return TaskManager.TaskManagerTaskBehavior
          ? TaskManager.TaskManagerTaskBehavior.BACKGROUND_FETCH_RESULT_FAILED
          : 'failed';
      }
    });
  }

  // -------------------------------------------------------------------------
  // Anomaly scoring
  // -------------------------------------------------------------------------

  /**
   * Run all anomaly rules against fresh device telemetry.
   *
   * RASP gate: if preOperationCheck fails, scoring is skipped and 0 is
   * returned. This prevents the agent itself from being used as an attack
   * surface on a compromised device.
   *
   * Score calculation:
   *  - Each rule contributes a score (0–100).
   *  - The aggregate score is the maximum contribution across all rules
   *    (not a sum) to avoid double-counting overlapping signals.
   *  - Final score is clamped to [0, 100].
   */
  async runAnomalyScoring(): Promise<number> {
    // RASP gate — all sensitive operations require a clean environment
    const raspResult = await raspGuard.preOperationCheck();
    if (!raspResult.allowed) {
      console.warn(
        `[ThreatAgent] RASP check failed — anomaly scoring skipped. Reason: ${raspResult.reason ?? 'unknown'}`,
      );
      // Still record the RASP violation as a threat
      await this.persistRASPViolation(raspResult.reason ?? 'RASP pre-operation check failed');
      return 0;
    }

    const telemetry = await this.collectTelemetry();
    const findings: AnomalyFinding[] = [];

    for (const rule of ANOMALY_RULES) {
      try {
        const finding = await rule.evaluate(telemetry);
        if (finding !== null) {
          findings.push(finding);
        }
      } catch (err) {
        console.warn(
          `[ThreatAgent] Rule "${rule.id}" evaluation error: ${String(err)}`,
        );
      }
    }

    // Persist all detected threats
    for (const finding of findings) {
      await threatStore.addThreat(finding.threat);
    }

    // Aggregate score: maximum contribution (not sum)
    const score =
      findings.length > 0
        ? Math.min(100, Math.max(...findings.map((f) => f.scoreContribution)))
        : 0;

    return score;
  }

  // -------------------------------------------------------------------------
  // Telemetry collection
  // -------------------------------------------------------------------------

  /**
   * Collect a fresh snapshot of device telemetry for anomaly rule evaluation.
   * All checks are on-device only — no data is transmitted externally.
   */
  async collectTelemetry(): Promise<DeviceTelemetry> {
    const timestamp = Date.now();

    // Parallel collection of independent checks
    const [isDeviceCompromised, isCodeSignatureValid] = await Promise.all([
      this.safeCheck(() => raspGuard.isDeviceCompromised(), false),
      this.safeCheck(() => raspGuard.verifyCodeSignature(), true),
    ]);

    const isDebuggerAttached = raspGuard.isDebuggerAttached();
    const isRunningOnEmulator = raspGuard.isRunningOnEmulator();

    // Network activity proxy via Performance API
    let resourceEntryCount = 0;
    try {
      if (
        typeof performance !== 'undefined' &&
        typeof performance.getEntriesByType === 'function'
      ) {
        resourceEntryCount = performance.getEntriesByType('resource').length;
      }
    } catch {
      // Performance API unavailable — leave at 0
    }

    return {
      timestamp,
      isDeviceCompromised,
      isDebuggerAttached,
      isRunningOnEmulator,
      isCodeSignatureValid,
      resourceEntryCount,
    };
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Execute an async check safely, returning the fallback value on error.
   */
  private async safeCheck<T>(
    check: () => Promise<T>,
    fallback: T,
  ): Promise<T> {
    try {
      return await check();
    } catch {
      return fallback;
    }
  }

  /**
   * Persist a RASP violation as a threat record in ThreatStore.
   */
  private async persistRASPViolation(reason: string): Promise<void> {
    await threatStore.addThreat({
      type: 'privilege_escalation',
      severity: 'high',
      description: `RASP pre-operation check failed: ${reason}`,
      detectedAt: Date.now(),
      resolved: false,
      metadata: { source: 'ThreatAgent.runAnomalyScoring', reason },
    });
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/** Singleton ThreatAgent instance. */
export const threatAgent: IThreatAgent = new ThreatAgentImpl();

// Register the background task at module load time (required by Expo)
threatAgent.registerBackgroundTask();

export default threatAgent;

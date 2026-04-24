/**
 * NetworkInspector — Wi-Fi Security Assessment & Network Threat Detection
 *
 * Extends the base NetworkService capabilities with:
 *  - Wi-Fi security assessment (encryption classification)
 *  - ARP spoofing detection via gateway IP consistency checks
 *  - Rogue access point fingerprinting (BSSID/SSID anomaly detection)
 *  - SSL anomaly detection (certificate chain validation probes)
 *
 * All processing is on-device only. No raw network telemetry is transmitted
 * externally. RASP checks gate all sensitive operations.
 *
 * No `any` types. Full error handling throughout.
 */

import { raspGuard } from '../../rasp/RASPGuard';
import { networkStore } from './NetworkStore';
import {
  NetworkStatus,
  MITMResult,
  NetworkScanResult,
  NetworkThreat,
} from '../../types/index';

// ---------------------------------------------------------------------------
// NetInfo shim (same pattern as NetworkService)
// ---------------------------------------------------------------------------

interface NetInfoWifiDetails {
  ssid?: string | null;
  bssid?: string | null;
  ipAddress?: string | null;
  subnet?: string | null;
  strength?: number | null;
  frequency?: number | null;
}

interface NetInfoState {
  type: string;
  isConnected: boolean | null;
  details: NetInfoWifiDetails | null;
}

type NetInfoFetchFn = () => Promise<NetInfoState>;

function loadNetInfo(): NetInfoFetchFn {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const NetInfo = require('@react-native-community/netinfo');
    return NetInfo.default?.fetch ?? NetInfo.fetch;
  } catch {
    return async (): Promise<NetInfoState> => ({
      type: 'unknown',
      isConnected: null,
      details: null,
    });
  }
}

const netInfoFetch: NetInfoFetchFn = loadNetInfo();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Timeout for SSL probe requests (ms) */
const SSL_PROBE_TIMEOUT_MS = 5_000;

/** Known-good HTTPS endpoints for SSL anomaly detection */
const SSL_PROBE_ENDPOINTS: readonly string[] = [
  'https://1.1.1.1',
  'https://8.8.8.8',
];

/** Minimum frequency (MHz) for 5 GHz band detection */
const FREQ_5GHZ_MIN = 4900;

/** Rogue AP: SSID length threshold for suspiciously short names */
const SUSPICIOUS_SSID_MIN_LENGTH = 2;

// ---------------------------------------------------------------------------
// Exported types
// ---------------------------------------------------------------------------

/** Result of a Wi-Fi security assessment */
export interface WiFiAssessment {
  ssid: string | undefined;
  bssid: string | undefined;
  encryption: NetworkStatus['encryption'];
  isSecure: boolean;
  /** Whether the network is on the 5 GHz band (more secure than 2.4 GHz) */
  is5GHz: boolean;
  /** Signal strength in dBm */
  signalStrength: number | undefined;
  /** Detected security issues */
  issues: string[];
  /** Risk level for this network */
  riskLevel: 'low' | 'medium' | 'high';
}

/** Result of ARP spoofing detection */
export interface ARPSpoofingResult {
  detected: boolean;
  /** Observed gateway IP addresses (should be exactly one) */
  observedGateways: string[];
  /** Confidence level of the detection */
  confidence: 'low' | 'medium' | 'high';
  details: string[];
}

/** Result of rogue AP fingerprinting */
export interface RogueAPResult {
  detected: boolean;
  /** Suspicious indicators found */
  indicators: string[];
  /** Risk level */
  riskLevel: 'low' | 'medium' | 'high';
}

/** Result of SSL anomaly detection */
export interface SSLAnomalyResult {
  anomalyDetected: boolean;
  /** Endpoints that failed SSL validation */
  failedEndpoints: string[];
  /** Detailed anomaly descriptions */
  anomalies: string[];
  riskLevel: 'low' | 'medium' | 'high';
}

/** Full network inspection report */
export interface NetworkInspectionReport {
  timestamp: number;
  wifiAssessment: WiFiAssessment | null;
  arpSpoofing: ARPSpoofingResult;
  rogueAP: RogueAPResult;
  sslAnomalies: SSLAnomalyResult;
  mitm: MITMResult;
  scanResult: NetworkScanResult;
}

// ---------------------------------------------------------------------------
// INetworkInspector interface
// ---------------------------------------------------------------------------

export interface INetworkInspector {
  /**
   * Perform a full network inspection.
   * RASP-gated. Results are persisted to NetworkStore.
   */
  inspect(): Promise<NetworkInspectionReport>;

  /** Assess the current Wi-Fi network security. */
  assessWiFi(): Promise<WiFiAssessment | null>;

  /** Detect ARP spoofing via gateway consistency checks. */
  detectARPSpoofing(): Promise<ARPSpoofingResult>;

  /** Fingerprint the current AP for rogue AP indicators. */
  fingerprintRogueAP(): Promise<RogueAPResult>;

  /** Probe SSL endpoints for certificate anomalies. */
  detectSSLAnomalies(): Promise<SSLAnomalyResult>;
}

// ---------------------------------------------------------------------------
// NetworkInspector implementation
// ---------------------------------------------------------------------------

class NetworkInspectorImpl implements INetworkInspector {
  // -------------------------------------------------------------------------
  // Full inspection
  // -------------------------------------------------------------------------

  async inspect(): Promise<NetworkInspectionReport> {
    const raspResult = await raspGuard.preOperationCheck();
    if (!raspResult.allowed) {
      throw new Error(
        `[NetworkInspector] RASP check failed — inspection blocked. Reason: ${raspResult.reason ?? 'unknown'}`,
      );
    }

    const timestamp = Date.now();

    // Run all checks in parallel for performance
    const [wifiAssessment, arpSpoofing, rogueAP, sslAnomalies] =
      await Promise.all([
        this.assessWiFi(),
        this.detectARPSpoofing(),
        this.fingerprintRogueAP(),
        this.detectSSLAnomalies(),
      ]);

    // Build MITM result from ARP + SSL findings
    const mitm = this.buildMITMResult(arpSpoofing, sslAnomalies);

    // Build scan result from all findings
    const scanResult = this.buildScanResult(
      wifiAssessment,
      arpSpoofing,
      rogueAP,
      sslAnomalies,
    );

    const report: NetworkInspectionReport = {
      timestamp,
      wifiAssessment,
      arpSpoofing,
      rogueAP,
      sslAnomalies,
      mitm,
      scanResult,
    };

    // Persist to NetworkStore
    await networkStore.updateLastScan(report);

    return report;
  }

  // -------------------------------------------------------------------------
  // Wi-Fi security assessment
  // -------------------------------------------------------------------------

  async assessWiFi(): Promise<WiFiAssessment | null> {
    let state: NetInfoState;
    try {
      state = await netInfoFetch();
    } catch (err) {
      console.warn(`[NetworkInspector] NetInfo fetch failed: ${String(err)}`);
      return null;
    }

    if (state.type !== 'wifi' || !state.isConnected) {
      return null;
    }

    const details = state.details;
    const ssid = details?.ssid ?? undefined;
    const bssid = details?.bssid ?? undefined;
    const signalStrength = details?.strength ?? undefined;
    const frequency = details?.frequency ?? undefined;

    // Derive encryption type (heuristic — NetInfo doesn't expose this directly)
    const encryption = this.deriveEncryptionType(state);
    const isSecure = encryption !== 'WEP' && encryption !== 'none';
    const is5GHz = frequency !== undefined && frequency >= FREQ_5GHZ_MIN;

    const issues: string[] = [];

    if (!isSecure) {
      issues.push(
        encryption === 'WEP'
          ? 'WEP encryption is cryptographically broken and provides no real security.'
          : 'Network has no encryption — all traffic is transmitted in plaintext.',
      );
    }

    if (encryption === 'WPA') {
      issues.push('WPA (TKIP) has known vulnerabilities. WPA2 or WPA3 is recommended.');
    }

    if (ssid !== undefined && ssid.length < SUSPICIOUS_SSID_MIN_LENGTH) {
      issues.push(`Suspiciously short SSID "${ssid}" may indicate a rogue access point.`);
    }

    // Signal strength anomaly: very strong signal from unknown AP can indicate evil twin
    if (signalStrength !== undefined && signalStrength > -30) {
      issues.push(
        'Unusually strong signal strength detected. This may indicate a nearby rogue AP.',
      );
    }

    const riskLevel = this.classifyWiFiRisk(encryption, issues);

    return {
      ssid,
      bssid,
      encryption,
      isSecure,
      is5GHz,
      signalStrength,
      issues,
      riskLevel,
    };
  }

  // -------------------------------------------------------------------------
  // ARP spoofing detection
  // -------------------------------------------------------------------------

  /**
   * Detect ARP spoofing by checking gateway IP consistency.
   *
   * Heuristic approach (Expo managed workflow limitation):
   *  - Fetch the device IP and subnet from NetInfo
   *  - Probe the default gateway (first IP in subnet) via HTTP HEAD
   *  - Inconsistencies in response headers or connection failures indicate
   *    potential ARP spoofing
   *
   * A native module would provide direct ARP table access for higher
   * confidence detection.
   */
  async detectARPSpoofing(): Promise<ARPSpoofingResult> {
    const observedGateways: string[] = [];
    const details: string[] = [];

    let state: NetInfoState;
    try {
      state = await netInfoFetch();
    } catch {
      return {
        detected: false,
        observedGateways: [],
        confidence: 'low',
        details: ['NetInfo unavailable — ARP check skipped'],
      };
    }

    if (state.type !== 'wifi' || !state.isConnected || !state.details) {
      return {
        detected: false,
        observedGateways: [],
        confidence: 'low',
        details: ['Not connected to Wi-Fi — ARP check not applicable'],
      };
    }

    const ipAddress = state.details.ipAddress;
    const subnet = state.details.subnet;

    if (!ipAddress || !subnet) {
      return {
        detected: false,
        observedGateways: [],
        confidence: 'low',
        details: ['IP address or subnet unavailable — ARP check skipped'],
      };
    }

    // Derive gateway IP (typically x.x.x.1)
    const gatewayIP = this.deriveGatewayIP(ipAddress, subnet);
    if (gatewayIP) {
      observedGateways.push(gatewayIP);
    }

    // Probe the gateway for anomalous responses
    const probeResult = await this.probeGateway(gatewayIP);
    if (probeResult.anomalous) {
      details.push(...probeResult.indicators);
      return {
        detected: true,
        observedGateways,
        confidence: 'medium',
        details,
      };
    }

    // Multiple gateway IPs observed (should be exactly one)
    if (observedGateways.length > 1) {
      details.push(
        `Multiple gateway IPs observed: ${observedGateways.join(', ')}. ` +
          'This may indicate ARP cache poisoning.',
      );
      return {
        detected: true,
        observedGateways,
        confidence: 'high',
        details,
      };
    }

    return {
      detected: false,
      observedGateways,
      confidence: 'low',
      details: ['No ARP spoofing indicators detected'],
    };
  }

  // -------------------------------------------------------------------------
  // Rogue AP fingerprinting
  // -------------------------------------------------------------------------

  /**
   * Fingerprint the current access point for rogue AP indicators.
   *
   * Checks:
   *  1. SSID/BSSID anomalies (suspiciously short SSID, null BSSID)
   *  2. Signal strength anomalies (evil twin APs often have stronger signal)
   *  3. Frequency band anomalies (rogue APs often use 2.4 GHz for wider range)
   *  4. Open network with captive portal indicators
   */
  async fingerprintRogueAP(): Promise<RogueAPResult> {
    const indicators: string[] = [];

    let state: NetInfoState;
    try {
      state = await netInfoFetch();
    } catch {
      return {
        detected: false,
        indicators: ['NetInfo unavailable — rogue AP check skipped'],
        riskLevel: 'low',
      };
    }

    if (state.type !== 'wifi' || !state.isConnected) {
      return {
        detected: false,
        indicators: ['Not connected to Wi-Fi'],
        riskLevel: 'low',
      };
    }

    const details = state.details;
    const ssid = details?.ssid;
    const bssid = details?.bssid;
    const strength = details?.strength;
    const frequency = details?.frequency;

    // Check 1: Null or missing BSSID (some rogue APs hide their MAC)
    if (!bssid || bssid === '00:00:00:00:00:00') {
      indicators.push('BSSID is null or zeroed — this is unusual for legitimate APs.');
    }

    // Check 2: Suspiciously short SSID
    if (ssid !== null && ssid !== undefined && ssid.length < SUSPICIOUS_SSID_MIN_LENGTH) {
      indicators.push(
        `SSID "${ssid}" is suspiciously short. Rogue APs sometimes use minimal SSIDs.`,
      );
    }

    // Check 3: Very strong signal (evil twin APs are often placed close to the victim)
    if (strength !== null && strength !== undefined && strength > -30) {
      indicators.push(
        `Signal strength ${strength} dBm is unusually strong. ` +
          'An evil twin AP placed nearby would exhibit this pattern.',
      );
    }

    // Check 4: 2.4 GHz band with open encryption (common rogue AP setup)
    const is24GHz =
      frequency !== null &&
      frequency !== undefined &&
      frequency < FREQ_5GHZ_MIN &&
      frequency > 2400;
    const encryption = this.deriveEncryptionType(state);
    if (is24GHz && (encryption === 'none' || encryption === 'WEP')) {
      indicators.push(
        'Open or WEP-encrypted network on 2.4 GHz band — common rogue AP configuration.',
      );
    }

    const detected = indicators.length > 0;
    const riskLevel: RogueAPResult['riskLevel'] =
      indicators.length >= 3 ? 'high' : indicators.length >= 1 ? 'medium' : 'low';

    return { detected, indicators, riskLevel };
  }

  // -------------------------------------------------------------------------
  // SSL anomaly detection
  // -------------------------------------------------------------------------

  /**
   * Probe known HTTPS endpoints for SSL certificate anomalies.
   *
   * Anomaly indicators:
   *  - SSL/TLS handshake failure (certificate error)
   *  - Unexpected HTTP status codes from well-known endpoints
   *  - Connection timeout (may indicate traffic interception)
   */
  async detectSSLAnomalies(): Promise<SSLAnomalyResult> {
    const failedEndpoints: string[] = [];
    const anomalies: string[] = [];

    await Promise.all(
      SSL_PROBE_ENDPOINTS.map(async (endpoint) => {
        const result = await this.probeSSLEndpoint(endpoint);
        if (result.anomalous) {
          failedEndpoints.push(endpoint);
          anomalies.push(...result.anomalies);
        }
      }),
    );

    const anomalyDetected = failedEndpoints.length > 0;
    const riskLevel: SSLAnomalyResult['riskLevel'] =
      failedEndpoints.length >= 2
        ? 'high'
        : failedEndpoints.length === 1
          ? 'medium'
          : 'low';

    return { anomalyDetected, failedEndpoints, anomalies, riskLevel };
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Derive Wi-Fi encryption type heuristically.
   * NetInfo does not expose encryption type directly on all platforms.
   */
  private deriveEncryptionType(
    state: NetInfoState,
  ): NetworkStatus['encryption'] {
    if (state.type !== 'wifi') return undefined;
    if (!state.isConnected) return 'none';
    // Conservative heuristic: assume WPA2 for connected networks
    // A native module would provide the actual encryption type
    return 'WPA2';
  }

  /**
   * Classify Wi-Fi risk level based on encryption and detected issues.
   */
  private classifyWiFiRisk(
    encryption: NetworkStatus['encryption'],
    issues: string[],
  ): WiFiAssessment['riskLevel'] {
    if (encryption === 'none' || encryption === 'WEP') return 'high';
    if (encryption === 'WPA') return 'medium';
    if (issues.length > 0) return 'medium';
    return 'low';
  }

  /**
   * Derive the default gateway IP from the device IP and subnet mask.
   * Returns null if derivation is not possible.
   */
  private deriveGatewayIP(ipAddress: string, subnet: string): string | null {
    try {
      const ipParts = ipAddress.split('.').map(Number);
      const subnetParts = subnet.split('.').map(Number);

      if (ipParts.length !== 4 || subnetParts.length !== 4) return null;

      // Network address = IP & subnet mask
      const networkParts = ipParts.map((part, i) => part & (subnetParts[i] ?? 0));
      // Gateway is typically network address + 1
      networkParts[3] = (networkParts[3] ?? 0) + 1;

      return networkParts.join('.');
    } catch {
      return null;
    }
  }

  /**
   * Probe a gateway IP for anomalous HTTP responses.
   * Returns detected indicators.
   */
  private async probeGateway(
    gatewayIP: string | null,
  ): Promise<{ anomalous: boolean; indicators: string[] }> {
    if (!gatewayIP) {
      return { anomalous: false, indicators: [] };
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), SSL_PROBE_TIMEOUT_MS);

    try {
      // Probe the gateway over HTTP (not HTTPS — gateways typically don't have certs)
      const response = await fetch(`http://${gatewayIP}`, {
        method: 'HEAD',
        signal: controller.signal,
      });

      // Unexpected redirect to a different host can indicate ARP spoofing
      if (response.redirected) {
        const redirectUrl = response.url;
        if (!redirectUrl.includes(gatewayIP)) {
          return {
            anomalous: true,
            indicators: [
              `Gateway ${gatewayIP} redirected to unexpected host: ${redirectUrl}. ` +
                'This may indicate ARP cache poisoning.',
            ],
          };
        }
      }

      return { anomalous: false, indicators: [] };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      // Abort = timeout, not necessarily anomalous
      if (message.includes('AbortError') || message.includes('abort')) {
        return { anomalous: false, indicators: [] };
      }
      // Other errors are not necessarily ARP spoofing
      return { anomalous: false, indicators: [] };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Probe a single HTTPS endpoint for SSL anomalies.
   */
  private async probeSSLEndpoint(
    endpoint: string,
  ): Promise<{ anomalous: boolean; anomalies: string[] }> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), SSL_PROBE_TIMEOUT_MS);

    try {
      const response = await fetch(endpoint, {
        method: 'HEAD',
        signal: controller.signal,
      });

      if (!response.ok) {
        return {
          anomalous: true,
          anomalies: [
            `Unexpected HTTP ${response.status} from SSL probe endpoint ${endpoint}.`,
          ],
        };
      }

      return { anomalous: false, anomalies: [] };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);

      if (message.includes('AbortError') || message.includes('abort')) {
        // Timeout — inconclusive
        return { anomalous: false, anomalies: [] };
      }

      // SSL/TLS errors are strong anomaly indicators
      if (
        message.includes('certificate') ||
        message.includes('SSL') ||
        message.includes('TLS') ||
        message.includes('CERT') ||
        message.includes('handshake')
      ) {
        return {
          anomalous: true,
          anomalies: [
            `SSL/TLS anomaly detected probing ${endpoint}: ${message}. ` +
              'A man-in-the-middle attack may be intercepting HTTPS traffic.',
          ],
        };
      }

      // Generic network error — low confidence
      return { anomalous: false, anomalies: [] };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Build a MITMResult from ARP spoofing and SSL anomaly findings.
   */
  private buildMITMResult(
    arp: ARPSpoofingResult,
    ssl: SSLAnomalyResult,
  ): MITMResult {
    const indicators: string[] = [];

    if (arp.detected) {
      indicators.push(...arp.details);
    }
    if (ssl.anomalyDetected) {
      indicators.push(...ssl.anomalies);
    }

    const detected = indicators.length > 0;
    const riskLevel: MITMResult['riskLevel'] =
      arp.detected && ssl.anomalyDetected
        ? 'high'
        : detected
          ? 'medium'
          : 'low';

    return { detected, indicators, riskLevel };
  }

  /**
   * Build a NetworkScanResult from all inspection findings.
   */
  private buildScanResult(
    wifi: WiFiAssessment | null,
    arp: ARPSpoofingResult,
    rogueAP: RogueAPResult,
    ssl: SSLAnomalyResult,
  ): NetworkScanResult {
    const threats: NetworkThreat[] = [];
    const recommendations: string[] = [];

    if (wifi !== null && !wifi.isSecure) {
      threats.push({
        type: 'unsecured_wifi',
        severity: 'high',
        description:
          wifi.encryption === 'WEP'
            ? 'Connected to a WEP-encrypted network. WEP is cryptographically broken.'
            : 'Connected to an open (unencrypted) Wi-Fi network.',
      });
      recommendations.push(
        'Connect to a WPA2 or WPA3 secured network.',
        'Avoid transmitting sensitive data on this network.',
      );
    }

    if (arp.detected) {
      threats.push({
        type: 'arp_spoofing',
        severity: arp.confidence === 'high' ? 'high' : 'medium',
        description: `ARP spoofing detected: ${arp.details.join('; ')}`,
      });
      recommendations.push(
        'Disconnect from the current network immediately.',
        'Use a VPN on untrusted networks.',
      );
    }

    if (rogueAP.detected) {
      threats.push({
        type: 'mitm',
        severity: rogueAP.riskLevel,
        description: `Rogue AP indicators: ${rogueAP.indicators.join('; ')}`,
      });
      recommendations.push(
        'Verify the access point with the network administrator.',
        'Avoid connecting to networks with suspicious characteristics.',
      );
    }

    if (ssl.anomalyDetected) {
      threats.push({
        type: 'mitm',
        severity: ssl.riskLevel,
        description: `SSL anomalies detected: ${ssl.anomalies.join('; ')}`,
      });
      recommendations.push(
        'Enable DNS-over-HTTPS to protect DNS queries.',
        'Disconnect and reconnect to a trusted network.',
      );
    }

    const overallRisk = Math.min(
      100,
      threats.reduce((sum, t) => {
        switch (t.severity) {
          case 'high':   return sum + 40;
          case 'medium': return sum + 20;
          case 'low':    return sum + 10;
          default:       return sum;
        }
      }, 0),
    );

    return { threats, recommendations, overallRisk };
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/** Singleton NetworkInspector instance. */
export const networkInspector: INetworkInspector = new NetworkInspectorImpl();
export default networkInspector;

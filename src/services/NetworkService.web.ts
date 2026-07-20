/**
 * NetworkService.web.ts — Web platform shim for NetworkService.
 *
 * On web, @react-native-community/netinfo is not available.
 * We use the browser's navigator.onLine and the Network Information API
 * (navigator.connection) to provide real network status instead of the
 * "unknown / disconnected" stub.
 *
 * This file is automatically picked up by Metro/Expo's platform-specific
 * resolution: NetworkService.web.ts takes precedence over NetworkService.ts
 * when bundling for web.
 */

import {
  NetworkStatus,
  MITMResult,
  DNSStatus,
  NetworkScanResult,
  NetworkThreat,
  DoHProvider,
} from '../types/index';
import { dohResolver } from './api/DoHResolver';

// ---------------------------------------------------------------------------
// Browser Network Information API types (not in all TS libs)
// ---------------------------------------------------------------------------

interface NetworkInformation {
  effectiveType?: '2g' | '3g' | '4g' | 'slow-2g';
  type?: 'bluetooth' | 'cellular' | 'ethernet' | 'none' | 'wifi' | 'wimax' | 'other' | 'unknown';
  downlink?: number;
  rtt?: number;
}

declare global {
  interface Navigator {
    connection?: NetworkInformation;
    mozConnection?: NetworkInformation;
    webkitConnection?: NetworkInformation;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getConnection(): NetworkInformation | undefined {
  return (
    navigator.connection ??
    navigator.mozConnection ??
    navigator.webkitConnection
  );
}

function getBrowserNetworkType(): NetworkStatus['type'] {
  const conn = getConnection();
  if (!navigator.onLine) return 'none';
  if (!conn || !conn.type) {
    // No Network Information API — assume wifi (most common for web)
    return 'wifi';
  }
  switch (conn.type) {
    case 'wifi':      return 'wifi';
    case 'cellular':  return 'cellular';
    case 'ethernet':  return 'ethernet';
    case 'none':      return 'none';
    default:          return 'wifi'; // wimax, bluetooth, other → treat as wifi
  }
}

const MITM_CHECK_URL = 'https://1.1.1.1';
const MITM_PROBE_TIMEOUT_MS = 5_000;
const AUTO_REFRESH_INTERVAL_MS = 30_000;

// ---------------------------------------------------------------------------
// NetworkService web implementation
// ---------------------------------------------------------------------------

class NetworkServiceWeb {
  private dohEnabled = false;
  private dohProvider: DoHProvider = 'cloudflare';
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private lastDohLatencyMs = 0;

  async getNetworkStatus(): Promise<NetworkStatus> {
    const isConnected = navigator.onLine;
    const type = getBrowserNetworkType();

    // On web over HTTPS we can assume WPA2-equivalent transport security
    const encryption: NetworkStatus['encryption'] =
      isConnected && type !== 'none' ? 'WPA2' : undefined;

    return {
      connected: isConnected,
      type,
      isSecure: isConnected,
      encryption,
      ssid: undefined,
      signalStrength: undefined,
      ipAddress: undefined,
    };
  }

  async isNetworkSecure(): Promise<boolean> {
    return navigator.onLine;
  }

  async detectMITM(): Promise<MITMResult> {
    const indicators: string[] = [];
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), MITM_PROBE_TIMEOUT_MS);

    try {
      const response = await fetch(MITM_CHECK_URL, {
        method: 'HEAD',
        signal: controller.signal,
      });
      if (!response.ok) {
        indicators.push(
          `Unexpected HTTP ${response.status} from certificate probe endpoint`,
        );
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (err instanceof DOMException && err.name === 'AbortError') {
        // Timeout — inconclusive
      } else if (
        message.includes('certificate') ||
        message.includes('SSL') ||
        message.includes('TLS') ||
        message.includes('CERT')
      ) {
        indicators.push('Certificate anomaly detected during SSL probe');
      } else {
        indicators.push(`Network error during MITM probe: ${message}`);
      }
    } finally {
      clearTimeout(timeoutId);
    }

    const detected = indicators.length > 0;
    const riskLevel: MITMResult['riskLevel'] = detected
      ? indicators.some((i) => i.includes('Certificate') || i.includes('ARP'))
        ? 'high'
        : 'medium'
      : 'low';

    return { detected, indicators, riskLevel };
  }

  async configureDNSOverHTTPS(provider: DoHProvider): Promise<void> {
    this.dohProvider = provider;
    this.dohEnabled = true;
    dohResolver.setProvider(provider);
  }

  async getDNSStatus(): Promise<DNSStatus> {
    if (!this.dohEnabled) {
      return { enabled: false, provider: this.dohProvider, latency: 0 };
    }
    const start = Date.now();
    try {
      await dohResolver.resolve('example.com');
      this.lastDohLatencyMs = Date.now() - start;
    } catch {
      this.lastDohLatencyMs = 0;
    }
    return {
      enabled: true,
      provider: this.dohProvider,
      latency: this.lastDohLatencyMs,
    };
  }

  async scanNetwork(): Promise<NetworkScanResult> {
    const [status, mitm] = await Promise.all([
      this.getNetworkStatus(),
      this.detectMITM(),
    ]);

    const threats: NetworkThreat[] = [];
    const recommendations: string[] = [];

    if (mitm.detected) {
      const severity: NetworkThreat['severity'] =
        mitm.riskLevel === 'high' ? 'high' : 'medium';
      threats.push({
        type: 'mitm',
        severity,
        description: `MITM indicators detected: ${mitm.indicators.join('; ')}`,
      });
      recommendations.push(
        'Disconnect from the current network immediately.',
        'Enable DNS-over-HTTPS to protect DNS queries.',
      );
    }

    if (!this.dohEnabled) {
      threats.push({
        type: 'dns_hijack',
        severity: 'medium',
        description:
          'DNS-over-HTTPS is disabled. DNS queries may be intercepted or hijacked.',
      });
      recommendations.push(
        'Enable DNS-over-HTTPS in the Network settings to protect DNS queries.',
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

  startAutoRefresh(): void {
    if (this.refreshTimer !== null) return;
    this.refreshTimer = setInterval(async () => {
      try {
        await this.getNetworkStatus();
      } catch {
        // swallow
      }
    }, AUTO_REFRESH_INTERVAL_MS);
  }

  stopAutoRefresh(): void {
    if (this.refreshTimer !== null) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }
}

export const networkService = new NetworkServiceWeb();
export default networkService;
export type { INetworkService } from './NetworkService';

# Aegis — Personal Cybersecurity Companion

A privacy-first, on-device mobile security app for iOS and Android built with **React Native (Expo SDK 54)** and **TypeScript**. Aegis consolidates six defensive security modules into a single interface, operating under a zero-trust model where all sensitive operations happen on-device.

> **Security standard:** OWASP MASVS Level 2 · AES-256-GCM encryption · Biometric authentication · RASP protection · Certificate pinning

---

## Features

| Module | Description |
|---|---|
| 🔐 **Encrypted Credential Vault** | Store passwords, passkeys, TOTP seeds, and API keys encrypted with AES-256-GCM |
| 🚨 **Real-Time Threat Monitor** | Background anomaly scoring engine with 5 rule-based on-device threat detectors |
| 📡 **Network Safety Analyzer** | Wi-Fi assessment, ARP spoofing detection, rogue AP fingerprinting, SSL anomaly detection |
| 🔍 **Breach Alert Engine** | Monitor emails/usernames against HaveIBeenPwned using k-anonymity |
| 📱 **App Permission Auditor** | Enumerate installed apps, calculate risk scores, identify over-privileged apps |
| 📊 **Security Score Dashboard** | Weighted 0–100 security posture score with actionable recommendations |
| ⚙️ **Settings** | Securely store API keys in device keychain — never in source code |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | React Native 0.81 + Expo SDK 54 |
| Language | TypeScript 5.9 (strict mode, zero `any`) |
| Navigation | Expo Router v6 |
| Crypto | `@noble/hashes` (PBKDF2-SHA256) + `@noble/ciphers` (AES-256-GCM) + `expo-crypto` |
| Storage | `expo-sqlite` (encrypted local DB) + `expo-secure-store` (keychain/keystore) |
| Auth | `expo-local-authentication` (biometrics + PIN) |
| Testing | Jest + jest-expo · **148 tests** |

---

## Prerequisites

| Tool | Version |
|---|---|
| Node.js | ≥ 20.19.4 |
| npm | ≥ 9 |
| Expo Go app | Latest from App Store / Play Store |

For native builds (optional):
- **iOS:** Xcode 16.1+ (macOS only)
- **Android:** Android Studio with SDK 35+

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/ishrakhossain53/aegis_mobile-V.0.0.git
cd aegis_mobile-V.0.0
```

### 2. Install dependencies

```bash
npm install --legacy-peer-deps
```

### 3. Start the development server

```bash
npm start          # interactive Metro menu
npm run web        # open in browser at http://localhost:8081
npm run android    # open on Android emulator
npm run ios        # open on iOS simulator (macOS only)
```

- **Physical device:** scan the QR code with **Expo Go**
- **Android emulator:** press `a` in the Metro terminal
- **iOS simulator:** press `i` (macOS only)
- **Web browser:** press `w` or visit `http://localhost:8081`

### 4. First launch

On first launch you'll be prompted to **create a PIN**. This PIN derives the master encryption key for your vault. Biometric authentication (Face ID / fingerprint) is offered on subsequent launches.

---

## Running Tests

```bash
npm test
```

**148 tests** across 6 suites:

| Suite | What it covers |
|---|---|
| `CryptoService` | Encryption round-trips, k-anonymity hashing |
| `SecureEnclave` | iOS Keychain / Android Keystore abstraction |
| `SecureClipboardService` | Auto-purge timer, timeout configuration |
| `BreachAPI` (PBT) | K-anonymity privacy, no PII in external requests |
| `ThreatIntelAPI` | Caching, fail-open, API key from SecurePrefs |
| `PermissionAuditorService` | Risk scoring, high-risk classification |
| `CloudBackupService` | Encrypted export/import, wrong-key rejection |

---

## Project Structure

```
aegis-mobile-app/
├── src/
│   ├── app/                              # Expo Router screens
│   │   ├── _layout.tsx                   # Root layout — RASP init, store hydration, session lock
│   │   ├── auth.tsx                      # Authentication screen (biometric + PIN)
│   │   └── (tabs)/                       # Protected tab screens
│   │       ├── index.tsx                 # Security Dashboard
│   │       ├── vault.tsx                 # Credential Vault
│   │       ├── network.tsx               # Network Safety (uses Phase 2 NetworkInspector)
│   │       ├── alerts.tsx                # Breach & Threat Alerts
│   │       ├── audit.tsx                 # App Permission Audit
│   │       └── settings.tsx              # API key management (⚙️ gear tab)
│   │
│   ├── components/                       # Reusable UI components
│   │   ├── ScoreRing.tsx                 # Animated security score ring
│   │   ├── SecurityBadge.tsx             # Safe / Warning / Critical pill badge
│   │   ├── CredentialCard.tsx            # Vault credential list item
│   │   ├── ModuleHealthBar.tsx           # Per-module score bar
│   │   ├── AlertItem.tsx                 # Threat / breach alert item
│   │   └── AppRiskCard.tsx               # App permission risk card
│   │
│   ├── services/                         # Phase 1 — business logic & integrations
│   │   ├── AuthService.ts                # Biometric + PIN auth, escalating lockout
│   │   ├── CryptoService.ts              # PBKDF2, AES-256-GCM, k-anonymity
│   │   ├── VaultService.ts               # Encrypted credential CRUD + TOTP (RFC 6238)
│   │   ├── BreachService.ts              # HIBP breach monitoring
│   │   ├── NetworkService.ts             # Wi-Fi security, MITM detection, DoH routing
│   │   ├── ThreatMonitorService.ts       # 60s polling threat monitor
│   │   ├── SecurityScoreService.ts       # Weighted 0–100 aggregate score
│   │   ├── PermissionAuditorService.ts   # App risk scoring (0–100)
│   │   ├── SecureClipboardService.ts     # Auto-purge clipboard (10–60s)
│   │   ├── CloudBackupService.ts         # Optional encrypted backup/restore
│   │   ├── RASPGuard.ts                  # Re-exports src/rasp/RASPGuard (Phase 2)
│   │   ├── SessionLockService.ts         # Auto-lock on inactivity (30–300s)
│   │   ├── SecureEnclave.ts              # iOS Keychain / Android Keystore abstraction
│   │   ├── SecurePrefs.ts                # Typed secure preferences
│   │   └── api/
│   │       ├── BreachAPI.ts              # HaveIBeenPwned v3 client (k-anonymity)
│   │       ├── ThreatIntelAPI.ts         # VirusTotal reputation client (canonical)
│   │       └── DoHResolver.ts            # DNS-over-HTTPS (Cloudflare / Google / Quad9)
│   │
│   ├── modules/                          # Phase 2 — feature modules
│   │   ├── threat/
│   │   │   ├── ThreatAgent.ts            # Background headless task + anomaly scoring engine
│   │   │   └── ThreatStore.ts            # Reactive store → encrypted SQLite write-through
│   │   └── network/
│   │       ├── NetworkInspector.ts       # ARP spoofing, rogue AP fingerprinting, SSL anomaly
│   │       └── NetworkStore.ts           # Reactive store with offline SQLite cache
│   │
│   ├── api/                              # Phase 2 — re-export shims (point to services/api/)
│   │   ├── certificatePinning.ts         # pinnedFetch interceptor (HTTPS-only + host allowlist)
│   │   ├── ThreatIntelAPI.ts             # Re-exports from services/api/ThreatIntelAPI
│   │   └── DoHResolver.ts                # Re-exports from services/api/DoHResolver
│   │
│   ├── rasp/                             # Phase 2 — enhanced RASP guard
│   │   └── RASPGuard.ts                  # Vault/crypto op gating + JS runtime tamper detection
│   │
│   ├── database/
│   │   ├── DatabaseService.ts            # expo-sqlite CRUD + transactions
│   │   └── DatabaseService.web.ts        # In-memory stub for web platform
│   ├── types/
│   │   └── index.ts                      # All shared TypeScript interfaces
│   └── theme/
│       └── colors.ts                     # Semantic color tokens
│
├── .kiro/specs/aegis-mobile-app/         # Spec-driven development docs
│   ├── requirements.md
│   ├── design.md
│   └── tasks.md
├── app.json                              # Expo app configuration
├── babel.config.js
├── tsconfig.json
└── package.json
```

---

## API Keys (Optional)

Some features require external API keys. These are **never hardcoded** — enter them in the **Settings** tab (⚙️) at runtime. They are stored in the device keychain via `expo-secure-store`.

| Feature | Key name | Where to get it |
|---|---|---|
| Breach monitoring | `hibp_api_key` | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| Threat intelligence | `threat_intel_api_key` | [virustotal.com](https://www.virustotal.com) |

The app functions fully without these keys — breach checking and threat intel lookups degrade gracefully.

---

## Building for Production

### Using EAS Build (recommended)

```bash
npm install -g eas-cli
eas login
eas build:configure

eas build --platform android   # Android AAB
eas build --platform ios       # iOS IPA (macOS only)
```

### Local builds

```bash
npx expo run:android --variant release
npx expo run:ios --configuration Release   # macOS only
```

> **Note:** Production builds enforce the full RASP checks including bundle ID verification (`com.aegis.cybersecurity`). Update `EXPECTED_BUNDLE_ID` in `src/rasp/RASPGuard.ts` if you change the bundle identifier.

---

## Security Architecture

### Encryption
- All vault data encrypted with **AES-256-GCM** before storage
- Master key derived via **PBKDF2-SHA256** (100,000 iterations)
- Unique IV generated per encryption operation — never reused
- Authentication tag verified on every decryption

### Key Storage
- Master key salt stored in **iOS Keychain / Android Keystore** via `expo-secure-store`
- PIN stored as **SHA-256 hash** only — never plaintext
- All API keys stored exclusively in the secure enclave via the Settings screen

### Privacy
- Breach checks use **k-anonymity** — only the first 5 chars of a SHA-1 hash are sent to HIBP
- No plaintext PII ever leaves the device
- DNS queries routed through **DNS-over-HTTPS** when enabled
- All external API payloads are anonymized — no user data transmitted

### RASP — Phase 1 (`src/services/RASPGuard.ts` → `src/rasp/RASPGuard.ts`)
- Debugger attachment detection (production only)
- Emulator / simulator detection
- Root / jailbreak detection via `expo-device`
- Bundle ID integrity verification

### RASP — Phase 2 enhancements (`src/rasp/RASPGuard.ts`)
- **`gateVaultOperation()`** — throws on any integrity failure before vault access
- **`gateCryptoOperation()`** — throws on any integrity failure before crypto ops
- **`detectTampering()`** — `Array.prototype.push` reference check + `JSON.parse`/`JSON.stringify` round-trip integrity

### Certificate Pinning (`src/api/certificatePinning.ts`)
- All external requests go through `pinnedFetch` — a drop-in `fetch` replacement
- HTTPS-only enforcement — HTTP requests rejected unconditionally
- Host allowlist — requests to unpinned hosts rejected before any connection
- Pinned: `www.virustotal.com`, `haveibeenpwned.com`, `cloudflare-dns.com`, `dns.google`, `dns.quad9.net`
- Full certificate fingerprint validation via `react-native-ssl-pinning` when installed

### Network Inspection — Phase 2 (`src/modules/network/NetworkInspector.ts`)
- **ARP spoofing** — gateway IP consistency + HTTP redirect anomaly checks
- **Rogue AP fingerprinting** — BSSID / SSID / signal / frequency heuristics
- **SSL anomaly detection** — parallel HTTPS probes to known-good endpoints
- Results persisted to encrypted offline cache via `NetworkStore`

### Background Threat Agent — Phase 2 (`src/modules/threat/ThreatAgent.ts`)
- Runs as a headless background task via `expo-task-manager`
- Five anomaly rules: device compromise, code signature, debugger, emulator, network activity
- Aggregate score = `max(rule contributions)` — no double-counting
- All telemetry is on-device only — nothing transmitted externally

---

## Known Limitations (Expo Go)

| Feature | Expo Go (dev) | Production (EAS Build) |
|---|---|---|
| RASP bundle ID check | Skipped (`host.exp.exponent`) | Enforced (`com.aegis.cybersecurity`) |
| RASP debugger check | Skipped (`__DEV__ = true`) | Enforced |
| SQLite encryption | Unencrypted (SQLCipher needs native build) | AES-256 encrypted |
| Certificate pinning | Hostname-only (no native SSL module) | Full fingerprint via `react-native-ssl-pinning` |
| Background tasks | Not available | Registered via `expo-task-manager` |

---

## Branch Strategy

| Branch | Purpose |
|---|---|
| `main` | Stable releases — only merge from `Releases` when ready |
| `Releases` | Active development — all new features and fixes go here |

```bash
# All new work on Releases
git checkout Releases

# When ready to release
git checkout main
git merge Releases --no-ff -m "release: vX.X.X"
git push origin main
git push origin Releases
```

---

## Contributing

1. Fork the repository
2. Branch off `Releases`: `git checkout -b feature/my-feature Releases`
3. Run tests: `npm test`
4. Check types: `node_modules/.bin/tsc --noEmit --project tsconfig.json`
5. Commit and push, then open a PR targeting `Releases`

All 148 tests must pass and `tsc --noEmit` must report zero errors.

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [HaveIBeenPwned](https://haveibeenpwned.com) by Troy Hunt — breach data API
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) — audited pure-JS cryptography
- [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) — audited pure-JS AES-GCM
- [Expo](https://expo.dev) — React Native toolchain

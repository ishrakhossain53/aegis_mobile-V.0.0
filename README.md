# Aegis — Personal Cybersecurity Companion

A privacy-first, on-device mobile security app for iOS and Android built with **React Native (Expo SDK 54)** and **TypeScript**. Aegis consolidates six defensive security modules into a single interface, operating under a zero-trust model where all sensitive operations happen on-device.

> **Security standard:** OWASP MASVS Level 2 · AES-256-GCM encryption · Biometric authentication · RASP protection · Certificate pinning

---

## Features

| Module | Description |
|---|---|
| 🔐 **Encrypted Credential Vault** | Store passwords and API keys encrypted with AES-256-GCM. Credentials are decrypted on demand — never stored in plaintext |
| 🚨 **Real-Time Threat Monitor** | Background anomaly scoring engine with 5 rule-based on-device threat detectors |
| 📡 **Network Safety Analyzer** | Wi-Fi assessment, ARP spoofing detection, rogue AP fingerprinting, SSL anomaly detection |
| 🔍 **Breach Alert Engine** | Monitor emails/usernames against HaveIBeenPwned using k-anonymity |
| 📱 **App Permission Auditor** | Enumerate installed apps, calculate risk scores, identify over-privileged apps |
| 📊 **Security Score Dashboard** | Weighted 0–100 security posture score with actionable recommendations |
| 🌙 **Dark / Light Theme** | Full dark and light mode with system preference detection and persistent user choice |
| ⚙️ **Settings** | Theme toggle + securely store API keys in device keychain — never in source code |

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
| Network | `@react-native-community/netinfo` (Wi-Fi / cellular status) |
| Theme | React Context (`ThemeContext`) with dark/light palettes, persisted to secure storage |
| Testing | Jest + jest-expo + @testing-library/react-native · **378 tests** |

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

Run with `--clear` on first launch to bust the Metro cache:

```bash
npx expo start --clear
```

Subsequent launches:

```bash
npm start          # interactive Metro menu (choose platform after)
npm run web        # open in browser at http://localhost:8081
npm run android    # open on Android emulator / device
npm run ios        # open on iOS simulator (macOS only)
```

- **Physical device:** scan the QR code with **Expo Go**
- **Android emulator:** press `a` in the Metro terminal
- **iOS simulator:** press `i` (macOS only)
- **Web browser:** press `w` or visit `http://localhost:8081`

### 4. Stop the development server

Press **`Ctrl + C`** in the terminal where Metro is running.

If the process is still running in the background:

```bash
lsof -ti :8081 | xargs kill -9
```

To clear the Metro cache and restart fresh:

```bash
npx expo start --clear
```

### 5. First launch

On first launch you'll be prompted to **create a PIN**. This PIN derives the master encryption key for your vault. Biometric authentication (Face ID / fingerprint) is offered on subsequent launches.

---

## Running Tests

```bash
npm test
```

**378 tests** across 17 suites:

| Suite | Tests | What it covers |
|---|---|---|
| `CryptoService` | 22 | PBKDF2 key derivation, AES-256-GCM encrypt/decrypt, wrong-key rejection, k-anonymity |
| `SecureEnclave` | 12 | iOS Keychain / Android Keystore abstraction |
| `SecureClipboardService` | 34 | Auto-purge timer, configurable timeout, UI callbacks |
| `SessionLockService` | 22 | Auto-lock at 60s, configurable 30–300s, resetTimer, lock events |
| `VaultService` | 28 | Credential CRUD, encryption, UUID assignment, TOTP, search |
| `SecurityScoreService` | 26 | Weighted score, level classification, recommendations, history |
| `PermissionAuditorService` | 40 | Risk scoring, permission categorization, high-risk classification |
| `CloudBackupService` | 22 | Encrypted export/import, wrong-key rejection, malformed payload |
| `BreachAPI` (PBT) | 18 | K-anonymity privacy — no PII in any external request |
| `ThreatIntelAPI` | 30 | Caching, fail-open, API key from SecurePrefs |
| `ThemeContext` | 28 | Dark/light palettes, toggle, persistence, color values |
| `SecurityBadge` | 11 | Label rendering, color per status, accessibility |
| `AlertItem` | 13 | Severity badge, dismiss button, resolved state, accessibility |
| `ModuleHealthBar` | 14 | Score rendering, color thresholds, clamping, onPress |
| `AppRiskCard` | 13 | App info, permission counts, badge mapping, onPress |
| `ScoreRing` | 12 | Score rendering, color thresholds, clamping, accessibility |
| `CredentialCard` | 14 | Rendering, **security: never renders plaintext secrets**, copy, press |

All tests must pass and `tsc --noEmit` must report zero errors before any push.

---

## Project Structure

```
aegis-mobile-app/
├── src/
│   ├── app/                              # Expo Router screens
│   │   ├── _layout.tsx                   # Root layout — ThemeProvider, RASP init, session lock
│   │   ├── auth.tsx                      # Authentication screen (biometric + PIN)
│   │   └── (tabs)/                       # Protected tab screens
│   │       ├── _layout.tsx               # Tab bar — theme-aware (dark/light tab bar colors)
│   │       ├── index.tsx                 # Security Dashboard
│   │       ├── vault.tsx                 # Credential Vault (passwords + API keys)
│   │       ├── network.tsx               # Network Safety
│   │       ├── alerts.tsx                # Breach & Threat Alerts
│   │       ├── audit.tsx                 # App Permission Audit
│   │       └── settings.tsx              # Theme toggle + API key management
│   │
│   ├── components/                       # Reusable UI components
│   │   ├── ScoreRing.tsx                 # Animated security score ring
│   │   ├── SecurityBadge.tsx             # Safe / Warning / Critical pill badge
│   │   ├── CredentialCard.tsx            # Vault credential list item
│   │   ├── ModuleHealthBar.tsx           # Per-module score bar
│   │   ├── AlertItem.tsx                 # Threat / breach alert item
│   │   ├── AppRiskCard.tsx               # App permission risk card
│   │   └── __tests__/                    # Component unit tests
│   │
│   ├── services/                         # Business logic & integrations
│   │   ├── AuthService.ts                # Biometric + PIN auth, escalating lockout
│   │   ├── CryptoService.ts              # PBKDF2, AES-256-GCM, k-anonymity
│   │   ├── VaultService.ts               # Encrypted credential CRUD + TOTP (RFC 6238)
│   │   ├── BreachService.ts              # HIBP breach monitoring
│   │   ├── NetworkService.ts             # Wi-Fi security, MITM detection, DoH routing
│   │   ├── NetworkService.web.ts         # Web platform shim
│   │   ├── ThreatMonitorService.ts       # 60s polling threat monitor
│   │   ├── SecurityScoreService.ts       # Weighted 0–100 aggregate score
│   │   ├── PermissionAuditorService.ts   # App risk scoring (0–100)
│   │   ├── SecureClipboardService.ts     # Auto-purge clipboard (10–60s)
│   │   ├── CloudBackupService.ts         # Optional encrypted backup/restore
│   │   ├── SessionLockService.ts         # Auto-lock on inactivity (30–300s)
│   │   ├── SecureEnclave.ts              # iOS Keychain / Android Keystore abstraction
│   │   ├── SecurePrefs.ts                # Typed secure preferences (incl. theme_mode)
│   │   └── api/
│   │       ├── BreachAPI.ts              # HaveIBeenPwned v3 client (k-anonymity)
│   │       ├── ThreatIntelAPI.ts         # VirusTotal reputation client
│   │       └── DoHResolver.ts            # DNS-over-HTTPS (Cloudflare / Google / Quad9)
│   │
│   ├── modules/                          # Phase 2 feature modules
│   │   ├── threat/
│   │   │   ├── ThreatAgent.ts            # Background headless task + anomaly scoring
│   │   │   └── ThreatStore.ts            # Reactive store → encrypted SQLite write-through
│   │   └── network/
│   │       ├── NetworkInspector.ts       # ARP spoofing, rogue AP, SSL anomaly detection
│   │       └── NetworkStore.ts           # Reactive store with offline SQLite cache
│   │
│   ├── rasp/
│   │   └── RASPGuard.ts                  # Vault/crypto op gating + JS runtime tamper detection
│   │
│   ├── database/
│   │   ├── DatabaseService.ts            # expo-sqlite CRUD + transactions
│   │   └── DatabaseService.web.ts        # In-memory stub for web platform
│   │
│   ├── types/
│   │   └── index.ts                      # All shared TypeScript interfaces
│   │
│   └── theme/
│       ├── colors.ts                     # Dark + light theme palettes (ThemeColors interface)
│       └── ThemeContext.tsx              # ThemeProvider + useTheme() hook
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

## Dark / Light Theme

Aegis supports full dark and light mode:

- **Auto-detect:** defaults to the device's system color scheme on first launch
- **Manual toggle:** switch in **Settings → Appearance** using the 🌙 / ☀️ toggle
- **Persistent:** preference is saved to the device keychain and restored on next launch
- **Reactive:** all screens, the tab bar, and modals update instantly when the theme changes

The theme system is built on React Context (`ThemeContext`) with two complete palettes defined in `src/theme/colors.ts`. All screens consume colors via the `useTheme()` hook — no hardcoded hex values in screen files.

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
- Master key derived via **PBKDF2-SHA256** (100,000 iterations in production, 1,000 in dev)
- Unique IV generated per encryption operation — never reused
- Authentication tag verified on every decryption

### Key Storage
- Master key salt stored in **iOS Keychain / Android Keystore** via `expo-secure-store`
- PIN stored as **SHA-256 hash** only — never plaintext
- All API keys and theme preference stored exclusively in the secure enclave

### Privacy
- Breach checks use **k-anonymity** — only the first 5 chars of a SHA-1 hash are sent to HIBP
- No plaintext PII ever leaves the device
- DNS queries routed through **DNS-over-HTTPS** when enabled
- All external API payloads are anonymized — no user data transmitted

### Session Security
- Auto-lock after **60 seconds of inactivity** by default (configurable 30–300s)
- Every user interaction resets the inactivity timer
- On lock, the master key is cleared from memory and re-authentication is required

### RASP Protection
- Debugger attachment detection (production only)
- Emulator / simulator detection
- Root / jailbreak detection via `expo-device`
- Bundle ID integrity verification
- `gateVaultOperation()` / `gateCryptoOperation()` — throw on any integrity failure
- JS runtime tamper detection (`Array.prototype.push` reference check)

### Certificate Pinning (`src/api/certificatePinning.ts`)
- All external requests go through `pinnedFetch` — HTTPS-only enforcement
- Host allowlist — requests to unpinned hosts rejected before any connection
- Pinned hosts: `www.virustotal.com`, `haveibeenpwned.com`, `cloudflare-dns.com`, `dns.google`, `dns.quad9.net`

---

## Troubleshooting

### Vault shows empty after saving credentials

This was a known bug (fixed in the current version). The root cause was `AuthService` not calling `vaultService.setMasterKey()` after successful authentication. If you're on an older version, pull the latest from `Releases`.

### Network screen shows "Disconnected / Unknown / NONE"

```bash
npx expo install @react-native-community/netinfo
npm start -- --clear
```

### Metro bundler port already in use

```bash
lsof -ti :8081 | xargs kill -9
npm start
```

### Dependency conflicts on install

```bash
npm install --legacy-peer-deps
```

### TypeScript errors after pulling changes

```bash
npx tsc --noEmit
```

### Tests failing

```bash
# Run a single suite to isolate the failure
npx jest src/services/CryptoService.test.ts --verbose

# Clear Jest cache
npx jest --clearCache && npm test
```

---

## Expo Go vs Production Build

| Feature | Expo Go (dev) | Production (EAS Build) |
|---|---|---|
| RASP bundle ID check | Skipped (`host.exp.exponent`) | Enforced (`com.aegis.cybersecurity`) |
| RASP debugger check | Skipped (`__DEV__ = true`) | Enforced |
| SQLite encryption | Unencrypted (SQLCipher needs native build) | AES-256 encrypted |
| Certificate pinning | Hostname-only (no native SSL module) | Full fingerprint via `react-native-ssl-pinning` |
| Background tasks | Not available | Registered via `expo-task-manager` |
| PBKDF2 iterations | 1,000 (dev speed) | 100,000 (production security) |

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
3. Run tests: `npm test` — all 378 must pass
4. Check types: `npx tsc --noEmit` — must report zero errors
5. Commit and push, then open a PR targeting `Releases`

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [HaveIBeenPwned](https://haveibeenpwned.com) by Troy Hunt — breach data API
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) — audited pure-JS cryptography
- [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) — audited pure-JS AES-GCM
- [Expo](https://expo.dev) — React Native toolchain

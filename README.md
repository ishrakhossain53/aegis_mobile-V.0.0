# Aegis — Personal Cybersecurity Companion

A privacy-first, on-device mobile security app for iOS and Android built with **React Native (Expo SDK 54)** and **TypeScript**. Aegis consolidates six defensive security modules into a single interface, operating under a zero-trust model where all sensitive operations happen on-device.

> **Security standard:** OWASP MASVS Level 2 · AES-256-GCM encryption · Biometric authentication · RASP protection

---

## Features

| Module | Description |
|---|---|
| 🔐 **Encrypted Credential Vault** | Store passwords, passkeys, TOTP seeds, and API keys encrypted with AES-256-GCM |
| 🚨 **Real-Time Threat Monitor** | Background monitoring for rootkits, jailbreaks, and suspicious activity |
| 📡 **Network Safety Analyzer** | Wi-Fi security classification, MITM detection, DNS-over-HTTPS routing |
| 🔍 **Breach Alert Engine** | Monitor emails/usernames against HaveIBeenPwned using k-anonymity |
| 📱 **App Permission Auditor** | Enumerate installed apps, calculate risk scores, identify over-privileged apps |
| 📊 **Security Score Dashboard** | Weighted 0–100 security posture score with actionable recommendations |

---

## Tech Stack

- **Framework:** React Native 0.81 + Expo SDK 54
- **Language:** TypeScript (strict mode)
- **Navigation:** Expo Router v6
- **Crypto:** `@noble/hashes` (PBKDF2-SHA256) + `@noble/ciphers` (AES-256-GCM) + `expo-crypto`
- **Storage:** `expo-sqlite` (local DB) + `expo-secure-store` (keychain/keystore)
- **Auth:** `expo-local-authentication` (biometrics + PIN)
- **Testing:** Jest + jest-expo (148 tests)

---

## Prerequisites

| Tool | Version |
|---|---|
| Node.js | ≥ 20.19.4 |
| npm | ≥ 9 |
| Expo CLI | latest (`npm install -g expo-cli`) |
| Expo Go app | Latest from App Store / Play Store |

For native builds (optional):
- **iOS:** Xcode 16.1+ (macOS only)
- **Android:** Android Studio with SDK 35+

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/aegis-mobile-app.git
cd aegis-mobile-app
```

### 2. Install dependencies

```bash
npm install --legacy-peer-deps
```

### 3. Start the development server

```bash
npx expo start
```

Then:
- **Android/iOS device:** Scan the QR code with the **Expo Go** app
- **Android emulator:** Press `a`
- **iOS simulator:** Press `i` (macOS only)

### 4. First launch

On first launch you'll be prompted to **create a PIN**. This PIN is used to derive the master encryption key for your vault. Biometric authentication (fingerprint/Face ID) is offered on subsequent launches.

---

## Running Tests

```bash
npm test
```

Runs 148 tests across 6 test suites covering:
- Cryptography (encryption round-trips, k-anonymity)
- Secure storage (SecureEnclave, SecurePrefs)
- Breach API (k-anonymity privacy, PII audit)
- Clipboard (auto-purge, timeout config)
- Permission auditor (risk scoring, classification)
- Cloud backup (encrypted export/import, wrong-key rejection)

---

## Project Structure

```
aegis-mobile-app/
├── src/
│   ├── app/                    # Expo Router screens
│   │   ├── _layout.tsx         # Root layout (RASP init, session lock)
│   │   ├── auth.tsx            # Authentication screen
│   │   └── (tabs)/             # Protected tab screens
│   │       ├── index.tsx       # Security Dashboard
│   │       ├── vault.tsx       # Credential Vault
│   │       ├── network.tsx     # Network Safety
│   │       ├── alerts.tsx      # Breach & Threat Alerts
│   │       └── audit.tsx       # App Permission Audit
│   ├── components/             # Reusable UI components
│   │   ├── ScoreRing.tsx       # Animated security score ring
│   │   ├── SecurityBadge.tsx   # Safe/Warning/Critical badge
│   │   ├── CredentialCard.tsx  # Vault credential list item
│   │   ├── ModuleHealthBar.tsx # Per-module score bar
│   │   ├── AlertItem.tsx       # Threat/breach alert item
│   │   └── AppRiskCard.tsx     # App permission risk card
│   ├── services/               # Business logic & integrations
│   │   ├── AuthService.ts      # Biometric + PIN auth, lockout
│   │   ├── CryptoService.ts    # PBKDF2, AES-256-GCM, k-anonymity
│   │   ├── VaultService.ts     # Encrypted credential CRUD
│   │   ├── BreachService.ts    # HIBP breach monitoring
│   │   ├── NetworkService.ts   # Wi-Fi security, MITM detection
│   │   ├── ThreatMonitorService.ts  # Background threat monitoring
│   │   ├── SecurityScoreService.ts  # Aggregate security score
│   │   ├── PermissionAuditorService.ts  # App risk scoring
│   │   ├── SecureClipboardService.ts    # Auto-purge clipboard
│   │   ├── CloudBackupService.ts        # Encrypted backup/restore
│   │   ├── RASPGuard.ts        # Runtime self-protection
│   │   ├── SessionLockService.ts  # Auto-lock on inactivity
│   │   ├── SecureEnclave.ts    # iOS Keychain / Android Keystore
│   │   ├── SecurePrefs.ts      # Typed secure preferences
│   │   └── api/
│   │       ├── BreachAPI.ts    # HaveIBeenPwned v3 client
│   │       ├── ThreatIntelAPI.ts  # VirusTotal reputation client
│   │       └── DoHResolver.ts  # DNS-over-HTTPS (Cloudflare/Google/Quad9)
│   ├── database/
│   │   └── DatabaseService.ts  # expo-sqlite CRUD + transactions
│   ├── types/
│   │   └── index.ts            # Shared TypeScript interfaces
│   └── theme/
│       └── colors.ts           # Semantic color tokens
├── app.json                    # Expo app configuration
├── babel.config.js
├── tsconfig.json
└── package.json
```

---

## API Keys (Optional Features)

Some features require external API keys. These are **never hardcoded** — store them in the app via `SecurePrefs` at runtime:

| Feature | Key | Where to get it |
|---|---|---|
| Breach monitoring | `hibp_api_key` | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| Threat intelligence | `threat_intel_api_key` | [virustotal.com](https://www.virustotal.com) |

The app functions fully without these keys — breach checking and threat intel lookups will be skipped.

---

## Building for Production

### Using EAS Build (recommended)

```bash
# Install EAS CLI
npm install -g eas-cli

# Log in to Expo
eas login

# Configure the project
eas build:configure

# Build for Android
eas build --platform android

# Build for iOS
eas build --platform ios
```

### Local builds

```bash
# Android APK/AAB
npx expo run:android --variant release

# iOS (macOS only)
npx expo run:ios --configuration Release
```

> **Note:** Production builds enforce the full RASP checks including bundle ID verification (`com.aegis.cybersecurity`) and debugger detection. Update `EXPECTED_BUNDLE_ID` in `RASPGuard.ts` if you change the bundle identifier.

---

## Security Architecture

### Encryption
- All vault data encrypted with **AES-256-GCM** before storage
- Master key derived via **PBKDF2-SHA256** (100,000 iterations in production, 1,000 in dev)
- Unique IV generated per encryption operation
- Authentication tag verified on every decryption

### Key Storage
- Master key salt stored in **iOS Keychain / Android Keystore** via `expo-secure-store`
- PIN stored as **SHA-256 hash** only — never plaintext
- API keys stored exclusively in secure enclave

### Privacy
- Breach checks use **k-anonymity** — only the first 5 chars of a SHA-1 hash are sent to HIBP
- No plaintext PII ever leaves the device
- DNS queries routed through **DNS-over-HTTPS** when enabled

### Runtime Protection (RASP)
- Debugger attachment detection (disabled in `__DEV__` mode)
- Emulator/simulator detection
- Root/jailbreak detection via `expo-device`
- Bundle ID integrity verification (disabled in Expo Go / dev builds)

---

## Known Limitations (Expo Go)

When running in **Expo Go** (development), some security features are intentionally relaxed:

- RASP bundle ID check is **skipped** (Expo Go uses `host.exp.exponent`)
- PBKDF2 uses **1,000 iterations** instead of 100,000 to avoid blocking the JS thread
- SQLite database is **not encrypted** (SQLCipher requires a custom native build)

These limitations do not apply to production builds created with EAS Build or `npx expo run`.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Run tests: `npm test`
4. Commit your changes: `git commit -m 'Add my feature'`
5. Push and open a pull request

Please ensure all 148 tests pass before submitting a PR.

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [HaveIBeenPwned](https://haveibeenpwned.com) by Troy Hunt — breach data API
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) — audited pure-JS cryptography
- [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) — audited pure-JS AES-GCM
- [Expo](https://expo.dev) — React Native toolchain

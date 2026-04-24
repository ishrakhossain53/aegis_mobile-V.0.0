# Implementation Plan: Aegis Personal Cybersecurity Companion

## Overview

Incremental implementation of the Aegis React Native (Expo SDK + TypeScript) app across six security modules. Each task builds on the previous, starting with the foundational type system and cryptography core, then layering services, UI components, and screens. All sensitive operations use AES-256-GCM encryption, biometric auth, and RASP protection per OWASP MASVS Level 2.

## Tasks

- [x] 1. Define shared TypeScript types and theme foundation
  - Create `src/types/index.ts` exporting all shared interfaces: `Credential`, `Threat`, `MonitoredIdentity`, `InstalledApp`, `AppPermission`, `SecurityScore`, `BreachInfo`, `NetworkStatus`, `UserSettings`, and all supporting types (`AuthResult`, `BiometricCapability`, `EncryptedData`, `KAnonymityResult`, `TOTPCode`, `ThreatLevel`, `MITMResult`, `DNSStatus`, `NetworkScanResult`, `BreachResult`, `AuditReport`, `ScoreBreakdown`, `Recommendation`, `IntegrityCheckResult`, `RASPResult`, `QueryResult`)
  - Use strict TypeScript with no `any` in exported types
  - Create `src/theme/colors.ts` with all semantic status tokens (`safe`, `warning`, `danger`, `neutral`), background hierarchy tokens, text hierarchy tokens, `statusColors` map, `scoreGradient`, and interactive state colors
  - _Requirements: 24.1, 24.2, 24.3, 24.4, 25.1, 25.2, 25.3_

- [x] 2. Implement Cryptography Core
  - [x] 2.1 Create `src/services/CryptoService.ts` implementing `ICryptographyService`
    - Implement PBKDF2 key derivation with 100,000 iterations using `expo-crypto` / `react-native-quick-crypto`
    - Implement AES-256-GCM encrypt/decrypt with authenticated encryption
    - Implement `generateSalt()` (32 bytes) and `generateIV()` (12 bytes) using CSPRNG
    - Implement `kAnonymityHash(email)` returning first 5 uppercase hex chars of SHA-1 hash
    - _Requirements: 3.1, 3.2, 3.3, 3.5, 3.6_

  - [ ]* 2.2 Write property test for encryption round-trip
    - **Property 1: Encryption Round-Trip** — for any valid plaintext string, `encrypt` then `decrypt` with the same key returns the original plaintext
    - **Validates: Requirements 3.4**

  - [ ]* 2.3 Write property test for unique initialization vectors
    - **Property 2: Unique Initialization Vectors** — for any two `encrypt` calls, the IVs in the resulting `EncryptedData` objects are distinct
    - **Validates: Requirements 3.6**

  - [ ]* 2.4 Write property test for k-anonymity prefix correctness
    - **Property 3: K-Anonymity Prefix Correctness** — for any input string, `kAnonymityHash` returns exactly 5 uppercase hex characters equal to the first 5 chars of the SHA-1 hash
    - **Validates: Requirements 3.5, 9.1, 15.2**

- [x] 3. Implement Secure Enclave and Secure Preferences
  - [x] 3.1 Create `src/services/SecureEnclave.ts` abstracting iOS Keychain / Android Keystore via `expo-secure-store`
    - Expose unified `store(key, value)`, `retrieve(key): string | null`, `remove(key)` interface
    - Never write raw key material to AsyncStorage or unencrypted storage
    - Return `null` (not throw) when a key does not exist
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5_

  - [x] 3.2 Create `src/services/SecurePrefs.ts` providing typed get/set/delete for all secure preference keys
    - Store PIN hash, biometric enabled flag, and third-party API keys exclusively via `SecureEnclave`
    - Return `null` (not throw) on missing key; complete silently on delete of missing key
    - Never persist any value to AsyncStorage
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5_

- [x] 4. Implement Database Service
  - [x] 4.1 Create `src/database/DatabaseService.ts` implementing `IDatabaseService`
    - Initialize SQLCipher-encrypted database via `expo-sqlite` keyed by `Master_Key`
    - Create all tables: `credentials`, `threats`, `monitored_identities`, `security_scores`, `user_settings` with schema constraints and indexes from the design
    - Implement `execute`, `insert`, `update`, `delete`, `select` methods
    - Implement `beginTransaction`, `commit`, `rollback` for atomic operations
    - Enforce schema constraints: credential type enum, monitored identity type enum, score range 0–100
    - _Requirements: 14.1, 14.2, 14.3, 14.5, 14.6, 14.7_

  - [ ]* 4.2 Write property test for database transaction atomicity
    - **Property 24: Database Transaction Atomicity** — for any multi-step transaction that fails mid-execution, the database state after rollback is identical to the state before the transaction began
    - **Validates: Requirements 14.3, 14.4**

- [x] 5. Implement RASP Guard
  - [x] 5.1 Create `src/services/RASPGuard.ts` implementing `IRASPGuard`
    - Implement `isDebuggerAttached()`, `isRunningOnEmulator()`, `isDeviceCompromised()` checks
    - Implement `verifyCodeSignature()` using app bundle integrity verification
    - Implement `preOperationCheck()` running all checks and returning `RASPResult`
    - Block and return denial result when any check fails; log violations with timestamp and type
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

  - [ ]* 5.2 Write property test for RASP operation blocking
    - **Property 11: RASP Operation Blocking** — for any sensitive operation requested while `preOperationCheck` returns a failure, the operation is denied and does not execute
    - **Validates: Requirements 7.5**

- [x] 6. Implement Authentication and Session Management
  - [x] 6.1 Create `src/services/AuthService.ts` implementing `IAuthenticationService`
    - Integrate `expo-local-authentication` for biometric (Face ID / Touch ID / fingerprint)
    - Implement PIN setup (`setupPIN`) and verification (`verifyPIN`) storing PIN hash via `SecurePrefs`
    - Implement escalating lockout: 3 attempts → 30s, 5 attempts → 5min, 10 attempts → permanent
    - Reset failed attempt counter on successful authentication
    - Derive `Master_Key` via `CryptoService.deriveMasterKey` on successful auth; unlock `DatabaseService`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

  - [x] 6.2 Create `src/services/SessionLockService.ts` implementing `ISessionLockService`
    - Auto-lock after 60s idle (configurable 30–300s via `UserSettings`)
    - Clear sensitive data from memory on lock
    - Require re-authentication via `AuthService` after lock
    - Reset inactivity timer on user interaction
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [x] 7. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Implement Encrypted Credential Vault (F1)
  - [x] 8.1 Create `src/services/VaultService.ts` implementing `IVaultService`
    - Encrypt sensitive fields (password, passkey, totpSeed, apiKey, notes) with `Master_Key` before persisting
    - Assign UUID v4 on `addCredential`; validate title non-empty and at least one secret field present
    - Decrypt all encrypted fields on `getCredential` / `getAllCredentials`
    - Implement `searchCredentials` matching query against title, username, URL, and tags
    - Implement `deleteCredential` with permanent removal; update `lastUsed` timestamp on every access
    - Implement `generateTOTP` per RFC 6238 (6-digit, 30s window)
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10_

  - [ ]* 8.2 Write property test for credential storage round-trip
    - **Property 4: Credential Storage Round-Trip** — for any valid `Credential`, adding then retrieving by ID returns a credential with decrypted fields equal to the original
    - **Validates: Requirements 4.1, 4.9**

  - [ ]* 8.3 Write property test for credential UUID uniqueness
    - **Property 5: Credential UUID Uniqueness** — for any sequence of added credentials, all assigned IDs are valid UUID v4 strings and are mutually distinct
    - **Validates: Requirements 4.2**

  - [ ]* 8.4 Write property test for credential validation invariant
    - **Property 6: Credential Validation Invariant** — for any credential missing all of password, passkey, totpSeed, and apiKey, `addCredential` rejects it and does not persist it
    - **Validates: Requirements 4.4**

  - [ ]* 8.5 Write property test for credential search correctness
    - **Property 7: Credential Search Correctness** — for any non-empty query, every result contains the query in title/username/URL/tags, and no matching credential is omitted
    - **Validates: Requirements 4.7**

  - [ ]* 8.6 Write property test for credential deletion completeness
    - **Property 8: Credential Deletion Completeness** — after deleting a credential by ID, retrieving that ID returns null
    - **Validates: Requirements 4.8**

- [x] 9. Implement Secure Clipboard Manager
  - Create `src/services/SecureClipboardService.ts` implementing `ISecureClipboardService` as a singleton
  - Start 30s auto-purge timer on `copy`; clear system clipboard on expiry; notify UI on clear
  - Support data types: password, apiKey, totp, generic
  - Allow clipboard timeout configuration between 10–60 seconds
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

- [x] 10. Implement Real-Time Threat Monitor (F2)
  - [x] 10.1 Create `src/services/ThreatMonitorService.ts` implementing `IThreatMonitorService`
    - Detect rootkit/jailbreak indicators (delegate to `RASPGuard.isDeviceCompromised`)
    - Monitor app permission usage patterns for anomalous behavior
    - Detect suspicious network activity indicative of data exfiltration
    - Assign severity (low/medium/high/critical) to each detected threat
    - Persist threat records to `DatabaseService` with UUID v4, type, severity, description, timestamp
    - Implement `resolveThreats` updating resolved status and resolution timestamp
    - Maintain queryable threat history
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

  - [ ]* 10.2 Write property test for threat severity validity
    - **Property 9: Threat Severity Validity** — for any detected and persisted threat, the severity field is one of: low, medium, high, or critical
    - **Validates: Requirements 6.4**

  - [ ]* 10.3 Write property test for threat storage round-trip
    - **Property 10: Threat Storage Round-Trip** — for any detected threat, storing then retrieving by UUID returns a record with fields equal to those at detection time
    - **Validates: Requirements 6.5**

- [x] 11. Implement Network Safety Analyzer (F3)
  - [x] 11.1 Create `src/services/api/DoHResolver.ts` implementing `IDoHResolver`
    - Support Cloudflare (`cloudflare-dns.com`), Google (`dns.google`), Quad9 (`dns.quad9.net`) providers with bootstrap IPs
    - Use `application/dns-json` content type; cache results using TTL from DNS response
    - Auto-fallback to next provider if primary fails within 3s; surface warning and fall back to system DNS if all fail
    - _Requirements: 8.5, 8.6, 8.7, 8.8, 8.9_

  - [x] 11.2 Create `src/services/NetworkService.ts` implementing `INetworkService`
    - Detect Wi-Fi encryption type (WPA3/WPA2/WPA/WEP/none) and classify WEP/none as insecure
    - Detect MITM indicators (ARP spoofing, certificate anomalies)
    - Auto-refresh network security status every 30s while app is in foreground
    - Integrate `DoHResolver` for DNS routing when DoH is enabled
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [ ]* 11.3 Write property test for insecure network classification
    - **Property 12: Insecure Network Classification** — for any Wi-Fi network with encryption WEP or none, `getNetworkStatus` returns `isSecure = false`
    - **Validates: Requirements 8.2**

- [x] 12. Implement Breach Alert Engine (F4)
  - [x] 12.1 Create `src/services/api/BreachAPI.ts` implementing `IBreachAPI`
    - Base URL `https://haveibeenpwned.com/api/v3`; include `User-Agent: Aegis-App/1.0` on all requests
    - Retrieve HIBP API key from `SecurePrefs`; never embed in source
    - Rate-limit to max 1 request/1500ms; retry on 429 with `Retry-After` backoff; treat 404 as no breaches
    - _Requirements: 9.5, 9.6, 9.7, 15.3, 16.5_

  - [x] 12.2 Create `src/services/BreachService.ts` implementing `IBreachService`
    - Use `CryptoService.kAnonymityHash` to derive 5-char prefix; never send full email/username to API
    - Update identity status to 'compromised' with breach details or 'safe' with last-checked timestamp
    - Return cached data when HIBP is unreachable; surface offline state if no cache
    - Persist all monitored identities and breach history to `DatabaseService`
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.8, 9.9_

  - [ ]* 12.3 Write property test for breach k-anonymity privacy
    - **Property 13: Breach K-Anonymity Privacy** — for any email/username submitted to `BreachService`, the value transmitted to HIBP is exactly the 5-char prefix and contains no portion of the original plaintext beyond those 5 characters
    - **Validates: Requirements 9.1, 15.2**

  - [ ]* 12.4 Write property test for monitored identity status consistency
    - **Property 14: Monitored Identity Status Consistency** — after a breach check, identity status is 'compromised' iff at least one breach was found; otherwise 'safe'
    - **Validates: Requirements 9.3, 9.4**

- [x] 13. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. Implement App Permission Auditor (F5)
  - [x] 14.1 Create `src/services/PermissionAuditorService.ts` implementing `IPermissionAuditorService`
    - Enumerate all installed apps and their declared permissions
    - Categorize each permission into exactly one of: location, camera, microphone, contacts, storage, phone, sms, calendar, sensors, network
    - Calculate risk score 0–100 per app based on permission profile; classify score ≥ 70 as high-risk
    - Identify dangerous permissions; produce `AuditReport` with total apps, high-risk count, total/dangerous permission counts, and recommendations
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_

  - [ ]* 14.2 Write property test for app risk score range
    - **Property 15: App Risk Score Range** — for any installed app audited, the calculated risk score is an integer between 0 and 100 inclusive
    - **Validates: Requirements 10.2**

  - [ ]* 14.3 Write property test for high-risk app classification threshold
    - **Property 16: High-Risk App Classification Threshold** — any app with score ≥ 70 is classified high-risk; any app with score < 70 is not
    - **Validates: Requirements 10.4**

  - [ ]* 14.4 Write property test for permission category coverage
    - **Property 17: Permission Category Coverage** — for any permission enumerated, it is assigned to exactly one of the 10 defined categories
    - **Validates: Requirements 10.3**

- [x] 15. Implement Threat Intelligence API Client
  - Create `src/services/api/ThreatIntelAPI.ts` implementing `IThreatIntelAPI`
  - Cache reputation results locally for minimum 1 hour; return cached result without network call when valid cache exists
  - Retrieve API key from `SecurePrefs`; never embed in source
  - Fail open on network error (return `malicious: false`, `confidence: 0`)
  - _Requirements: 20.1, 20.2, 20.3, 20.4, 20.5_

- [x] 16. Implement Security Score Dashboard (F6)
  - [x] 16.1 Create `src/services/SecurityScoreService.ts` implementing `ISecurityScoreService`
    - Aggregate weighted category scores from vault health, network safety, app risk, OS hygiene, and breach status into overall score 0–100
    - Classify: 80–100 → 'good'/'excellent', 50–79 → 'fair', 0–49 → 'poor'/'critical'
    - Persist each calculated score to `DatabaseService` with timestamp, overall score, level, and per-category breakdown
    - Provide `getScoreHistory(days)` and `getRecommendations()` returning prioritized action list
    - Complete full score calculation within 2 seconds
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 16.3_

  - [ ]* 16.2 Write property test for security score range
    - **Property 18: Security Score Range** — for any invocation of `calculateSecurityScore`, the overall score is an integer between 0 and 100 inclusive
    - **Validates: Requirements 11.1**

  - [ ]* 16.3 Write property test for security score level classification
    - **Property 19: Security Score Level Classification** — for any overall score, the assigned level maps to exactly one band (80–100 → good/excellent, 50–79 → fair, 0–49 → poor/critical)
    - **Validates: Requirements 11.2, 11.3, 11.4**

  - [ ]* 16.4 Write property test for security score history round-trip
    - **Property 20: Security Score History Round-Trip** — for any score calculated and persisted, querying score history includes an entry matching that score and timestamp
    - **Validates: Requirements 11.5, 11.6**

- [x] 17. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 18. Implement UI Components
  - [x] 18.1 Create `src/components/SecurityBadge.tsx`
    - Render pill badge: safe → green (#00FF88) bg tint + text "SAFE", warning → amber (#FFB800) "WARNING", critical → red (#FF3B30) "CRITICAL"
    - Background is 15% opacity of status color on `colors.surface`; all-caps monospace font; rounded pill
    - _Requirements: 13.4, 13.5, 13.6_

  - [ ]* 18.2 Write property test for SecurityBadge rendering correctness
    - **Property 23: SecurityBadge Rendering Correctness** — for any status value ('safe', 'warning', 'critical'), the badge renders with the correct color and label
    - **Validates: Requirements 13.4, 13.5, 13.6**

  - [x] 18.3 Create `src/components/ScoreRing.tsx`
    - Animated circular progress ring using `react-native-reanimated`; animate 0 → score over 800ms on mount
    - Color thresholds: 80–100 → #00FF88, 50–79 → #FFB800, 0–49 → #FF3B30
    - Display numeric score in center, bold, colored to match ring; background track uses `colors.border`
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

  - [ ]* 18.4 Write property test for ScoreRing color mapping
    - **Property 21: ScoreRing Color Mapping** — for any score 0–100, the ring renders in exactly one color per the three threshold bands
    - **Validates: Requirements 12.1, 12.2, 12.3**

  - [x] 18.5 Create `src/components/ModuleHealthBar.tsx`
    - Horizontal progress bar with label, score value (`{score}/100`), and fill color following same green/amber/red thresholds
    - Tappable — invoke `onPress` to navigate to relevant module screen
    - _Requirements: 21.1, 21.2, 21.3, 21.4, 21.5_

  - [x] 18.6 Create `src/components/CredentialCard.tsx`
    - Display type icon, title, username (truncated); never render plaintext password/passkey/totpSeed/apiKey
    - Copy button invokes `SecureClipboardService` without displaying the value
    - TOTP type shows live countdown ring (30s cycle) next to copy button
    - _Requirements: 13.1, 13.2, 13.3_

  - [ ]* 18.7 Write property test for credential card secret concealment
    - **Property 22: Credential Card Secret Concealment** — for any Credential rendered in list view, the rendered output does not contain the plaintext password, passkey, totpSeed, or apiKey
    - **Validates: Requirements 13.1**

  - [x] 18.8 Create `src/components/AlertItem.tsx`
    - Left accent bar: critical/high → red, medium → amber, low → neutral
    - Display title, description, formatted timestamp; dismiss action marks alert resolved in data store
    - Resolved alerts render at 0.4 opacity and remain visible in list
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 22.5_

  - [x] 18.9 Create `src/components/AppRiskCard.tsx`
    - Display app name, package name, `SecurityBadge` for risk level, total permission count, and dangerous permission count (visually distinct)
    - Tapping opens full permission detail view for that app
    - _Requirements: 23.1, 23.2, 23.3_

- [x] 19. Implement App Screens
  - [x] 19.1 Create `src/app/auth.tsx` — Authentication screen
    - Prompt biometric auth via `AuthService.authenticate()`; fall back to PIN entry when biometric unavailable
    - Display lockout countdown when account is locked; show error states for failed attempts
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [x] 19.2 Create `src/app/(tabs)/index.tsx` — Dashboard screen
    - Render `ScoreRing` (size 160) centered with overall score + level label
    - Render 5 `ModuleHealthBar` components (Vault Health, Network Safety, App Risk, OS Hygiene, Breach Status)
    - Render last 3 `AlertItem` components in "Recent Alerts" section with "View All" link
    - Quick action row: "Scan Network", "Check Breaches", "Add Credential"
    - Pull-to-refresh recalculates security score; score animates on every refresh
    - _Requirements: 11.1, 11.7, 26.1_

  - [x] 19.3 Create `src/app/(tabs)/vault.tsx` — Vault screen
    - Search bar filtering credential list in real-time by title/username/URL/tags
    - Filter chips: All / Passwords / Passkeys / TOTP / API Keys
    - `FlatList` of `CredentialCard` components; FAB to add new credential
    - Tapping card opens credential detail sheet (full decrypt on demand); long-press shows edit/delete menu
    - Copy action triggers `SecureClipboardService` + toast with countdown
    - _Requirements: 4.7, 5.1, 5.5_

  - [x] 19.4 Create `src/app/(tabs)/network.tsx` — Network Safety screen
    - Display current network status card (SSID, encryption type, `SecurityBadge`)
    - MITM detection card with status, last scan timestamp, "Scan Now" button
    - DoH card with toggle switch, provider selector (Cloudflare/Google/Quad9), latency display
    - Active network threats list; auto-refresh every 30s while screen is visible
    - _Requirements: 27.1, 27.2, 27.3, 27.4, 27.5_

  - [x] 19.5 Create `src/app/(tabs)/alerts.tsx` — Alerts screen
    - Segmented control tabs: "Breaches" | "Threats"
    - Breaches tab: `AlertItem` list grouped by monitored identity; "Add Email to Monitor" when empty
    - Threats tab: `AlertItem` list sorted by severity then timestamp
    - Empty state: green checkmark + "All Clear" message; filter bar (All/Breaches/Threats/Network)
    - Dismiss and escalate actions per alert; "Mark All Resolved" header button
    - _Requirements: 28.1, 28.2, 28.3, 28.4_

  - [x] 19.6 Create `src/app/(tabs)/audit.tsx` — Audit screen
    - Summary card: total apps, high-risk count, overall audit `SecurityBadge`
    - Sort control: By Risk (default) / By Name / By Install Date
    - `FlatList` of `AppRiskCard` components; high-risk apps (score ≥ 70) with red left border accent
    - Tapping card opens permission detail bottom sheet; "Re-audit" header button triggers fresh scan
    - _Requirements: 29.1, 29.2, 29.3, 29.4, 29.5_

- [x] 20. Implement Root Layout and App Initialization
  - Create `src/app/_layout.tsx` wrapping all protected tab screens with session lock enforcement
  - Initialize `RASPGuard` before rendering any screen content on app start
  - Register background task for threat monitoring on app start
  - Redirect to auth screen immediately when session lock state changes to locked
  - _Requirements: 26.1, 26.2, 26.3, 26.4_

- [x] 21. Implement Optional Cloud Backup
  - Create `src/services/CloudBackupService.ts`
  - Encrypt all backup data with AES-256-GCM before transmitting; never transmit plaintext vault data or key material
  - Support export to user-specified destination and import with `Master_Key` decryption
  - Reject import with incorrect key and return decryption error without modifying local data
  - Cloud backup is entirely optional — app functions fully without it configured
  - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6_

- [x] 22. Wire all services into app and validate no plaintext PII in external requests
  - Audit all outgoing HTTP requests in `BreachAPI`, `ThreatIntelAPI`, `DoHResolver` to confirm no plaintext email, username, password, passkey, TOTP seed, or API key appears in URL, headers, or body
  - Confirm all third-party API keys are loaded from `SecurePrefs` and never embedded in source
  - Confirm HIBP API key stored in `expo-secure-store`
  - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_

  - [ ]* 22.1 Write property test for no plaintext PII in external requests
    - **Property 25: No Plaintext PII in External Requests** — for any outgoing HTTP request to an external API, the URL, headers, and body contain no plaintext email, username, password, passkey, TOTP seed, or API key belonging to the user
    - **Validates: Requirements 15.1, 15.2**

- [x] 23. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 2 Tasks

- [x] 24. Implement Certificate Pinning Infrastructure
  - [x] 24.1 Create `src/api/certificatePinning.ts` implementing `pinnedFetch`
    - Enforce HTTPS-only — reject all non-HTTPS requests unconditionally
    - Maintain pin registry for: `www.virustotal.com`, `haveibeenpwned.com`, `cloudflare-dns.com`, `dns.google`, `dns.quad9.net`
    - Delegate to `react-native-ssl-pinning` native module when installed; fall back to hostname-only validation with logged warning
    - Expose `registerCertificatePin` and `isPinned` utilities for runtime pin management
    - _Requirements: 31.1, 31.2_

- [x] 25. Implement Phase 2 Enhanced RASP Guard
  - [x] 25.1 Create `src/rasp/RASPGuard.ts` extending Phase 1 RASP with vault/crypto gating and tamper detection
    - Implement `gateVaultOperation(operationName)` — throws when `preOperationCheck()` fails
    - Implement `gateCryptoOperation(operationName)` — throws when `preOperationCheck()` fails
    - Implement `detectTampering()` — checks `Array.prototype.push` reference integrity and `JSON.parse`/`JSON.stringify` round-trip
    - Add `tamper_detected` violation type mapped to `high` threat level
    - Consolidate `src/services/RASPGuard.ts` as a re-export shim pointing to `src/rasp/RASPGuard.ts`
    - _Requirements: 31.3, 31.4, 31.5_

  - [ ]* 25.2 Write property test for vault operation gating
    - **Property 29: Vault Operation Gating** — for any call to `gateVaultOperation()` while `preOperationCheck()` returns a failure, the method SHALL throw and the vault operation SHALL NOT proceed
    - **Validates: Requirements 31.3**

- [x] 26. Implement Phase 2 API Re-export Shims
  - [x] 26.1 Create `src/api/ThreatIntelAPI.ts` — re-exports from `src/services/api/ThreatIntelAPI.ts`
    - Canonical implementation stays in `src/services/api/` (tested, used by Phase 1)
    - `src/api/` shim ensures Phase 2 module imports resolve correctly
    - _Requirements: 31.6, 20.1, 20.2, 20.3, 20.4, 20.5_

  - [x] 26.2 Create `src/api/DoHResolver.ts` — re-exports from `src/services/api/DoHResolver.ts`
    - Canonical implementation stays in `src/services/api/` (tested, used by NetworkService)
    - `src/api/` shim ensures Phase 2 module imports resolve correctly
    - _Requirements: 31.7, 8.5, 8.6, 8.7, 8.8, 8.9_

  - [ ]* 26.3 Write property test for certificate pinning enforcement
    - **Property 28: Certificate Pinning Enforcement** — for any request via `pinnedFetch` to a non-HTTPS URL or unpinned host, the request SHALL be rejected before any network connection is established
    - **Validates: Requirements 31.1, 31.2**

- [x] 27. Implement ThreatStore
  - [x] 27.1 Create `src/modules/threat/ThreatStore.ts` implementing `IThreatStore`
    - Implement lightweight reactive store (Zustand pattern) with typed subscriber notifications
    - Write-through persistence to encrypted SQLite `threats` table via `DatabaseService`
    - Hydrate in-memory state from database on startup via `hydrate()`
    - Compute aggregate `ThreatLevel` from active (unresolved) threats on every mutation
    - Gate `addThreat` and `resolveThreats` via `raspGuard.preOperationCheck()`
    - _Requirements: 30.3, 32.2, 32.3, 32.4_

  - [ ]* 27.2 Write property test for ThreatStore write-through consistency
    - **Property 27: ThreatStore Write-Through Consistency** — for any threat added via `addThreat()`, the threat SHALL be retrievable from both in-memory state and the encrypted SQLite database with identical field values
    - **Validates: Requirements 30.3, 32.2**

- [x] 28. Implement ThreatAgent
  - [x] 28.1 Create `src/modules/threat/ThreatAgent.ts` implementing `IThreatAgent`
    - Register background headless task `AEGIS_THREAT_AGENT` via `expo-task-manager` (graceful degradation when not installed)
    - Implement 5 anomaly rules: `device_compromise`, `code_signature_invalid`, `debugger_attachment`, `emulator_detected`, `excessive_network_activity`
    - Aggregate score = `max(rule contributions)`, clamped to [0, 100]
    - Persist detected threats to `ThreatStore`; record RASP violations as threats when pre-op check fails
    - All telemetry collection is on-device only — no external transmission
    - Wire into `src/app/_layout.tsx` initialization sequence
    - _Requirements: 30.1, 30.2, 30.3, 30.4, 30.5, 30.6_

  - [ ]* 28.2 Write property test for anomaly score bounds
    - **Property 26: Anomaly Score Bounds** — for any invocation of `runAnomalyScoring()`, the returned score SHALL be an integer between 0 and 100 inclusive
    - **Validates: Requirements 30.2**

- [x] 29. Implement NetworkStore
  - [x] 29.1 Create `src/modules/network/NetworkStore.ts` implementing `INetworkStore`
    - Implement lightweight reactive store with typed subscriber notifications
    - Persist last scan result, MITM result, and scan timestamp to `network_cache` key-value table in encrypted SQLite
    - Hydrate from cache on startup via `hydrate()`; expose `isOffline` flag
    - Wire into `src/app/_layout.tsx` initialization sequence
    - _Requirements: 32.1, 32.3, 32.5_

  - [ ]* 29.2 Write property test for NetworkStore offline cache consistency
    - **Property 30: NetworkStore Offline Cache Consistency** — for any scan result persisted via `updateLastScan()`, hydrating the store SHALL restore `lastScanResult` and `lastScanAt` matching the persisted values
    - **Validates: Requirements 32.1**

- [x] 30. Implement NetworkInspector
  - [x] 30.1 Create `src/modules/network/NetworkInspector.ts` implementing `INetworkInspector`
    - Implement `assessWiFi()` — encryption classification, signal anomaly detection, BSSID/SSID heuristics
    - Implement `detectARPSpoofing()` — gateway IP derivation, HTTP probe for unexpected redirects
    - Implement `fingerprintRogueAP()` — null BSSID, short SSID, signal >-30 dBm, open 2.4 GHz checks
    - Implement `detectSSLAnomalies()` — parallel HTTPS probes to `1.1.1.1` and `8.8.8.8` for certificate errors
    - Implement `inspect()` — runs all checks in parallel, builds `NetworkInspectionReport`, persists to `NetworkStore`
    - Gate `inspect()` via `raspGuard.preOperationCheck()`
    - Wire into `src/app/(tabs)/network.tsx` "Scan Now" button
    - _Requirements: 33.1, 33.2, 33.3, 33.4, 33.5, 33.6_

  - [ ]* 30.2 Write property test for rogue AP risk classification
    - **Property 31: Rogue AP Risk Classification** — for any AP with two or more rogue AP indicators, `fingerprintRogueAP()` SHALL return `riskLevel: 'high'`
    - **Validates: Requirements 33.4**

- [x] 31. Implement Settings Screen
  - [x] 31.1 Create `src/app/(tabs)/settings.tsx` — Settings screen
    - Provide secure input fields for HIBP API key and VirusTotal API key
    - Store keys via `SecurePrefs` (expo-secure-store) — never display after saving
    - Show "✓ SET" badge when a key is already stored; provide remove action
    - Register in `src/app/(tabs)/_layout.tsx` with ⚙️ gear icon tab
    - _Requirements: 34.1, 34.2, 34.3, 34.4, 34.5_

- [x] 32. Cleanup — Remove duplicates and consolidate
  - Delete `src/platform/DatabaseService.web.ts` (duplicate of `src/database/DatabaseService.web.ts`)
  - Make `src/services/RASPGuard.ts` a re-export shim pointing to `src/rasp/RASPGuard.ts`
  - Make `src/api/ThreatIntelAPI.ts` and `src/api/DoHResolver.ts` re-export shims
  - Update `src/app/_layout.tsx` to import `raspGuard` from `src/rasp/RASPGuard` directly
  - _Requirements: 31.3_

- [x] 33. Phase 2 checkpoint — Ensure all tests pass
  - Run full test suite; confirm 148+ tests pass with no regressions
  - Verify all Phase 2 files have zero TypeScript diagnostics
  - Commit and push to `Releases` branch; merge to `main` for release
  - _Requirements: 30–34_

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at key milestones
- Property tests validate universal correctness properties (31 properties total across Phase 1 + Phase 2)
- Unit tests validate specific examples and edge cases
- The design uses TypeScript throughout — all implementation uses TypeScript with strict mode
- Phase 2 modules live in `src/modules/`, `src/api/`, and `src/rasp/` — Phase 1 services in `src/services/` are unchanged
- `src/services/RASPGuard.ts` is now a re-export shim — the canonical implementation is `src/rasp/RASPGuard.ts`

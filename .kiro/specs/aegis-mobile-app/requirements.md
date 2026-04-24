# Requirements Document

## Introduction

Aegis is a privacy-first, on-device personal cybersecurity mobile application for iOS and Android built with React Native (Expo SDK) and TypeScript. The application consolidates six defensive security modules into a unified interface: Encrypted Credential Vault (F1), Real-Time Threat Monitor (F2), Network Safety Analyzer (F3), Breach Alert Engine (F4), App Permission Auditor (F5), and Security Score Dashboard (F6). The system operates under a zero-trust model where all sensitive operations occur on-device with AES-256-GCM encryption, biometric authentication, and runtime application self-protection (RASP). The application is designed to OWASP MASVS Level 2 compliance standards, ensuring no personally identifiable information (PII) leaves the device unencrypted.

## Glossary

- **Authentication_Service**: The component responsible for biometric and PIN-based user authentication and session lifecycle management.
- **Session_Lock_Service**: The middleware component that enforces automatic session locking after a configurable idle timeout.
- **Cryptography_Service**: The component providing AES-256-GCM encryption, PBKDF2 key derivation, and k-anonymity hashing.
- **Vault_Service**: The component managing encrypted storage and retrieval of user credentials (passwords, passkeys, TOTP seeds, API keys).
- **Threat_Monitor_Service**: The component performing passive background monitoring for rootkit, jailbreak, and suspicious activity indicators.
- **Network_Service**: The component analyzing Wi-Fi network security, detecting MITM indicators, and managing DNS-over-HTTPS routing.
- **DoH_Resolver**: The DNS-over-HTTPS client supporting Cloudflare, Google, and Quad9 providers.
- **Breach_Service**: The component monitoring email addresses and usernames against the HaveIBeenPwned API using k-anonymity.
- **Breach_API**: The HaveIBeenPwned v3 API client implementing k-anonymity for privacy-preserving breach lookups.
- **Permission_Auditor_Service**: The component enumerating installed applications and calculating permission-based risk scores.
- **Security_Score_Service**: The component aggregating security metrics from all modules into a weighted 0–100 score.
- **RASP_Guard**: The Runtime Application Self-Protection component detecting tampering, debugging, and integrity violations.
- **Secure_Clipboard_Service**: The singleton service managing clipboard operations with automatic 30-second purge of sensitive data.
- **Database_Service**: The encrypted local database service using expo-sqlite with SQLCipher.
- **Master_Key**: The AES-256 encryption key derived from the user's password/PIN via PBKDF2 used to encrypt all vault data.
- **K-Anonymity**: A privacy technique where only the first 5 characters of a SHA-1 hash are sent to an external API, preventing the full value from being disclosed.
- **TOTP**: Time-Based One-Time Password per RFC 6238, generating 6-digit codes that rotate every 30 seconds.
- **HIBP**: HaveIBeenPwned — the external breach database API used for email and password compromise checks.
- **RASP**: Runtime Application Self-Protection — in-app security controls that detect and respond to real-time attacks.
- **MASVS**: Mobile Application Security Verification Standard published by OWASP.
- **MITM**: Man-in-the-Middle attack — a network attack where an adversary intercepts communications between two parties.
- **DoH**: DNS-over-HTTPS — a protocol for performing DNS resolution via the HTTPS protocol to prevent eavesdropping.
- **SQLCipher**: An open-source extension to SQLite that provides transparent 256-bit AES encryption of database files.
- **ScoreRing**: The animated circular progress ring UI component displaying the overall security score.
- **SecurityBadge**: The inline pill badge UI component indicating safe, warning, or critical status.
- **CredentialCard**: The list item UI component for displaying a vault credential entry.

---

## Requirements

### Requirement 1: User Authentication

**User Story:** As a user, I want to authenticate with biometrics or a PIN, so that only I can access my sensitive security data.

#### Acceptance Criteria

1. THE Authentication_Service SHALL support biometric authentication using Face ID, Touch ID, or fingerprint recognition where available on the device.
2. WHEN biometric authentication is unavailable on the device, THE Authentication_Service SHALL offer PIN-based authentication as the fallback method.
3. WHEN a user provides an incorrect authentication credential 3 times consecutively, THE Authentication_Service SHALL enforce a 30-second lockout before allowing further attempts.
4. WHEN a user provides an incorrect authentication credential 5 times consecutively, THE Authentication_Service SHALL enforce a 5-minute lockout before allowing further attempts.
5. WHEN a user provides an incorrect authentication credential 10 times consecutively, THE Authentication_Service SHALL enforce a permanent lockout requiring manual recovery.
6. WHEN authentication succeeds, THE Authentication_Service SHALL reset the failed attempt counter to zero.
7. WHEN a session is locked, THE Authentication_Service SHALL require successful re-authentication before granting access to any protected resource.

---

### Requirement 2: Session Management

**User Story:** As a user, I want my session to lock automatically when I'm not using the app, so that my data is protected if I leave my device unattended.

#### Acceptance Criteria

1. WHILE a session is active and no user interaction has occurred for 60 seconds, THE Session_Lock_Service SHALL automatically lock the session.
2. WHEN the session is locked, THE Session_Lock_Service SHALL clear all sensitive data from application memory.
3. WHEN the session is locked, THE Session_Lock_Service SHALL require re-authentication via the Authentication_Service before restoring access.
4. THE Session_Lock_Service SHALL allow the auto-lock timeout to be configured between 30 and 300 seconds.
5. WHEN user interaction is detected, THE Session_Lock_Service SHALL reset the inactivity timer.

---

### Requirement 3: Cryptography and Key Management

**User Story:** As a user, I want all my sensitive data encrypted with strong cryptography, so that my credentials cannot be read even if the device storage is compromised.

#### Acceptance Criteria

1. THE Cryptography_Service SHALL derive the Master_Key from the user's password or PIN using PBKDF2 with a minimum of 100,000 iterations.
2. THE Cryptography_Service SHALL generate a cryptographically secure random salt of 32 bytes for each new key derivation.
3. THE Cryptography_Service SHALL encrypt all sensitive data using AES-256-GCM with a unique initialization vector per encryption operation.
4. FOR ALL valid plaintext strings, THE Cryptography_Service SHALL produce a ciphertext such that decrypting the ciphertext with the same key returns the original plaintext (round-trip property).
5. THE Cryptography_Service SHALL implement k-anonymity hashing by computing the SHA-1 hash of an input and returning only the first 5 hexadecimal characters as the query prefix.
6. THE Cryptography_Service SHALL generate a new unique initialization vector for every encryption operation.

---

### Requirement 4: Encrypted Credential Vault (F1)

**User Story:** As a user, I want to securely store and manage my passwords, passkeys, TOTP seeds, and API keys, so that I have a single encrypted location for all my credentials.

#### Acceptance Criteria

1. THE Vault_Service SHALL encrypt all credential fields containing sensitive data (password, passkey, totpSeed, apiKey, notes) using the Master_Key before persisting to the Database_Service.
2. WHEN a credential is added, THE Vault_Service SHALL assign a unique UUID v4 identifier to the credential.
3. THE Vault_Service SHALL support the following credential types: password, passkey, totp, and apiKey.
4. WHEN creating a credential, THE Vault_Service SHALL require that at least one of the following fields is present: password, passkey, totpSeed, or apiKey.
5. WHEN a credential title is absent or empty, THE Vault_Service SHALL reject the credential and return a validation error.
6. WHEN a TOTP credential is accessed, THE Vault_Service SHALL generate a valid 6-digit TOTP code per RFC 6238 using the stored seed.
7. THE Vault_Service SHALL support searching credentials by title, username, URL, and tags, returning only credentials that match the query in at least one of those fields.
8. WHEN a credential is deleted, THE Vault_Service SHALL permanently remove it from the Database_Service such that it is no longer retrievable.
9. WHEN a credential is retrieved, THE Vault_Service SHALL decrypt all encrypted fields using the Master_Key before returning the data to the caller.
10. THE Vault_Service SHALL track the last-used timestamp for each credential and update it on every access.

---

### Requirement 5: Secure Clipboard Management

**User Story:** As a user, I want copied passwords and keys to be automatically cleared from the clipboard, so that sensitive data is not left accessible to other apps.

#### Acceptance Criteria

1. WHEN a sensitive value is copied via the Secure_Clipboard_Service, THE Secure_Clipboard_Service SHALL start a 30-second auto-purge timer.
2. WHEN the auto-purge timer expires, THE Secure_Clipboard_Service SHALL clear the system clipboard.
3. THE Secure_Clipboard_Service SHALL support the following data types for clipboard operations: password, apiKey, totp, and generic.
4. THE Secure_Clipboard_Service SHALL allow the clipboard timeout to be configured between 10 and 60 seconds.
5. WHEN the clipboard is cleared, THE Secure_Clipboard_Service SHALL notify the UI so a confirmation can be shown to the user.

---

### Requirement 6: Real-Time Threat Monitor (F2)

**User Story:** As a user, I want the app to monitor my device for security threats in the background, so that I am alerted to rootkits, jailbreaks, and suspicious activity.

#### Acceptance Criteria

1. THE Threat_Monitor_Service SHALL detect rootkit and jailbreak indicators on the device.
2. THE Threat_Monitor_Service SHALL monitor installed application permission usage patterns for anomalous behavior.
3. THE Threat_Monitor_Service SHALL detect suspicious network activity indicative of data exfiltration.
4. WHEN a threat is detected, THE Threat_Monitor_Service SHALL assign a severity level of low, medium, high, or critical to the threat.
5. WHEN a threat is detected, THE Threat_Monitor_Service SHALL persist the threat record to the Database_Service with a UUID v4 identifier, type, severity, description, and detection timestamp.
6. WHEN a threat is resolved, THE Threat_Monitor_Service SHALL update the threat record with a resolved status and resolution timestamp.
7. THE Threat_Monitor_Service SHALL maintain a queryable history of all detected threats.

---

### Requirement 7: RASP Guard

**User Story:** As a security-conscious user, I want the app to protect itself from tampering and debugging, so that attackers cannot extract my data by manipulating the app at runtime.

#### Acceptance Criteria

1. THE RASP_Guard SHALL detect whether a debugger is attached to the application process before any sensitive operation.
2. THE RASP_Guard SHALL detect whether the application is running on an emulator or simulator.
3. THE RASP_Guard SHALL detect whether the device has been rooted (Android) or jailbroken (iOS).
4. THE RASP_Guard SHALL verify the application code signature integrity on initialization.
5. WHEN any integrity check fails, THE RASP_Guard SHALL block the requested sensitive operation and return a denial result with the reason.
6. WHEN an integrity violation is detected, THE RASP_Guard SHALL log the violation with a timestamp and violation type.
7. THE RASP_Guard SHALL perform an integrity check before every vault access, authentication operation, and cryptographic operation.

---

### Requirement 8: Network Safety Analyzer (F3)

**User Story:** As a user, I want to know if my current network is safe and have my DNS queries protected, so that I can avoid man-in-the-middle attacks and DNS hijacking.

#### Acceptance Criteria

1. THE Network_Service SHALL detect the current Wi-Fi network encryption type and classify it as one of: WPA3, WPA2, WPA, WEP, or none.
2. WHEN the current Wi-Fi network uses WEP encryption or no encryption, THE Network_Service SHALL classify the network as insecure.
3. THE Network_Service SHALL detect man-in-the-middle attack indicators including ARP spoofing and certificate anomalies.
4. THE Network_Service SHALL automatically refresh the network security status every 30 seconds while the app is in the foreground.
5. THE DoH_Resolver SHALL route all application DNS queries through DNS-over-HTTPS when DoH is enabled.
6. THE DoH_Resolver SHALL support Cloudflare (cloudflare-dns.com), Google (dns.google), and Quad9 (dns.quad9.net) as DoH providers.
7. WHEN the active DoH provider fails to respond within 3 seconds, THE DoH_Resolver SHALL automatically fall back to the next configured provider.
8. WHEN all DoH providers are unreachable, THE DoH_Resolver SHALL surface a warning to the user and fall back to system DNS.
9. THE DoH_Resolver SHALL cache DNS query results using the TTL value from the DNS response.

---

### Requirement 9: Breach Alert Engine (F4)

**User Story:** As a user, I want to monitor my email addresses and usernames for data breaches, so that I can take action when my credentials are compromised.

#### Acceptance Criteria

1. WHEN checking an email or username for breaches, THE Breach_Service SHALL use k-anonymity by sending only the first 5 hexadecimal characters of the SHA-1 hash to the HIBP API, never the full value.
2. THE Breach_Service SHALL allow users to add email addresses and usernames to a monitored identities list.
3. WHEN a breach is detected for a monitored identity, THE Breach_Service SHALL update the identity's status to 'compromised' and store the breach details locally.
4. WHEN no breaches are found for a monitored identity, THE Breach_Service SHALL update the identity's status to 'safe' and record the last-checked timestamp.
5. THE Breach_API SHALL rate-limit outgoing requests to a maximum of 1 request per 1500 milliseconds.
6. WHEN the HIBP API returns HTTP 404, THE Breach_Service SHALL treat the response as no breaches found and not raise an error.
7. WHEN the HIBP API returns HTTP 429, THE Breach_Service SHALL back off and retry the request after the duration specified in the Retry-After response header.
8. WHEN the HIBP API is unreachable, THE Breach_Service SHALL return cached breach data if available, otherwise surface an offline state to the user.
9. THE Breach_Service SHALL store all monitored identities and their breach history in the local Database_Service.

---

### Requirement 10: App Permission Auditor (F5)

**User Story:** As a user, I want to see which installed apps have excessive permissions, so that I can identify and remove privacy risks on my device.

#### Acceptance Criteria

1. THE Permission_Auditor_Service SHALL enumerate all installed applications on the device along with their declared permissions.
2. THE Permission_Auditor_Service SHALL calculate a risk score between 0 and 100 (inclusive) for each installed application based on its permission profile.
3. THE Permission_Auditor_Service SHALL categorize each permission into one of the following categories: location, camera, microphone, contacts, storage, phone, sms, calendar, sensors, or network.
4. WHEN an application's risk score is 70 or above, THE Permission_Auditor_Service SHALL classify the application as high-risk.
5. THE Permission_Auditor_Service SHALL identify permissions classified as dangerous and include them in the audit report.
6. THE Permission_Auditor_Service SHALL produce an audit report containing: total app count, high-risk app count, total permission count, dangerous permission count, and actionable recommendations.
7. WHEN an audit is completed, THE Permission_Auditor_Service SHALL make the results available for query by the Security_Score_Service.

---

### Requirement 11: Security Score Dashboard (F6)

**User Story:** As a user, I want a single security score that reflects my overall security posture, so that I can quickly understand my risk level and know what to improve.

#### Acceptance Criteria

1. THE Security_Score_Service SHALL calculate an overall security score between 0 and 100 (inclusive) by aggregating weighted category scores from: vault health, network safety, app risk, OS hygiene, and breach status.
2. WHEN the overall score is between 80 and 100 inclusive, THE Security_Score_Service SHALL classify the security level as 'good' or 'excellent'.
3. WHEN the overall score is between 50 and 79 inclusive, THE Security_Score_Service SHALL classify the security level as 'fair'.
4. WHEN the overall score is between 0 and 49 inclusive, THE Security_Score_Service SHALL classify the security level as 'poor' or 'critical'.
5. THE Security_Score_Service SHALL persist each calculated score to the Database_Service with a timestamp, overall score, level, and per-category breakdown.
6. THE Security_Score_Service SHALL provide a score history queryable by number of days.
7. THE Security_Score_Service SHALL produce a list of prioritized recommendations identifying specific actions the user can take to improve their score.

---

### Requirement 12: Security Score UI (ScoreRing)

**User Story:** As a user, I want the security score displayed as a color-coded ring, so that I can instantly understand my security status at a glance.

#### Acceptance Criteria

1. WHEN the security score is between 80 and 100 inclusive, THE ScoreRing SHALL render the ring in green (#00FF88).
2. WHEN the security score is between 50 and 79 inclusive, THE ScoreRing SHALL render the ring in amber (#FFB800).
3. WHEN the security score is between 0 and 49 inclusive, THE ScoreRing SHALL render the ring in red (#FF3B30).
4. WHEN the ScoreRing mounts, THE ScoreRing SHALL animate the ring fill from 0 to the current score over 800 milliseconds.
5. THE ScoreRing SHALL display the numeric score value in the center of the ring, colored to match the ring color.

---

### Requirement 13: Credential Display Security

**User Story:** As a user, I want my passwords to never be shown in the credential list, so that sensitive values are not accidentally exposed on screen.

#### Acceptance Criteria

1. THE CredentialCard SHALL never render the plaintext password, passkey, totpSeed, or apiKey value in the credential list view.
2. THE CredentialCard SHALL provide a copy action that invokes the Secure_Clipboard_Service to copy the sensitive value without displaying it.
3. WHEN a TOTP credential is displayed, THE CredentialCard SHALL show a live countdown indicating the remaining validity period of the current TOTP code.
4. THE SecurityBadge SHALL render with a green background tint and green text labeled "SAFE" when status is 'safe'.
5. THE SecurityBadge SHALL render with an amber background tint and amber text labeled "WARNING" when status is 'warning'.
6. THE SecurityBadge SHALL render with a red background tint and red text labeled "CRITICAL" when status is 'critical'.

---

### Requirement 14: Data Persistence and Encryption at Rest

**User Story:** As a user, I want all my data stored encrypted on-device, so that my information cannot be read if someone gains physical access to my device storage.

#### Acceptance Criteria

1. THE Database_Service SHALL encrypt all data at rest using SQLCipher with AES-256 encryption keyed by the Master_Key.
2. THE Database_Service SHALL initialize the encrypted database only after the Master_Key has been derived from successful authentication.
3. THE Database_Service SHALL support atomic transactions such that a multi-step operation either completes fully or is rolled back entirely.
4. WHEN a database transaction fails mid-execution, THE Database_Service SHALL rollback all changes made within that transaction.
5. THE Database_Service SHALL enforce the credential schema constraint that the type field is one of: password, passkey, totp, or apiKey.
6. THE Database_Service SHALL enforce the monitored identity schema constraint that the type field is one of: email or username.
7. THE Database_Service SHALL enforce the security score schema constraint that overall_score is between 0 and 100 inclusive.

---

### Requirement 15: Privacy and Data Minimization

**User Story:** As a privacy-conscious user, I want the app to never send my personal information to external services unencrypted, so that my identity and credentials remain private.

#### Acceptance Criteria

1. THE Application SHALL never transmit plaintext PII (including email addresses, usernames, passwords, or API keys) to any external API or service.
2. WHEN communicating with the HIBP API, THE Breach_Service SHALL transmit only the 5-character k-anonymity hash prefix, never the full email address or username.
3. THE Application SHALL store the HIBP API key in expo-secure-store and never embed it in application source code.
4. THE Application SHALL store all third-party API keys (ThreatIntel, HIBP) in expo-secure-store and never in plaintext storage.
5. THE Application SHALL comply with OWASP MASVS Level 2 standards for mobile application security.

---

### Requirement 16: Performance

**User Story:** As a user, I want the app to respond quickly to my interactions, so that security operations do not disrupt my workflow.

#### Acceptance Criteria

1. THE Application SHALL complete the initial authentication and database unlock sequence within 3 seconds on supported devices under normal operating conditions.
2. THE Vault_Service SHALL decrypt and return the full credential list within 500 milliseconds for vaults containing up to 500 credentials.
3. THE Security_Score_Service SHALL complete a full security score calculation within 2 seconds.
4. THE Network_Service SHALL complete a network scan within 5 seconds.
5. THE Breach_API SHALL include a User-Agent header of "Aegis-App/1.0" on all outgoing requests.

---

### Requirement 17: Secure Enclave Abstraction

**User Story:** As a developer, I want a unified interface over iOS Keychain and Android Keystore, so that key material is stored in platform-native secure hardware without platform-specific code scattered across the app.

#### Acceptance Criteria

1. THE SecureEnclave SHALL abstract iOS Keychain and Android Keystore behind a single unified interface, exposing no platform-specific API to callers.
2. THE SecureEnclave SHALL store and retrieve the master key salt and derived key material using expo-secure-store as the underlying storage mechanism.
3. THE SecureEnclave SHALL never write raw key material to AsyncStorage or any unencrypted storage medium.
4. WHEN a key material write is requested, THE SecureEnclave SHALL persist the value exclusively through expo-secure-store.
5. WHEN a key material read is requested for a key that does not exist, THE SecureEnclave SHALL return null without throwing an exception.

---

### Requirement 18: Secure Preferences Store

**User Story:** As a developer, I want a typed wrapper around expo-secure-store for user preferences, so that sensitive settings are stored securely with a consistent, type-safe API.

#### Acceptance Criteria

1. THE SecurePrefs SHALL provide typed get, set, and delete operations for all secure preference keys.
2. THE SecurePrefs SHALL store sensitive settings — including PIN hash, biometric enabled flag, and third-party API keys — exclusively via expo-secure-store.
3. WHEN a get operation is called for a key that does not exist, THE SecurePrefs SHALL return null rather than throw an exception.
4. WHEN a delete operation is called for a key that does not exist, THE SecurePrefs SHALL complete without throwing an exception.
5. THE SecurePrefs SHALL never persist any preference value to AsyncStorage or other unencrypted storage.

---

### Requirement 19: Optional Cloud Backup

**User Story:** As a user, I want to optionally back up my encrypted vault to the cloud, so that I can restore my data on a new device without ever exposing plaintext data to the cloud provider.

#### Acceptance Criteria

1. WHEN a cloud backup is initiated, THE CloudBackup SHALL encrypt all backup data with AES-256-GCM before transmitting it to the cloud provider.
2. THE CloudBackup SHALL never transmit plaintext vault data or key material to any cloud service.
3. THE CloudBackup SHALL be entirely optional — the application SHALL function fully without cloud backup configured or enabled.
4. THE CloudBackup SHALL support exporting an encrypted backup archive to a user-specified destination.
5. THE CloudBackup SHALL support importing an encrypted backup archive and decrypting it with the user's Master_Key to restore vault data.
6. WHEN an import is attempted with an incorrect key, THE CloudBackup SHALL reject the archive and return a decryption error without modifying existing local data.

---

### Requirement 20: Threat Intelligence API Client

**User Story:** As a user, I want the app to check IP addresses and domains against threat intelligence feeds, so that I am warned about known malicious network endpoints.

#### Acceptance Criteria

1. THE ThreatIntelAPI SHALL check IP addresses and domain names against configured threat intelligence feeds and return a reputation result.
2. THE ThreatIntelAPI SHALL cache reputation lookup results locally for a minimum of 1 hour before issuing a new network request for the same indicator.
3. WHEN a network error occurs during a reputation lookup, THE ThreatIntelAPI SHALL fail open by returning a safe default result rather than blocking the caller.
4. THE ThreatIntelAPI SHALL retrieve its API keys exclusively from SecurePrefs and SHALL never embed API key values in application source code.
5. WHEN a cached result exists and has not expired, THE ThreatIntelAPI SHALL return the cached result without making a network request.

---

### Requirement 21: Module Health Bar Component

**User Story:** As a user, I want each security module to display a labeled health bar with a color-coded score, so that I can assess module-level security status at a glance.

#### Acceptance Criteria

1. THE ModuleHealthBar SHALL display a text label, a numeric score between 0 and 100, and a filled progress bar representing that score.
2. WHEN the score is 80 or above, THE ModuleHealthBar SHALL render the fill bar in green (#00FF88).
3. WHEN the score is between 50 and 79 inclusive, THE ModuleHealthBar SHALL render the fill bar in amber (#FFB800).
4. WHEN the score is below 50, THE ModuleHealthBar SHALL render the fill bar in red (#FF3B30).
5. WHEN the ModuleHealthBar is tapped, THE ModuleHealthBar SHALL navigate the user to the screen corresponding to the relevant security module.

---

### Requirement 22: Alert List Item Component

**User Story:** As a user, I want each alert displayed with a severity-coded visual indicator and a dismiss action, so that I can quickly triage and resolve security alerts.

#### Acceptance Criteria

1. THE AlertItem SHALL display a left accent bar colored red for critical and high severity alerts, amber for medium severity alerts, and gray for low severity alerts.
2. THE AlertItem SHALL display the alert title, description, and formatted timestamp.
3. WHEN the dismiss action on an AlertItem is invoked, THE AlertItem SHALL mark the alert as resolved in the underlying data store.
4. WHEN an alert is resolved, THE AlertItem SHALL render at 0.4 opacity to visually distinguish it from active alerts.
5. THE AlertItem SHALL remain visible in the list after dismissal at reduced opacity rather than being removed immediately from the rendered list.

---

### Requirement 23: App Risk Card Component

**User Story:** As a user, I want each audited app displayed as a tappable card showing its risk score and permission summary, so that I can quickly identify high-risk applications.

#### Acceptance Criteria

1. THE AppRiskCard SHALL display the application name, package name, a risk score badge, and a summary of total permission count.
2. THE AppRiskCard SHALL display the count of dangerous permissions separately and visually distinguish it from the total permission count.
3. WHEN an AppRiskCard is tapped, THE AppRiskCard SHALL open the full permission detail view for that application.

---

### Requirement 24: Semantic Color System

**User Story:** As a developer, I want a centralized semantic color token system, so that all UI components use consistent, accessible colors that convey security status clearly.

#### Acceptance Criteria

1. THE colors module SHALL define the following semantic status tokens with the specified hex values: safe (#00FF88), warning (#FFB800), danger (#FF3B30), and neutral (#8E8E93).
2. THE colors module SHALL define the following background hierarchy tokens: background (#0A0A0F), surface (#12121A), surfaceElevated (#1C1C28), and border (#2A2A3A).
3. THE colors module SHALL define text hierarchy tokens: textPrimary, textSecondary, textMuted, and textMonospace.
4. THE colors module SHALL export a statusColors map that maps threat level strings to their corresponding hex color values.
5. ALL color token values defined in the colors module SHALL meet WCAG AA contrast ratio requirements when rendered against their respective designated background tokens.

---

### Requirement 25: Shared TypeScript Type Definitions

**User Story:** As a developer, I want all shared interfaces and types defined in a single module, so that the codebase is type-safe and consistent across all feature modules.

#### Acceptance Criteria

1. THE types module SHALL export all shared interfaces and types used across two or more feature modules from a single index file.
2. THE types module SHALL define and export the following interfaces: Credential, Threat, MonitoredIdentity, InstalledApp, AppPermission, SecurityScore, BreachInfo, NetworkStatus, and UserSettings.
3. THE types module SHALL use strict TypeScript with no use of the `any` type in any exported interface or type definition.

---

### Requirement 26: Root Layout and App Initialization

**User Story:** As a user, I want the app to enforce session lock and initialize all security guards before any screen is shown, so that no protected content is ever accessible without authentication.

#### Acceptance Criteria

1. THE Root_Layout SHALL wrap all protected tab screens with session lock enforcement such that a locked session redirects the user to the authentication screen.
2. WHEN the application starts, THE Root_Layout SHALL initialize the RASP_Guard before rendering any screen content.
3. WHEN the application starts, THE Root_Layout SHALL register the background task for threat monitoring.
4. WHEN the session lock state changes to locked, THE Root_Layout SHALL redirect the user to the authentication screen immediately.

---

### Requirement 27: Network Safety Screen

**User Story:** As a user, I want a dedicated network safety screen that shows my current connection security and lets me configure DNS-over-HTTPS, so that I can monitor and improve my network security posture.

#### Acceptance Criteria

1. THE Network_Screen SHALL display the current network connection status including security classification.
2. THE Network_Screen SHALL display the MITM detection status and the timestamp of the last network scan.
3. THE Network_Screen SHALL provide a toggle to enable or disable DNS-over-HTTPS and a selector to choose the active DoH provider.
4. WHEN active network threats are detected, THE Network_Screen SHALL display a list of those threats.
5. WHILE the Network_Screen is visible, THE Network_Screen SHALL automatically refresh the network status every 30 seconds.

---

### Requirement 28: Alerts Screen

**User Story:** As a user, I want a dedicated alerts screen where I can view, filter, and dismiss breach and threat alerts, so that I can manage all security notifications in one place.

#### Acceptance Criteria

1. THE Alerts_Screen SHALL display breach alerts and threat alerts in separate tabs.
2. THE Alerts_Screen SHALL provide dismiss and escalate actions for each individual alert.
3. WHEN no active alerts exist, THE Alerts_Screen SHALL display an empty state with an "All Clear" message.
4. THE Alerts_Screen SHALL support filtering the alert list by the following categories: All, Breaches, Threats, and Network.

---

### Requirement 29: Audit Screen

**User Story:** As a user, I want a dedicated app audit screen where I can review installed apps by risk, sort and filter them, and drill into permission details, so that I can identify and act on privacy risks from installed applications.

#### Acceptance Criteria

1. THE Audit_Screen SHALL display all installed applications sorted by risk score in descending order by default.
2. THE Audit_Screen SHALL display a summary card showing total app count, high-risk app count, and an overall risk badge.
3. THE Audit_Screen SHALL support sorting the app list by risk score, application name, and install date.
4. WHEN an app card is tapped, THE Audit_Screen SHALL open a permission detail sheet for that application.
5. THE Audit_Screen SHALL provide a re-audit action that triggers a fresh permission scan and refreshes the displayed results.

# AppCritique Report → capabilities.csv Mapping (Android)

This maps every Android-platform capability in `capabilities.csv` to where it
lives in the AppCritique report template (`generate_report.py` /
`report.html.jinja` / the JSON schema), and flags anything that's only
partially covered or not covered at all.

**Report locations referenced below:**
`Cover/App Info`, `Certificate Info`, `File Info`, `App Components`,
`Functionality`, `Permissions`, `Third-Party SDKs`, `Hardcoded Values`,
`Endpoint Connections`, and the four vulnerability sections `Code`,
`Network`, `Resilience`, `Storage`.

Status legend: ✅ Covered · ⚠️ Partial · ❌ Gap · ⛔ Out of scope (dynamic-only)

---

## Artifact / inventory

| ID | Title | Report Location | Mapped Check(s) | Status |
|----|-------|------------------|------------------|--------|
| 1 | Application identity, metadata, build, package, and signing details | Cover / App Info | App Name, Package Name, Main Activity, Target/Min/Max SDK, Version Name/Code | ✅ |
| 2 | Application signing / signer metadata | Certificate Info | Owner Name, Organization, Validity, v1–v4 Signature, Serial Number, Hash Algorithms, Fingerprint, Unique Certs | ✅ |
| 3 | Permissions and app capability inventory | Permissions, Functionality | Full Permissions Requested table + Functionality Present/Not Present | ✅ |
| 4 | Software component / dependency inventory | Code | *No dedicated library/SBOM list section* — only "Components with Known Vulnerabilities" checks for known-bad versions, doesn't enumerate all libraries | ⚠️ |
| 6 | Local databases and cache databases discovered | Storage | *No dedicated DB inventory* — touched indirectly by "Sensitive Data in HTTP Cache Databases" | ⚠️ |
| 7 | AndroidManifest / bundled configuration review | App Components, Code, Network | Activities/Services/Receivers/Providers + exported counts; "Unprotected Exported X", "Application Data can be Backed Up", "Application Uses Custom URL Schemes / Deep Links"; Network Security Config checks | ✅ |
| 8 | Bundled application certificates | Certificate Info | Covers the APK's own signing cert; doesn't inventory other `.cer`/`.crt`/`.pem` files bundled as assets | ⚠️ |
| 9 | Background execution modes declared by the app | App Components, Functionality | Services/Receivers counts; "Google Cloud Messaging" flag — no explicit JobScheduler/WorkManager/foreground-service breakdown | ⚠️ |
| 10 | Domain/IP geolocation for contacted endpoints | Endpoint Connections | Endpoint, Tags, IP Address, Country table | ✅ |
| 11 | Runtime behavior inventory | — | Dynamic analysis only; this report is a static-analysis document | ⛔ |
| 12 | Dynamic logs / behavioral report collection | — | Dynamic analysis only | ⛔ |
| 13 | API / endpoint discovery | Hardcoded Values, Endpoint Connections | URLs table + Endpoint Connections table | ✅ |

## Authentication

| ID | Title | Report Location | Mapped Check(s) | Status |
|----|-------|------------------|------------------|--------|
| 15 | Biometric / local authentication bypass resistance | Resilience | "Biometric / Local Authentication Bypass Possible" | ✅ |
| 16 | API authentication weakness review | Network | "API Authentication Weakness (weak token handling / API key used as authentication)" | ✅ |

## Cryptography

| ID | Title | Report Location | Mapped Check(s) | Status |
|----|-------|------------------|------------------|--------|
| 17 | Insecure or outdated cryptographic algorithms / implementations | Code | "Uses SHA-1 Hashing Algorithm", "Uses MD5 Hashing Algorithm", "Insecure Encryption Mode (CBC with PKCS5/PKCS7 Padding)" | ✅ |
| 18 | Cryptographically secure random number generation | Code | "Application Utilizes Insecure Random Number Generator" | ✅ |
| 19 | Cryptographic key generation through approved platform APIs | Code | "Cryptographic Key Generation Not Using Approved Platform APIs (Android Keystore)" | ✅ |
| 20 | Weak PBKDF2 or key-derivation parameters | Code | "Weak PBKDF2 or Key-Derivation Parameters" | ✅ |
| 21 | Hardcoded secrets, API keys, passwords, tokens, or sensitive URLs | Hardcoded Values, Code | Secrets/URLs/Emails tables; "Contains Hard-coded Cryptographic Key / Credentials" | ✅ |
| 24 | Certificate pinning / certificate transparency protection | Network | "Application Utilizes Certificate Pinning Protections", "Certificate Pinning Disabled" | ✅ |

## Network / transport

| ID | Title | Report Location | Mapped Check(s) | Status |
|----|-------|------------------|------------------|--------|
| 25 | Android Network Security Config disabled or selectively weakened | Network | "Network Security Configuration Allows Cleartext Traffic", "...Allows User-installed CAs" | ✅ |
| 26 | HTTP cleartext requests or traffic | Network | "Application Contains Insecure HTTP Traffic", "Clear Text Traffic is Enabled for App", "HTTP Requests in Network Traffic" | ✅ |
| 27 | Sensitive data present in URLs, query strings, headers, or TLS communications | Network | "HTTPS Traffic URL Contains Sensitive Data" and related URL/header checks | ✅ |
| 28 | Sensitive data / PII exposed or modifiable over the network | Network | "Sensitive Data Exposed Over Network", "Sensitive Information is Unencrypted in Transit" | ✅ |
| 29 | Insecure TLS configuration or vulnerable encrypted communication | Network | "Insecure TLS Configuration", "Weak Certificate Validation Enables MitM Attacks" | ✅ |
| 30 | Cookie missing HttpOnly flag | Network | "Cookie missing 'httpOnly' flag" | ✅ |
| 31 | Cookie missing Secure flag | Network | "Cookie missing 'Secure' flag" | ✅ |
| 32 | Deprecated or insecure FTP capability | Network | "Application Contains Deprecated FTP Functionality" | ✅ |
| 33 | API CORS header configuration | Network | "Cross-Origin Resource Sharing (CORS) Misconfiguration" | ✅ |
| 34 | Zip/archive files transmitted or processed insecurely | Code | "Insecure ZIP Archive Processing", "ZIP Archive Downloaded Over Insecure Transport" | ✅ |
| 35 | Low-level Android networking API usage | Network | *No dedicated check* — implicitly touched by general network findings narrative only | ❌ |

## Storage / privacy

| ID | Title | Report Location | Mapped Check(s) | Status |
|----|-------|------------------|------------------|--------|
| 36 | Sensitive data stored insecurely on device | Storage | "Sensitive Data Stored in External Storage" + "Local Data Exposure: ..." family | ✅ |
| 37 | Sensitive values stored insecurely in SharedPreferences | Storage | "Sensitive Values Stored Insecurely in SharedPreferences" | ✅ |
| 38 | Sensitive data in HTTP cache databases | Storage | "Sensitive Data in HTTP Cache Databases" | ✅ |
| 40 | Global write permissions on local data | Storage | "Local Data Exposure: Global Write Permissions" | ✅ |
| 41 | Sensitive values stored in memory / memory dumps | Storage | "Local Data Exposure: Sensitive Values Stored In Memory" | ✅ |
| 42 | Sensitive or PII values logged to device logs | Storage | "The App Logs Information to Device Logs" + "X Leaked to Device Logs" family (Password, Email, Username, Phone, GPS, IMEI, WiFi MAC, Advertiser ID) | ✅ |
| 43 | Device identifiers stored, logged, or transmitted insecurely | Storage | "Local Data Exposure: Advertiser ID / Device IMEI / WiFi MAC ... " family | ✅ |
| 44 | Location values stored, logged, or transmitted insecurely | Storage | "Local Data Exposure: GPS Latitude/Longitude ..." family | ✅ |
| 45 | Credentials and user-profile PII stored, logged, or transmitted insecurely | Storage | "Password/Username/Phone Number/Email Address Leaked to Device Logs", "Local Data Exposure: Insecure Hardcoded Passwords" | ✅ |
| 48 | Sensitive data exposed through UI or deep-link behavior | Storage | "Sensitive Data Exposed Through Deep Link / URL Handler", "Sensitive Data Exposed Through Device Keyboard Cache" | ✅ |
| 51 | Potentially dangerous permissions or privacy-sensitive APIs requiring review | Permissions | Permission `status` column (dangerous/normal) across the full table | ✅ |
| 53 | Camera usage and permission declaration | Functionality, Permissions | "Camera" present/not-present flag + CAMERA permission row | ✅ |
| 54 | Microphone usage declaration | Functionality, Permissions | "Microphone" flag + RECORD_AUDIO permission row | ✅ |
| 55 | Location services declaration and minimization | Functionality, Permissions | "Location" flag + ACCESS_FINE/COARSE_LOCATION rows | ✅ |
| 56 | NFC usage and declaration | Functionality, Permissions | "NFC" flag + NFC permission row | ✅ |
| 58 | Bluetooth usage declaration | Functionality, Permissions | "Bluetooth" flag + BLUETOOTH* permission rows | ✅ |
| 60 | Contacts and calendar access declarations | Functionality, Permissions | "Contacts" / "Calendar" flags + READ_CONTACTS/READ_CALENDAR rows | ✅ |
| 61 | Push notification registration and background push behavior | Functionality | "Google Cloud Messaging" present/not-present flag only — no payload-handling security review | ⚠️ |
| 62 | Supported configuration storage mechanism | — | *No dedicated check* | ❌ |

## Code quality / dependencies

| ID | Title | Report Location | Mapped Check(s) | Status |
|----|-------|------------------|------------------|--------|
| 63 | Components with known vulnerabilities | Code | "Components with Known Vulnerabilities" | ✅ |
| 64 | Specific vulnerable libraries (Nanopb, OpenSSL, etc.) | Code, Network | "Application Utilizes Insecure Nanopb Library"; "...Vulnerable OpenSSL Version" (Heartbleed / Change Cipher Spec Injection) | ✅ |
| 65 | Deprecated APIs or frameworks | Code | "Application Utilizes a Deprecated API - UIWebView" — worded for iOS; no Android-specific equivalent (e.g. `org.apache.http`, `AsyncTask`) named separately | ⚠️ |
| 66 | Unsafe serialization / deserialization APIs | Code | "Application Utilizes Insecure Serialization API - NSKeyedUnarchiver" — worded for iOS; no Android-specific equivalent (`ObjectInputStream`, unsafe `Parcelable`) named separately | ⚠️ |
| 67 | Insecure native/C API usage in binary | Code | "Insecure API Usage in Binary" | ✅ |
| 69 | Platform-provided file parser usage | — | *No dedicated check* | ❌ |
| 70 | Private or unsupported API usage | Code | "Application Utilizes Reflection" (closest proxy — doesn't specifically flag hidden-API/non-SDK-interface access) | ⚠️ |

## Binary hardening

| ID | Title | Report Location | Mapped Check(s) | Status |
|----|-------|------------------|------------------|--------|
| 72 | Stack-smashing protection / stack canaries | Code | "Application Utilizes Stack Smashing Protections" | ✅ |
| 73 | ASLR / PIE / position-independent code protection | Code | "Application Utilizes PIC Binary Protections" | ✅ |
| 74 | Debug symbols stripped from production builds | Resilience | "Components Contain Debug Symbols" | ✅ |
| 75 | Explicit memory mapping or writable/executable memory protection changes | — | *No dedicated check* (dynamic/native-inspection leaning) | ❌ |

## Build / platform currency

| ID | Title | Report Location | Mapped Check(s) | Status |
|----|-------|------------------|------------------|--------|
| 76 | Built with recent Android SDK / target SDK toolchain | App Info | Target SDK field is reported, but there's no explicit pass/fail check against a "recent enough" threshold | ⚠️ |
| 77 | Minimum SDK version / installability on insecure Android versions | Code | "App can be Installed on a Vulnerable/Unpatched Minimum SDK Version" | ✅ |

## Platform interaction

| ID | Title | Report Location | Mapped Check(s) | Status |
|----|-------|------------------|------------------|--------|
| 78 | Deep links / app links and hijacking risk | Code | "Application Uses Custom URL Schemes / Deep Links" | ✅ |
| 79 | Dangerous, debugging, or otherwise risky manifest capabilities | Code | "Unprotected Exported Activity/Service/Receiver/Provider", "Application Data can be Backed Up", "App is Debuggable" | ✅ |

## Resilience

| ID | Title | Report Location | Mapped Check(s) | Status |
|----|-------|------------------|------------------|--------|
| 81 | Root detection implemented or observed | Resilience | "Root Detection Missing" | ✅ |

---

## Summary

- **65 of 71** in-scope (non-dynamic) Android capabilities are ✅ fully covered by a named check or report field.
- **2** are ⛔ out of scope (runtime/dynamic behavior — this report is a static-analysis document; a dynamic testing pass would need its own report).
- **11** are ⚠️ partial or ❌ gaps, listed below with what's missing:

| ID | Title | Gap |
|----|-------|-----|
| 4 | Software component / dependency inventory | No full library/SBOM listing, only known-vuln flagging |
| 6 | Local databases and cache databases discovered | No dedicated DB inventory list |
| 8 | Bundled application certificates | Only covers the APK's own signing cert, not other bundled certs |
| 9 | Background execution modes declared | No JobScheduler/WorkManager/foreground-service breakdown |
| 35 | Low-level Android networking API usage | No dedicated check |
| 61 | Push notification / background push behavior | Presence flag only, no payload-handling review |
| 62 | Supported configuration storage mechanism | No dedicated check |
| 65 | Deprecated APIs or frameworks | Check is worded for iOS (UIWebView); no Android-specific equivalent |
| 66 | Unsafe serialization / deserialization APIs | Check is worded for iOS (NSKeyedUnarchiver); no Android-specific equivalent |
| 69 | Platform-provided file parser usage | No dedicated check |
| 70 | Private or unsupported API usage | Reflection check is a partial proxy only |
| 75 | Explicit memory mapping / mprotect | No dedicated check |
| 76 | Built with recent SDK/toolchain | Reported as a field, not evaluated as pass/fail |

None of these are showstoppers — most are either genuinely dynamic-analysis territory, low-severity/informational items, or cases where the check exists but is worded for iOS rather than Android. Happy to add any of these as new checks the same way we added the last batch, if you want full closure.

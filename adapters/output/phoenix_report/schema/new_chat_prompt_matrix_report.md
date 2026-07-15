# Starter prompt -- phoenix check schema + matrix report review

Copy everything below the line into a new conversation, then upload the
matrix report file.

---

I'm building a security-report tool called **phoenix** -- a Python +
Jinja2 + WeasyPrint pipeline that turns scan data (JSON) into a formatted
PDF security report for mobile apps (Android-focused so far). The report
has these sections: cover (app summary, icon, meta table), Findings by
Severity (bar meters), Overall Security (a polar/Nightingale-rose chart
across Code Vulnerability / Data Storage / Networking / Resilience),
Overall Evaluation Results table, Certificate Info, File Info, App Info,
App Components, Functionality, Third-Party SDKs, Permissions, one section
per vulnerability category (currently Code / Network / Resilience /
Storage -- each with a findings narrative + a checks-conducted table),
Hardcoded Values, and Endpoint Connections.

Earlier I had a file called `capabilities.csv` -- a capability/check matrix
with columns: ID, Platform (iOS/Android), CapabilityType (Binary/Source),
Category, Title, Description, Default Severity, NIAP, OWASP MASVS, OWASP
MASWE, OWASP MASTG/MSTG, CVE, and Phoenix Output Location (which tool +
JSON path produced the finding -- tools included mobsf, androguard,
apktool, lief, strings, gitleaks, trufflehog, opengrep, syft, apksigner,
or "dynamic"). That file is NOT the matrix report I'm about to upload here
-- it's a separate, smaller reference file from a prior conversation. I'm
including everything useful I already extracted from it below so you have
full context without needing it re-uploaded.

## Check schema built from capabilities.csv + phoenix's own fields

I built a JSON Schema for a single security check record
(`check.schema.json`), deliberately scoped to only two sources:
capabilities.csv's own columns, and the field set phoenix's own
checks-conducted table already uses (Check, Result, Explanation,
Compliance, Remediation link, Evidence). No NowSecure-specific concepts
(numeric 0-10 severity scoring, policy-category buckets, finding-card
metadata, SDK-list flags) and no ID field that cross-references a specific
external system's row/index number -- just one `check_id` I assign myself.

Top-level shape:

```
check_id, title, category, platform, capability_type[],
description, status, severity, impact,
remediation{guidance, resources[]{title, url}},
compliance{niap[], owasp_masvs[], owasp_maswe[], owasp_mastg_mstg[],
           owasp_top10_mobile_2016, cwe[], cve[], hipaa[], gdpr[]},
evidence[]{file_path, tool, output_location},
report_section
```

Field notes:
- `description` = what the check looks for in the abstract (csv's
  Description column).
- `impact` = plain-language consequence of THIS finding specifically
  (phoenix's Explanation column) -- distinct from `description`.
- `status` = Present / Not Present / Not Evaluated (phoenix's Result
  column). Use "Not Evaluated" rather than guessing when a check didn't
  run.
- `severity` = csv's Default Severity values (Critical/High/Medium/Low/
  Info/Secure/Hotspot), plus "Variable" (used in the csv itself for checks
  like "Components with known vulnerabilities" where actual severity
  depends on the specific CVE) and "N/A" (pure inventory/artifact checks
  with no risk rating of their own).
- `compliance` folds in HIPAA/GDPR/legacy-OWASP-Mobile-Top-10 tags too,
  since those appear in phoenix's own Compliance column even though
  csv doesn't carry them as dedicated columns.
- `evidence[].tool` / `output_location` map directly to csv's "Phoenix
  Output Location" column.
- `report_section` is presentation-only -- the one field tying an
  otherwise source-agnostic record to this specific report template.

## Full capabilities.csv -> phoenix mapping (Android, everything I'd already worked out)

Status legend: Covered / Partial / Gap / Out-of-scope (dynamic-only)

**Artifact / inventory**
- 1. Application identity, metadata, build, package, signing details -> Cover/App Info (App Name, Package, Main Activity, Target/Min/Max SDK, Version) -- Covered
- 2. Application signing / signer metadata -> Certificate Info (Owner, Org, Validity, v1-v4 sig, Serial, Hash Algos, Fingerprint, Unique Certs) -- Covered
- 3. Permissions and app capability inventory -> Permissions + Functionality tables -- Covered
- 4. Software component / dependency inventory -> Code ("Components with Known Vulnerabilities" only flags known-bad versions, doesn't enumerate all libraries) -- Partial
- 6. Local databases and cache databases discovered -> Storage (touched indirectly by "Sensitive Data in HTTP Cache Databases") -- Partial
- 7. AndroidManifest / bundled configuration review -> App Components + Code + Network (exported counts, "Unprotected Exported X", backup flag, custom URL schemes, Network Security Config checks) -- Covered
- 8. Bundled application certificates -> Certificate Info (only covers the APK's own signing cert, not other bundled certs) -- Partial
- 9. Background execution modes declared -> App Components + Functionality (service/receiver counts, "Google Cloud Messaging" flag; no JobScheduler/WorkManager/foreground-service breakdown) -- Partial
- 10. Domain/IP geolocation for contacted endpoints -> Endpoint Connections table -- Covered
- 11. Runtime behavior inventory -> dynamic-only -- Out of scope
- 12. Dynamic logs / behavioral report collection -> dynamic-only -- Out of scope
- 13. API / endpoint discovery -> Hardcoded Values (URLs) + Endpoint Connections -- Covered

**Authentication**
- 15. Biometric / local authentication bypass resistance -> Resilience: "Biometric / Local Authentication Bypass Possible" -- Covered
- 16. API authentication weakness review -> Network: "API Authentication Weakness" -- Covered

**Cryptography**
- 17. Insecure/outdated crypto algorithms -> Code: "Uses SHA-1", "Uses MD5", "Insecure Encryption Mode (CBC/PKCS5/PKCS7)" -- Covered
- 18. Cryptographically secure RNG -> Code: "Application Utilizes Insecure Random Number Generator" -- Covered
- 19. Crypto key generation via approved platform APIs -> Code: "Cryptographic Key Generation Not Using Approved Platform APIs (Android Keystore)" -- Covered
- 20. Weak PBKDF2/key-derivation parameters -> Code: "Weak PBKDF2 or Key-Derivation Parameters" -- Covered
- 21. Hardcoded secrets/keys/tokens/URLs -> Hardcoded Values + Code: "Contains Hard-coded Cryptographic Key / Credentials" -- Covered
- 24. Certificate pinning / cert transparency -> Network: "Application Utilizes Certificate Pinning Protections", "Certificate Pinning Disabled" -- Covered

**Network / transport**
- 25. Network Security Config disabled/weakened -> Network: "...Allows Cleartext Traffic", "...Allows User-installed CAs" -- Covered
- 26. HTTP cleartext requests/traffic -> Network: "Insecure HTTP Traffic", "Clear Text Traffic is Enabled for App" -- Covered
- 27. Sensitive data in URLs/headers/TLS -> Network: "HTTPS Traffic URL Contains Sensitive Data" family -- Covered
- 28. Sensitive data/PII exposed over network -> Network: "Sensitive Data Exposed Over Network" -- Covered
- 29. Insecure TLS config -> Network: "Insecure TLS Configuration", "Weak Certificate Validation Enables MitM Attacks" -- Covered
- 30. Cookie missing HttpOnly -> Network: "Cookie missing 'httpOnly' flag" -- Covered
- 31. Cookie missing Secure -> Network: "Cookie missing 'Secure' flag" -- Covered
- 32. Deprecated/insecure FTP -> Network: "Application Contains Deprecated FTP Functionality" -- Covered
- 33. API CORS misconfiguration -> Network: "Cross-Origin Resource Sharing (CORS) Misconfiguration" -- Covered
- 34. Zip/archive insecure processing -> Code: "Insecure ZIP Archive Processing" -- Covered
- 35. Low-level Android networking API usage -> no dedicated check -- Gap

**Storage / privacy**
- 36. Sensitive data stored insecurely -> Storage: "Local Data Exposure" family -- Covered
- 37. Sensitive values in SharedPreferences -> Storage: "Sensitive Values Stored Insecurely in SharedPreferences" -- Covered
- 38. Sensitive data in HTTP cache DBs -> Storage: "Sensitive Data in HTTP Cache Databases" -- Covered
- 40. Global write permissions -> Storage: "Local Data Exposure: Global Write Permissions" -- Covered
- 41. Sensitive values in memory -> Storage: "Local Data Exposure: Sensitive Values Stored In Memory" -- Covered
- 42. Sensitive/PII logged to device logs -> Storage: "The App Logs Information..." + "X Leaked to Device Logs" family -- Covered
- 43. Device identifiers stored/logged/transmitted insecurely -> Storage: Advertiser ID / IMEI / WiFi MAC family -- Covered
- 44. Location values stored/logged/transmitted insecurely -> Storage: GPS Lat/Long family -- Covered
- 45. Credentials/PII stored/logged/transmitted insecurely -> Storage: Password/Username/Phone/Email Leaked family -- Covered
- 48. Sensitive data exposed through UI/deep-link -> Storage: "Sensitive Data Exposed Through Deep Link / URL Handler" -- Covered
- 51. Dangerous permissions/privacy APIs review -> Permissions table status column -- Covered
- 53-58. Camera/Microphone/Location/NFC/Bluetooth usage declarations -> Functionality + Permissions -- Covered
- 60. Contacts/calendar access declarations -> Functionality + Permissions -- Covered
- 61. Push notification / background push behavior -> Functionality: "Google Cloud Messaging" flag only, no payload-handling review -- Partial
- 62. Supported configuration storage mechanism -> no dedicated check -- Gap

**Code quality / dependencies**
- 63. Components with known vulnerabilities -> Code: "Components with Known Vulnerabilities" -- Covered
- 64. Specific vulnerable libraries (Nanopb, OpenSSL) -> Code + Network: "Insecure Nanopb Library", "...Vulnerable OpenSSL Version" -- Covered
- 65. Deprecated APIs/frameworks -> Code: "Deprecated API - UIWebView" worded for iOS, no Android-specific equivalent named -- Partial
- 66. Unsafe serialization/deserialization -> Code: "Insecure Serialization API - NSKeyedUnarchiver" worded for iOS, no Android equivalent named -- Partial
- 67. Insecure native/C API usage -> Code: "Insecure API Usage in Binary" -- Covered
- 69. Platform-provided file parser usage -> no dedicated check -- Gap
- 70. Private/unsupported API usage -> Code: "Application Utilizes Reflection" (partial proxy only) -- Partial

**Binary hardening**
- 72. Stack-smashing protection -> Code: "Application Utilizes Stack Smashing Protections" -- Covered
- 73. ASLR/PIE -> Code: "Application Utilizes PIC Binary Protections" -- Covered
- 74. Debug symbols stripped -> Resilience: "Components Contain Debug Symbols" -- Covered
- 75. Explicit memory mapping/mprotect -> no dedicated check -- Gap

**Build / platform currency**
- 76. Built with recent SDK/toolchain -> App Info Target SDK field reported, no explicit pass/fail threshold check -- Partial
- 77. Min SDK / installability on insecure versions -> Code: "App can be Installed on a Vulnerable/Unpatched Minimum SDK Version" -- Covered

**Platform interaction**
- 78. Deep links/app links hijacking risk -> Code: "Application Uses Custom URL Schemes / Deep Links" -- Covered
- 79. Dangerous/risky manifest capabilities -> Code: "Unprotected Exported Activity/Service/Receiver/Provider", "Application Data can be Backed Up", "App is Debuggable" -- Covered

**Resilience**
- 81. Root detection implemented or observed -> Resilience: "Root Detection Missing" -- Covered

**Summary of prior state:** 65 of 71 in-scope Android capabilities were
fully covered by a named phoenix check or report field; 2 were out of
scope as dynamic-only; 11 were partial/gap (IDs 4, 6, 8, 9, 35, 61, 62, 65,
66, 69, 70, 75, 76 -- listed above with exactly what's missing on each).

## What I need from you in this conversation

I'm uploading the actual **matrix report** now (too large to attach in the
prior conversation). Please:

1. Read the uploaded file and extract every distinct field/column/section
   it contains.
2. Compare it against both things above -- the check schema shape AND the
   capability-by-capability mapping list -- and tell me:
   - Whether this file is a superset, subset, or different taxonomy
     entirely compared to the `capabilities.csv` I described.
   - Which of the Partial/Gap items in my mapping list this new file
     actually resolves (i.e. does it contain a capability/column that
     covers IDs 4, 6, 8, 9, 35, 61, 62, 65, 66, 69, 70, 75, or 76?).
   - Any genuinely new fields not represented in `check.schema.json`'s
     shape above, with proposed field names/types/descriptions in the same
     style.
3. Propose an updated `check.schema.json` (additive only -- don't remove or
   rename existing fields) and an updated version of the mapping list.
4. Validate the updated schema is syntactically valid JSON Schema
   (Draft 2020-12), and construct one filled example record from the new
   file's data and validate it against the updated schema.

Keep the same ground rules as before: no NowSecure-specific concepts, no
ID fields that cross-reference a specific external system's row number,
and don't limit new fields to only what would render in the phoenix
PDF today -- this is meant to stay a complete data record a report
template can choose to display or ignore.

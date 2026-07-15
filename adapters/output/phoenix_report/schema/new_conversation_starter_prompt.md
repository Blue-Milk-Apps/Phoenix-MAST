# Starter prompt -- continue phoenix check-schema work in a new chat

Copy everything below the line into a new conversation, then upload the file
that wouldn't fit here.

---

I'm building out a security-report tool called **phoenix** -- a Python +
Jinja2 + WeasyPrint pipeline that turns scan data (JSON) into a formatted PDF
security report for mobile apps (Android-focused so far). The report has
these sections: cover (app summary, icon, meta table), Findings by Severity
(bar meters), Overall Security (a polar/Nightingale-rose chart across
Code Vulnerability / Data Storage / Networking / Resilience), Overall
Evaluation Results table, Certificate Info, File Info, App Info, App
Components, Functionality, Third-Party SDKs, Permissions, one section per
vulnerability category (currently Code / Network / Resilience / Storage --
each with a findings narrative + a checks-conducted table), Hardcoded
Values, and Endpoint Connections.

I built a **JSON Schema for a single security "check" record**
(check.schema.json), deliberately scoped to only two sources:

1. capabilities.csv -- a capability/check matrix with columns: ID,
   Platform (iOS/Android), CapabilityType (Binary/Source), Category, Title,
   Description, Default Severity, NIAP, OWASP MASVS, OWASP MASWE, OWASP
   MASTG/MSTG, CVE, Phoenix Output Location (which tool + JSON path produced
   the finding -- tools included mobsf, androguard, apktool, lief, strings,
   gitleaks, trufflehog, opengrep, syft, apksigner, or "dynamic").
2. phoenix's own checks-conducted table fields: Check, Result,
   Explanation, Compliance, Remediation link, Evidence.

Deliberately excluded: any NowSecure-specific concepts (numeric 0-10
severity scoring, policy-category buckets, finding-card metadata, SDK-list
flags) and any ID field that cross-references a specific external system's
row/index number (no capability_matrix_id, no vendor-specific rule IDs --
just one check_id that's mine to assign).

The schema's top-level shape:

check_id, title, category, platform, capability_type[],
description, status, severity, impact,
remediation{guidance, resources[]{title, url}},
compliance{niap[], owasp_masvs[], owasp_maswe[], owasp_mastg_mstg[],
owasp_top10_mobile_2016, cwe[], cve[], hipaa[], gdpr[]},
evidence[]{file_path, tool, output_location},
report_section

Field notes:
- description = what the check looks for in the abstract (capabilities.csv
  Description column).
- impact = plain-language consequence of THIS finding specifically
  (phoenix's Explanation column) -- distinct from description.
- status = Present / Not Present / Not Evaluated (phoenix's Result
  column). Use "Not Evaluated" rather than guessing when a check didn't run.
- severity = capabilities.csv's Default Severity column, plus "Variable"
  (used in the CSV itself for checks like "Components with known
  vulnerabilities" where actual severity depends on the specific CVE) and
  "N/A" (for pure inventory/artifact checks with no risk rating of their
  own).
- compliance folds in HIPAA/GDPR/legacy-OWASP-Mobile-Top-10 tags too, since
  those appear in phoenix's own Compliance column even though they're
  not columns in capabilities.csv itself.
- evidence[].tool / output_location map directly to capabilities.csv's
  "Phoenix Output Location" column.
- report_section is presentation-only -- it's the one field that ties an
  otherwise source-agnostic record to this specific report template.

## What I need from you in this conversation

I'm uploading a file I couldn't attach in the previous conversation due to
size limits: [describe the file here, e.g. "the full capabilities.csv
matrix with all platforms" / "additional capability rows" / "a different
check taxonomy"].

Please:

1. Read the uploaded file and extract every distinct field/column it
   contains.
2. Compare that field list against the schema shape above (or the attached
   check.schema.json) and tell me:
   - Which fields it already covers.
   - Which fields are genuinely new and should be added (propose exact
     field names, types, and a one-line description in the same style as
     the schema's existing description values -- tie each new field back
     to a specific column/concept in the uploaded file, not to NowSecure or
     any other source we've deliberately excluded).
3. Update check.schema.json with those additions only -- keep it valid
   JSON Schema (Draft 2020-12), keep backward compatibility (don't remove
   or rename existing fields), and keep it scoped to capabilities.csv +
   phoenix's own report fields, same as before.
4. Validate the updated schema is syntactically valid, and construct one
   filled example record from the new file's data and validate it against
   the updated schema (jsonschema.validate).

Don't limit new fields to only what would render in the phoenix PDF --
the schema is meant to be a complete data record that a report template
can choose to display or ignore.

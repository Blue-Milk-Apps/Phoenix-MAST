# phoenix Security Report Generator

Turns a JSON scan-data file into a formatted PDF report, matching the
structure of your phoenix spec: cover page with app summary card ->
polar risk chart -> overall evaluation -> certificate/file/app info ->
functionality table & SDK inventory -> permissions -> one section per
vulnerability category with findings + checks-conducted table -> hardcoded
values -> endpoint connections.

The generator also supports source-oriented report scope. Flutter source
payloads receive Flutter-specific project, generated-platform, dependency,
application-link, and manual-review sections in addition to the applicable
vulnerability sections.

## Files

- `generate_report.py` - the generator. Renders `templates/report.html.jinja`
  with your data, draws the polar risk chart with matplotlib, and converts
  to PDF with WeasyPrint.
- `templates/report.html.jinja` - the report layout (Jinja2 + HTML).
- `templates/style.css` - all styling (colors, badges, pills, page numbers,
  print page size). Edit this to reskin the report without touching the
  template.
- `assets/placeholder_icon.png` - generic app-icon placeholder used on the
  cover page whenever `app_info.icon_path` isn't set. Point `icon_path` at
  a real icon file to swap it in for a given app.
- `data/blank_template.json` - empty schema, one of each section, ready to
  copy per new app scan.
- `data/sample_mirrcast.json` - a second filled example, built from real
  MobSF scan data (MirrCast), demonstrating every check added during the
  capabilities.csv gap-closure work (exported activities, backup flag,
  vulnerable min SDK, custom URL schemes, root detection, etc.) alongside
  the App Components segmented-bar view.
- `docs/capabilities_mapping.md` - the full capability-by-capability
  mapping between `capabilities.csv` (Android) and this report's sections/
  checks: 65 of 71 in-scope capabilities covered, with the remaining
  partial/gap items called out explicitly.
- `schema/check.schema.json` - a standalone JSON Schema (Draft 2020-12) for
  a single security check record, scoped to `capabilities.csv` columns +
  this report's own checks-conducted fields (check, severity, status,
  explanation, compliance, remediation, evidence). Useful if you want to
  build/validate a check catalog independent of any one report template.
- `schema/example_check.json` - a filled record validated against
  `check.schema.json`.
- `data/sample_insecurebankv2.json` - filled example built from the
  InsecureBankv2 sample report you provided, so you can see the full
  report style end to end.
- `output/InsecureBankv2_phoenix_Report.pdf` - that sample rendered.

## Usage

```bash
python3 generate_report.py data/<your_scan>.json output/<report_name>.pdf
```

## Flutter source reports

A Flutter report is selected when `meta.platform` is `"Flutter"` and
`meta.target_type` is `"SOURCE"`. The post-scan extractor supplies the
following additional objects:

- `platform_inventory` - metadata assessment, SDK constraints, generated
  Android/iOS/web/desktop targets, embedded-platform identifiers, and
  extraction warnings.
- `dependency_inventory` - declared dependencies, resolved lockfile
  dependencies, and packages observed in the Syft SBOM.
- `deep_links`, `url_schemes`, and `queried_url_schemes` - Android and iOS
  application-link declarations.
- `manual_review` - raw-only OpenGrep findings that require human validation,
  together with the scopes that were successfully assessed.
- `code_evidence`, `network_evidence`, `data_storage_evidence`, and
  `resilience_evidence` - structured findings from Dart and applicable
  embedded Android/iOS source.

Flutter vulnerability sections are included only when their evidence bundle
contains an assessed result. Individual checks with incomplete evidence render
as `Not Evaluated`; they are not converted into clean `Not Present` results.
Positive findings from partial scans remain visible. Source reports omit
binary-only certificate and file-hash presentation.

## Native library requirements

WeasyPrint depends on native text and graphics libraries in addition to the
Python packages above. On macOS, the report generator expects these shared
libraries to be available from a package manager such as Homebrew.

For Homebrew-based macOS setup:

```bash
brew install pango
```

`glib` and `cairo` are also required by WeasyPrint. If they are not already
installed on the host, Homebrew will install or upgrade them as dependencies.

The generator also sets `DYLD_FALLBACK_LIBRARY_PATH` at runtime on macOS so
WeasyPrint can find Homebrew libraries under `/opt/homebrew/lib` or
`/usr/local/lib`.

If WeasyPrint fails with errors such as `cannot load library 'libgobject-2.0-0'`
or `cannot load library 'libpango-1.0-0'`, first verify that the Homebrew
packages are installed and then rerun the scan inside the project virtualenv.

## Filling in data for a new app

1. Copy `data/blank_template.json` to something like `data/myapp_scan.json`.
2. Fill in each section:
   - `meta` - file name, package name, scan date, version.
   - `findings_severity` - counts of `high`, `medium`, `info`, `secure`, `hotspot`
     findings. Renders as horizontal bar meters on page 2, right after the
     cover - each bar's length is scaled relative to the largest count, no
     composite score involved.
   - `risk_summary` - Low / Medium / High for Code Vulnerability, Data
     Storage, Networking. Drives the polar (Nightingale rose) chart on
     page 2 - wedge length and color both encode severity.
   - `overall_evaluation` - one row per area of concern (Code Vulnerability,
     Data Storage, Networking, Cryptography, Platform, etc.) with a risk
     rating and a bullet list of summary findings.
   - `certificate`, `file_info`, `app_components` - straight key/value
     fields.
   - `app_info` - name, package, SDK versions, plus the app-summary-card
     fields shown on the cover page: `icon_path` (leave blank to use the
     placeholder icon), `app_store_id`, `developer`, `categories`, and
     `trackers_detected`.
   - `functionality` - every key from your fixed list (Audio, Contacts,
     Geofencing, ...) with `present: true/false` and a one-line explanation
     for the ones that are present. Renders as a single Present/Not
     Present table.
   - `third_party_sdks` - grouped by Analytics / Advertising / Cloud Storage
     / Developer Tools, each SDK name mapped to `true`/`false`. Add or
     remove SDK names freely - the template just iterates whatever's there.
   - `permissions` - one row per permission with `status` of `"dangerous"`
     or `"normal"` (drives the red/blue badge).
   - `vulnerability_sections` - one object per category. **Authentication,
     Cryptography, and Platform are filtered out of the PDF automatically**
     by `generate_report.py` (see `EXCLUDED_VULN_SECTIONS`), even if you
     leave data for them in the JSON - remove that filter in the script if
     you want them back. The remaining categories (Code, Network,
     Resilience, Storage) each have a `findings_text` narrative paragraph
     and a `checks` array. Each check needs `check`, `severity`
     (`"Critical"`, `"High"`, `"Medium"`, `"Low"`, `"Info"`, `"Secure"`,
     `"Hotspot"`, `"Variable"`, or `"N/A"` - the check's own risk
     classification, shown regardless of whether the result is Present or
     Not Present), `result` (`"Present"`
     or `"Not Present"` - Present renders red, Not Present renders green),
     `explanation`, `compliance` (e.g. `"OWASP: 2016-M2-Insecure Data
     Storage; HIPAA: 164.312(a)(2)(iv)"`), `remediation_link`, and
     `evidence`. Leave `checks` as `[]` for a category with nothing to
     report and the section will note that instead of showing an empty
     table.
   - `hardcoded_values` - `urls` (with country), `emails`, `secrets`.
   - `endpoints` - one row per connection (endpoint, tags, IP, country).
3. Run the generator against your new file.

## Notes

- Sections that come up empty (e.g. no hardcoded emails, no checks logged
  for a category) render a short "none found" note instead of a blank
  table, so the PDF never shows empty headers.
- The `data.certificate`, `file_info`, etc. fields in the sample file are
  marked `"Not Provided"` where your source report didn't include that
  data (e.g. cert signature versions, file size/MD5/SHA1) - replace those
  with real values from your scan tool's output.
- Styling lives entirely in `style.css` - badge colors, pill styling, table
  borders, page margins, and the footer page-number format are all there
  if you want to match a specific brand template later.

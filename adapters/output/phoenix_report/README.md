# Phoenix PDF reports

`PdfReportGenerator` renders the completed `ReportData` aggregate saved by the
scan workflow. Findings, counts, risk levels, and platform details come from
that model. Rendering does not load a blank data template or merge sample data.

## Usage

The scan workflow generates the PDF automatically. To regenerate one from a
saved `post_scan_processing.json` (schema version 1):

```python
import json
from pathlib import Path

from adapters.output.phoenix_report.pdf_report import PdfReportGenerator
from domain.report import ReportData

report_data = ReportData.from_dict(
    json.loads(Path("post_scan_processing.json").read_text(encoding="utf-8"))
)
PdfReportGenerator().generate(report_data, Path("report.pdf"))
```

This uses the saved findings and assessments without running scanners, loading
rules, or recalculating severity counts. Older intermediate JSON and the legacy
sample files in `data/` are not inputs to this API.

## Rendering contract

- `pdf_report/` maps typed platform details to the shared HTML template.
- `templates/report.html.jinja` controls layout and platform-specific sections.
  Required fields use Jinja's strict undefined handling, so missing data fails
  rendering instead of silently producing blank fields or zero findings.
- `templates/style.css` controls colors, tables, page size, and page numbering.
- `pdf_report/common/charts.py` renders the aggregate's category risks.
- `assets/` contains branding and the placeholder used when an app icon is
  unavailable. An absent icon does not change assessment results.

Source categories come from the loaded YAML rules. Functionality observations
remain separate from weakness counts. Flutter and React Native findings retain
their framework or embedded Android/iOS origin. Android component counts appear
only for Android targets; certificate and file-hash sections are binary-only.
Empty endpoint collections do not produce a table or an extra report section.

Security data belongs in the aggregate, not in template defaults. When extending
a report, update its typed model and platform mapper, then the relevant template
section. The legacy samples, check schema, and capability-mapping document are
historical references; the runtime does not load them as defaults or catalogs.

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

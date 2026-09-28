"""Static, CI-friendly console presentation for Phoenix scans."""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from domain.models import ScanConfig, ScanResult
from domain.report import ReportData
from ports.scan_output_port import ScanOutputPort


class ConsoleScanOutput(ScanOutputPort):
    """Format console output without animations, cursor movement, or markup parsing."""

    SEVERITY_STYLES = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "blue",
        "secure": "green",
    }

    def __init__(self, console: Console | None = None, *, stderr: bool = False) -> None:
        self.console = console or Console(
            stderr=stderr,
            force_interactive=False,
            force_terminal=True if os.environ.get("GITHUB_ACTIONS") == "true" else None,
            color_system=None if "NO_COLOR" in os.environ else "auto",
            width=120 if os.environ.get("CI", "").lower() in {"true", "1"} else None,
            markup=False,
            highlight=False,
            emoji=False,
        )

    def message(self, label: str, value: object, *, style: str = "") -> None:
        self.console.print(Text.assemble((f"{label}: ", "bold"), (str(value), style)), soft_wrap=True)

    def scan_started(self, config: ScanConfig) -> None:
        self.console.rule(Text("Phoenix scan", style="bold cyan"), align="left", characters="-")
        details = Table.grid(padding=(0, 2))
        details.add_column(style="bold", no_wrap=True)
        details.add_column(overflow="fold")
        details.add_row("Project", str(config.display_project_path or config.project_path))
        details.add_row("Scan type", config.scan_label)
        details.add_row("Output", str(config.output_path))
        details.add_row(
            "Stdout severity", f"{config.stdout_severity.upper()} and higher" if config.stdout_severity else "All"
        )
        if config.exclude_patterns:
            details.add_row("Excluded paths", ", ".join(config.exclude_patterns))
        self.console.print(details)
        self.console.print()

    def tool_status(self, name: str, status: str, detail: str = "") -> None:
        style = {"START": "cyan", "OK": "green", "FAILED": "bold red", "SKIPPED": "yellow"}.get(status, "")
        line = Text.assemble((f"[{status}] ", style), (name, "bold"))
        if detail:
            line.append(f" | {detail}")
        self.console.print(line, soft_wrap=True)

    def report_written(self, kind: str, path: Path) -> None:
        self.message(f"{kind} report", path)

    def scan_summary(self, report: ReportData, config: ScanConfig, executions: int, duration: float) -> None:
        self.console.print()
        self.console.rule(Text("Scan summary", style="bold cyan"), align="left", characters="-")
        self.message("Tool executions completed", executions)
        coverage_style = "green" if report.rule_status in {"success", "complete"} else "yellow"
        self.message("OpenGrep coverage", report.rule_status, style=coverage_style)
        if report.rule_status_reason:
            self.console.print(Text(report.rule_status_reason), overflow="fold")

        visible_severities = None
        if config.stdout_severity is not None:
            ordered = tuple(self.SEVERITY_STYLES)
            visible_severities = ordered[: ordered.index(config.stdout_severity) + 1]
        counts = Table(title="Weakness counts", box=box.SIMPLE_HEAD, title_justify="left", min_width=20)
        values = []
        for severity, count in asdict(report.findings_severity).items():
            if visible_severities is None or severity in visible_severities:
                counts.add_column(severity.upper(), style=self.SEVERITY_STYLES.get(severity, ""), justify="right")
                values.append(str(count))
        counts.add_row(*values)
        self.console.print(counts)

        findings = Table(title="Findings", box=box.SIMPLE_HEAD, title_justify="left", expand=True)
        findings.add_column("Severity", no_wrap=True)
        findings.add_column("Rule", ratio=2, overflow="fold")
        findings.add_column("Finding", ratio=3, overflow="fold")
        for section in report.vulnerability_sections:
            for check in section.checks:
                severity = check.severity.value
                if check.result.value == "present" and (visible_severities is None or severity in visible_severities):
                    findings.add_row(
                        Text(severity.upper(), style=self.SEVERITY_STYLES.get(severity, "")),
                        Text(check.rule_id),
                        Text(" ".join(check.name.splitlines())),
                    )
        if findings.row_count:
            self.console.print(findings)
        else:
            self.console.print(
                "No findings at the selected severity threshold." if visible_severities else "No findings recorded."
            )

        if report.secret_scans:
            secrets = Table(title="Secret detectors", box=box.SIMPLE_HEAD, title_justify="left")
            secrets.add_column("Tool")
            secrets.add_column("Status")
            secrets.add_column("Detections", justify="right")
            for summary in report.secret_scans:
                style = "green" if summary.status == "Completed" else "yellow"
                secrets.add_row(Text(summary.scanner), Text(summary.status, style=style), str(len(summary.findings)))
            self.console.print(secrets)
        self.message("Artifacts", config.output_path)
        self.console.print(Text(f"Phoenix scan completed in {duration:.2f}s", style="bold green"))

    def write_result(self, result: ScanResult) -> None:
        if result.skipped:
            status, style = "Skipped", "yellow"
            detail = result.error_message
        elif result.success:
            status, style = "OK", "green"
            detail = result.raw_output
        else:
            status, style = "Failed", "red"
            detail = result.error_message or result.raw_output
        self.message(result.scanner_name, status, style=style)
        if detail:
            self.console.print(Text(f"  {detail}"), overflow="fold")

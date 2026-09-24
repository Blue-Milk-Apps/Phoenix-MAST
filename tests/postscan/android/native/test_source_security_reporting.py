import yaml

from adapters.output.phoenix_report.builders.android import NativeAndroidReportDataBuilder
from adapters.output.phoenix_report.pdf_report import PdfReportGenerator
from adapters.output.phoenix_report.pdf_report.common import build_charts
from adapters.post_scan import NativeAndroidScanDetailExtractor
from application.report_generation_service import ReportGenerationService
from domain.post_scan.android.rule_registry import (
    ANDROID_RULE_REGISTRY,
    AndroidRuleDisposition,
    unclassified_android_rule_ids,
)
from tests.rule_fixtures import private_rules


def _report(sections: dict) -> object:
    payload = {
        **sections,
        "target_information": {
            "target_kind": "native_android_source",
            "platform": "android",
            "target_type": "source",
            "stack": "native_android",
        },
    }
    return ReportGenerationService([NativeAndroidReportDataBuilder()]).build_report_data(payload)


def test_all_bundled_android_rules_are_explicitly_classified() -> None:
    rule_ids: set[str] = set()
    rules_root = private_rules("android")
    for rules_path in rules_root.glob("*.yml"):
        document = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
        for rule in document["rules"]:
            rule_id = rule["id"]
            rule_ids.add(rule_id)
            metadata = rule.get("metadata") or {}
            mapping = ANDROID_RULE_REGISTRY[rule_id]
            if mapping.disposition is AndroidRuleDisposition.REPORT_VULNERABILITY:
                assert metadata["report_section"] == mapping.section
                assert metadata["evidence_key"] == mapping.evidence_key

    assert unclassified_android_rule_ids(rule_ids) == set()
    assert set(ANDROID_RULE_REGISTRY) == rule_ids


def test_source_security_evidence_uses_exact_rules_and_relative_locations() -> None:
    sections = NativeAndroidScanDetailExtractor().extract_sections(
        {
            "scan_metadata": {"project_path": "/workspace/Example", "target_type": "SOURCE"},
            "source_metadata": {
                "application": {"debuggable": False, "allow_backup": True},
                "components": {"activities": [{"name": "MainActivity", "exported": True}]},
                "permissions": [],
                "deep_links": [],
            },
            "opengrep": {
                "success": True,
                "scan_metadata": {
                    "rules_path": "/phoenix/rules/android",
                    "configured_rule_ids": ["android.source.sha1"],
                },
                "results": [
                    {
                        "check_id": "android.source.sha1",
                        "path": "/workspace/Example/app/src/main/Crypto.kt",
                        "start": {"line": 18},
                        "extra": {"message": "SHA-1 hashing usage was detected."},
                    }
                ],
            },
        }
    )

    assert sections["code_evidence"]["uses_sha1_hashing_algorithm"]["present"] is True
    assert sections["code_evidence"]["uses_sha1_hashing_algorithm"]["evidence"] == (
        "app/src/main/Crypto.kt:18: SHA-1 hashing usage was detected."
    )
    report = _report(sections)
    code = next(section for section in report.vulnerability_sections if section.name == "Code")
    checks = {check.name: check for check in code.checks}
    assert checks["Uses SHA1 Hashing Algorithm"].result.value == "present"
    assert checks["Contains Reflection Code"].result.value == "not_evaluated"


def test_missing_security_scanner_keeps_canonical_checks_not_evaluated() -> None:
    sections = NativeAndroidScanDetailExtractor().extract_sections(
        {
            "scan_metadata": {"project_path": "/workspace/Example", "target_type": "SOURCE"},
            "source_metadata": {"application": {"debuggable": False, "allow_backup": False}},
        }
    )

    report = _report(sections)
    code = next(section for section in report.vulnerability_sections if section.name == "Code")
    checks = {check.name: check for check in code.checks}
    assert checks["App is Debuggable"].result.value == "not_present"
    assert checks["Contains Potential SQL Injection"].result.value == "not_evaluated"
    assert report.findings_severity.high == 0
    assert report.findings_severity.info == 0


def test_report_presentation_contains_risk_chart() -> None:
    report = _report(NativeAndroidScanDetailExtractor().extract_sections({}))
    presentation = PdfReportGenerator._presentation_data(report)
    assert build_charts(presentation)["overall_risk_polar"]

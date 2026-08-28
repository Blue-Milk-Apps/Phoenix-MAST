from __future__ import annotations

from pathlib import Path

import yaml

from adapters.output.phoenix_report.generate_report import build_charts, load_report_data
from adapters.post_scan import NativeAndroidScanDetailExtractor
from domain.post_scan.android.rule_registry import (
    ANDROID_RULE_REGISTRY,
    REPORT_RULE_IDS_BY_SECTION,
    AndroidRuleDisposition,
    unclassified_android_rule_ids,
)

SECURITY_RULE_IDS = sorted(
    rule_id for section in REPORT_RULE_IDS_BY_SECTION.values() for rule_ids in section.values() for rule_id in rule_ids
)


def test_all_bundled_android_rules_are_explicitly_classified() -> None:
    rule_ids: set[str] = set()
    rules_root = Path(__file__).parents[4] / "rules" / "android"
    for rules_path in rules_root.glob("*.yml"):
        document = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
        for rule in document["rules"]:
            rule_id = rule["id"]
            rule_ids.add(rule_id)
            phoenix = (rule.get("metadata") or {}).get("phoenix") or {}
            mapping = ANDROID_RULE_REGISTRY[rule_id]
            if mapping.disposition is AndroidRuleDisposition.REPORT_VULNERABILITY:
                assert phoenix["report_section"] == mapping.section
                assert phoenix["evidence_key"] == mapping.evidence_key

    assert unclassified_android_rule_ids(rule_ids) == set()
    assert set(ANDROID_RULE_REGISTRY) == rule_ids


def test_source_security_evidence_uses_exact_rules_and_relative_locations() -> None:
    loaded_outputs = {
        "scan_metadata": {
            "project_path": "/workspace/Example",
            "target_type": "SOURCE",
        },
        "source_metadata": {
            "application": {
                "debuggable": False,
                "allow_backup": True,
                "uses_cleartext_traffic": None,
            },
            "components": {
                "activities": [{"name": "com.example.MainActivity", "exported": True}],
                "services": [],
                "receivers": [],
                "providers": [],
            },
            "permissions": [],
            "deep_links": [],
        },
        "opengrep": {
            "success": True,
            "scan_metadata": {
                "rules_path": "/phoenix/rules/android",
                "configured_rule_ids": SECURITY_RULE_IDS,
            },
            "results": [
                {
                    "check_id": "android.source.sha1",
                    "path": "/workspace/Example/app/src/main/Crypto.kt",
                    "start": {"line": 18},
                    "extra": {"message": "SHA-1 hashing usage was detected."},
                },
                {
                    "check_id": "unregistered.android.rule",
                    "path": "/workspace/Example/app/src/main/Ignored.kt",
                    "start": {"line": 2},
                    "extra": {"message": "SHA-1 text from an unrelated rule."},
                },
            ],
        },
    }

    sections = NativeAndroidScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["code_evidence"]["uses_sha1_hashing_algorithm"] == {
        "present": True,
        "evidence": "app/src/main/Crypto.kt:18: SHA-1 hashing usage was detected.",
        "details": ["app/src/main/Crypto.kt:18: SHA-1 hashing usage was detected."],
    }
    assert sections["code_evidence"]["contains_reflection_code"]["present"] is False
    assert sections["code_evidence"]["contains_hard_coded_cryptographic_key"]["present"] is None
    assert "Ignored.kt" not in str(sections["code_evidence"])

    report = load_report_data(sections)
    code = next(section for section in report["vulnerability_sections"] if section["section_name"] == "Code")
    checks = {check["check"]: check for check in code["checks"]}
    assert checks["Uses SHA1 Hashing Algorithm"]["result"] == "Present"
    assert checks["Contains Reflection Code"]["result"] == "Not Present"
    assert checks["Contains Hard-coded Cryptographic Key"]["result"] == "Not Evaluated"
    assert report["findings_severity"]["high"] == 2


def test_missing_security_scanner_does_not_produce_false_clean_results() -> None:
    sections = NativeAndroidScanDetailExtractor().extract_sections(
        {
            "scan_metadata": {"project_path": "/workspace/Example", "target_type": "SOURCE"},
            "source_metadata": {
                "application": {
                    "debuggable": False,
                    "allow_backup": False,
                    "uses_cleartext_traffic": None,
                }
            },
        }
    )

    assert set(key for key in sections if key.endswith("_evidence")) == {"code_evidence"}
    report = load_report_data(sections)
    assert report["report_scope"]["assessed_sections"] == ("code",)
    assert [section["section_name"] for section in report["vulnerability_sections"]] == ["Code"]
    checks = {check["check"]: check for check in report["vulnerability_sections"][0]["checks"]}
    assert checks["App is Debuggable"]["result"] == "Not Present"
    assert checks["Contains Potential SQL Injection"]["result"] == "Not Evaluated"
    assert checks["Contains Hard-coded Cryptographic Key"]["result"] == "Not Evaluated"
    assert report["findings_severity"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "secure": 0,
    }


def test_legacy_opengrep_output_without_rule_inventory_is_not_security_assessed() -> None:
    sections = NativeAndroidScanDetailExtractor().extract_sections(
        {
            "scan_metadata": {"project_path": "/workspace/Example", "target_type": "SOURCE"},
            "source_metadata": {"application": {"debuggable": False}},
            "opengrep": {
                "success": True,
                "results": [],
                "scan_metadata": {"rules_path": "/phoenix/rules/android"},
            },
        }
    )

    assert sections["code_evidence"]["contains_potential_sql_injection"]["present"] is None
    assert "network_evidence" not in sections
    assert "resilience_evidence" not in sections


def test_report_handles_source_scan_with_no_assessed_security_sections() -> None:
    sections = NativeAndroidScanDetailExtractor().extract_sections(
        {"scan_metadata": {"project_path": "/workspace/Example", "target_type": "SOURCE"}}
    )

    report = load_report_data(sections)

    assert report["report_scope"]["assessed_sections"] == ()
    assert report["vulnerability_sections"] == []
    assert report["risk_summary"] == {}
    assert build_charts(report)["overall_risk_polar"]

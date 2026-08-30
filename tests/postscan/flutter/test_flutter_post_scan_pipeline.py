"""End-to-end coverage for the Flutter post-scan processing pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.post_scan.flutter import FlutterScanDetailExtractor, FlutterScanOutputLoader
from application.post_scan_processing_service import PostScanProcessingService


def test_persisted_flutter_artifacts_produce_the_complete_section_contract(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "scan_metadata.json",
        {
            "project_path": "/workspace/example_app",
            "platform": "ANY",
            "stack": "FLUTTER",
            "target_type": "SOURCE",
        },
    )
    _write_json(
        tmp_path / "flutter_source_metadata" / "project_metadata.json",
        {
            "extraction": {"status": "complete", "warnings": []},
            "identity": {"package_name": "example_app", "version_name": "1.0.0"},
            "platforms": {"android": True, "ios": False},
            "android": {
                "available": True,
                "metadata": {
                    "identity": {
                        "app_name": "Example App",
                        "package_name": "com.example.app",
                    },
                    "application": {"debuggable": False},
                    "components": {"activities": [], "receivers": [], "services": []},
                    "permissions": [{"name": "android.permission.CAMERA"}],
                    "deep_links": [],
                },
            },
            "dependencies": {
                "direct": [{"name": "http", "constraint": "^1.2.0", "source": "hosted"}],
                "development": [],
                "resolved": [],
            },
        },
    )
    _write_json(
        tmp_path / "opengrep_source" / "opengrep_results.json",
        {
            "results": [
                _finding("flutter.source.sql-injection", "flutter", "lib/database.dart", 10),
                _finding("flutter.source.cleartext-http", "flutter", "lib/client.dart", 20),
                _finding("flutter.source.sensitive-hive-storage", "flutter", "lib/storage.dart", 30),
                _finding("flutter.source.unsafe-platform-channel", "flutter", "lib/channel.dart", 40),
                _finding(
                    "android.source.unsafe-biometric-auth",
                    "android",
                    "android/app/Auth.kt",
                    50,
                ),
            ],
            "scan_metadata": {
                "scopes": {
                    "flutter": {
                        "status": "success",
                        "configured_rule_ids": [
                            "flutter.source.sql-injection",
                            "flutter.source.cleartext-http",
                            "flutter.source.sensitive-hive-storage",
                            "flutter.source.unsafe-platform-channel",
                        ],
                    },
                    "android": {"status": "failed", "configured_rule_ids": []},
                }
            },
        },
    )
    _write_json(tmp_path / "gitleaks" / "gitleaks_report.json", [])
    _write_json(
        tmp_path / "syft" / "sbom.json",
        {"artifacts": [{"name": "http", "version": "1.2.0"}]},
    )

    sections = PostScanProcessingService(
        scan_output_loader=FlutterScanOutputLoader(),
        scan_detail_extractor=FlutterScanDetailExtractor(),
    ).process(tmp_path)

    assert set(sections) == {
        "meta",
        "file_info",
        "app_info",
        "platform_inventory",
        "dependency_inventory",
        "application",
        "app_components",
        "permissions",
        "deep_links",
        "url_schemes",
        "queried_url_schemes",
        "functionality",
        "hardcoded_values",
        "endpoints",
        "manual_review",
        "code_evidence",
        "network_evidence",
        "data_storage_evidence",
        "resilience_evidence",
    }
    assert sections["meta"]["platform"] == "Flutter"
    assert sections["platform_inventory"]["android"]["metadata_assessed"] is True
    assert sections["dependency_inventory"]["sbom_assessed"] is True
    assert sections["functionality"]["Camera"]["present"] is True
    assert sections["hardcoded_values"] == {"urls": [], "emails": [], "secrets": []}
    assert sections["manual_review"]["findings"][0]["rule_id"] == ("flutter.source.unsafe-platform-channel")
    assert sections["code_evidence"]["contains_potential_sql_injection"]["present"] is True
    assert sections["network_evidence"]["sensitive_information_unencrypted_in_transit"]["present"] is True
    assert sections["data_storage_evidence"]["sensitive_values_stored_insecurely"]["present"] is True
    assert sections["resilience_evidence"]["biometric_local_authentication_bypass_possible"]["present"] is True
    for section_name in (
        "code_evidence",
        "network_evidence",
        "data_storage_evidence",
        "resilience_evidence",
    ):
        assert "assessed" not in sections[section_name]
    json.dumps(sections)


def _finding(rule_id: str, scope: str, path: str, line: int) -> dict[str, Any]:
    return {
        "check_id": rule_id,
        "phoenix_scope": scope,
        "path": f"/workspace/example_app/{path}",
        "start": {"line": line},
    }


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")

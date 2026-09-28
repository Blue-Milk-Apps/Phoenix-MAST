"""End-to-end coverage for the Flutter post-scan processing pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.post_scan.flutter import FlutterScanDetailExtractor, FlutterScanOutputLoader
from application.post_scan_processing_service import PostScanProcessingService
from tests.rule_fixtures import assessment_payload, rule, scoped_payload


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
    definition = rule("example.framework-review", finding_type="review")
    camera = rule("example.camera", finding_type="observation")
    camera["metadata"].update(functionality="Camera", scope="app_declaration")
    _write_json(
        tmp_path / "opengrep_source" / "opengrep_results.json",
        scoped_payload(
            flutter=assessment_payload(
                definition, category="code", results=[_finding(definition["id"], "flutter", "lib/channel.dart", 40)]
            ),
            android=assessment_payload(
                camera,
                category="functionality",
                results=[
                    {
                        **_finding(camera["id"], "android", "android/AndroidManifest.xml", 5),
                        "extra": {"metavars": {"$PERMISSION": {"abstract_content": "android.permission.CAMERA"}}},
                    }
                ],
            ),
        ),
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
        "rule_assessments",
        "secret_scans",
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
    }
    assert sections["meta"]["platform"] == "Flutter"
    assert sections["platform_inventory"]["android"]["metadata_assessed"] is True
    assert sections["dependency_inventory"]["sbom_assessed"] is True
    assert sections["functionality"]["Camera"]["present"] is True
    assert sections["hardcoded_values"] == {"urls": [], "emails": [], "secrets": []}
    assert sections["permissions"][0]["permission"] == "android.permission.CAMERA"
    checks = sections["rule_assessments"]["rules"]
    assert [check["rule_id"] for check in checks] == [definition["id"], camera["id"]]
    assert all(check["status"] == "present" for check in checks)
    assert checks[0]["metadata"] == definition["metadata"]
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

import json
from pathlib import Path

from adapters.post_scan.react_native.scan_output_loader import ReactNativeScanOutputLoader
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext
from domain.post_scan.rule_assessment import rule_assessments
from tests.rule_fixtures import assessment_payload, rule


def test_loader_context_and_tri_state_assessment(tmp_path: Path) -> None:
    (tmp_path / "react_native_source_metadata").mkdir()
    (tmp_path / "opengrep_source").mkdir()
    (tmp_path / "scan_metadata.json").write_text(
        json.dumps({"project_path": "/project", "target_type": "SOURCE"}), encoding="utf-8"
    )
    (tmp_path / "react_native_source_metadata" / "project_metadata.json").write_text(
        json.dumps(
            {
                "identity": {"package_name": "mobile"},
                "platforms": {"android": True, "ios": False, "web": True},
                "dependencies": {"declared": [], "resolved": []},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "opengrep_source" / "opengrep_results.json").write_text(
        json.dumps(
            {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "react_native": {
                            "status": "success",
                            "applicable": True,
                            "configured_rule_ids": ["react-native.source.cleartext-http"],
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    context = ReactNativeScanExtractionContext(ReactNativeScanOutputLoader().load(tmp_path))
    assert context.platforms == {"android": True, "ios": False}
    # Older artifacts without a catalog cannot manufacture rule outcomes.
    assert rule_assessments(context.opengrep)["rules"] == []
    output = assessment_payload(rule("example.new"), platform="react_native")
    assert rule_assessments(output)["rules"][0]["status"] == "not_present"
    output["scan_metadata"]["rule_execution"] = {}
    assert rule_assessments(output)["rules"][0]["status"] == "not_evaluated"


def test_loader_tolerates_missing_and_invalid_artifacts(tmp_path: Path) -> None:
    (tmp_path / "scan_metadata.json").write_text("not-json", encoding="utf-8")

    loaded = ReactNativeScanOutputLoader().load(tmp_path)
    context = ReactNativeScanExtractionContext(loaded)

    assert loaded["scan_metadata"] is None
    assert context.identity == {}
    assert context.opengrep_results == []


def test_empty_valid_sbom_is_assessed() -> None:
    context = ReactNativeScanExtractionContext({"syft_outputs": {"sbom.json": {"artifacts": []}}})

    assert context.syft_assessed is True
    assert context.syft_packages == []

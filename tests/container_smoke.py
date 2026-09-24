"""Run explicitly inside an ephemeral image; no private rules or network needed."""

import json
import os
import plistlib
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from entrypoints.cli import _build_parser, _create_scan_config


def main():
    rules_root = Path("/app/rules")
    assert os.environ["PHOENIX_RULES_ROOT"] == str(rules_root)
    assert not list(rules_root.rglob("*.yml")), "Private rules must not be bundled"
    assert not list(rules_root.rglob("*.yaml")), "Private rules must not be bundled"

    for flag, relative in (
        ("--ios-source", "ios/source"),
        ("--android-source", "android/source"),
        ("--flutter-source", "flutter/source"),
        ("--react-native-source", "react_native/source"),
        ("--ios-binary", "ios/binary"),
        ("--android-binary", "android/binary"),
    ):
        config = _create_scan_config(_build_parser().parse_args(["scan", flag, "/workspace"]))
        assert config.opengrep_rules_path == rules_root / relative
        assert config.opengrep_rules_root == rules_root

    for tool in (
        "phoenix",
        "opengrep",
        "opengrep-core",
        "gitleaks",
        "trufflehog",
        "syft",
        "strings",
        "ipsw",
        "apktool",
        "apksigner",
    ):
        assert shutil.which(tool), f"Missing scanner executable: {tool}"

    rule = {
        "id": "phoenix.container.smoke",
        "languages": ["generic"],
        "severity": "WARNING",
        "message": "Synthetic container verification marker",
        "pattern-regex": "PHOENIX_CONTAINER_SMOKE",
        "metadata": {
            "title": "Container smoke check",
            "description": "A synthetic marker validates the scanner and report pipeline.",
            "scope": "matched_code",
            "impact": "Synthetic test data only.",
            "finding_type": "observation",
            "remediation": {"guidance": "No action required for the synthetic fixture."},
        },
    }
    rule_path = rules_root / "ios/source/smoke.yml"
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text(yaml.safe_dump({"rules": [rule]}))

    with TemporaryDirectory(prefix="phoenix-smoke-") as temporary:
        root = Path(temporary)
        source = root / "source"
        source.mkdir()
        (source / "Example.swift").write_text("// PHOENIX_CONTAINER_SMOKE\n")
        (source / "Info.plist").write_bytes(
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "test.phoenix.container",
                    "CFBundleName": "Phoenix Container Smoke",
                    "CFBundleShortVersionString": "1.0",
                }
            )
        )
        output = root / "results"
        subprocess.run(
            ["phoenix", "scan", "--ios-source", str(source), "--output", str(output)],
            check=True,
            timeout=180,
        )
        artifacts = list(output.rglob("opengrep_results.json"))
        assert len(artifacts) == 1, artifacts
        result = json.loads(artifacts[0].read_text())
        assert not result.get("errors"), result.get("errors")
        catalog = result["scan_metadata"]["rule_catalog"]
        assert len(catalog) == 1, catalog
        assert catalog[0]["rule_id"] == rule["id"], catalog
        assert result["results"], "The synthetic marker was not detected"
        executions = result["scan_metadata"]["rule_execution"]
        assert executions[rule["id"]]["status"] == "success", executions
        reports = list(output.rglob("*.pdf"))
        assert len(reports) == 1, reports
        assert reports[0].read_bytes().startswith(b"%PDF"), "Invalid PDF output"

    print("Container smoke passed: default rule routing, scanners, synthetic iOS finding, and PDF report.")


if __name__ == "__main__":
    main()

"""Synthetic rule definitions for the public engine's metadata contract tests."""

from pathlib import Path

import yaml

from domain.post_scan.rule_assessment import RuleDefinition


def rule(rule_id="example.check", *, finding_type="weakness", severity="HIGH", title="Example check"):
    return {
        "id": rule_id,
        "message": "Example matched",
        "severity": severity,
        "languages": ["generic"],
        "pattern-regex": "EXAMPLE_MARKER",
        "metadata": {
            "finding_type": finding_type,
            "scope": "matched_code",
            "title": title,
            "description": "An example marker was found.",
            "impact": "Review the example context.",
            "remediation": {
                "guidance": "Remove the example marker.",
                "resources": [{"title": "Example", "url": "https://example.test/guide"}],
            },
            "compliance": {"example_standard": [{"id": "A1", "relationship": "review_context"}]},
        },
    }


def write_rules(path: Path, *definitions):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"rules": list(definitions or (rule(),))}, sort_keys=False))
    return path


def private_rules(platform: str) -> Path:
    import os

    import pytest

    location = os.environ.get("PHOENIX_RULES_ROOT")
    if not location:
        pytest.skip("Set PHOENIX_RULES_ROOT to test a private rules checkout")
    path = Path(location) / platform / "source"
    if not path.is_dir():
        pytest.fail(f"Configured private rules directory is missing: {path}")
    return path


def assessment_payload(*definitions, status="success", results=(), platform="ios", category="custom"):
    return {
        "results": list(results),
        "scan_metadata": {
            "platform": platform,
            "mode": "source",
            "status": status,
            "rule_catalog": [
                RuleDefinition.from_rule(
                    item, category=category, rule_file=f"{category}.yml", fingerprint="example"
                ).snapshot()
                for item in definitions
            ],
            "rule_execution": {item["id"]: {"status": status} for item in definitions},
        },
    }

"""Tests for raw-only Flutter manual-review inventory."""

from __future__ import annotations

from domain.post_scan.flutter import FlutterManualReviewInventory, FlutterScanExtractionContext
from domain.post_scan.ios.rule_registry import RAW_ONLY_RULE_REASONS as IOS_RAW_ONLY_RULE_REASONS


def test_preserves_raw_only_findings_without_promoting_report_rules() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/app"},
            "source_metadata": {
                "platforms": {"ios": True},
                "ios": {"available": True, "metadata": {}},
            },
            "opengrep": {
                "results": [
                    {
                        "check_id": "flutter.source.unsafe-platform-channel",
                        "phoenix_scope": "flutter",
                        "path": "/workspace/app/lib/channel.dart",
                        "start": {"line": 17},
                        "extra": {"message": "Privileged platform channel handler"},
                    },
                    {
                        "check_id": "private-api-usage-dynamic",
                        "phoenix_scope": "ios",
                        "path": "/workspace/app/ios/Runner/Bridge.swift",
                        "start": {"line": 8},
                        "extra": {"message": "Dynamic private API usage"},
                    },
                    {
                        "check_id": "flutter.source.sql-injection",
                        "phoenix_scope": "flutter",
                        "path": "/workspace/app/lib/database.dart",
                    },
                    {
                        "check_id": "fileprotection-complete-applevel",
                        "phoenix_scope": "ios",
                        "path": "/workspace/app/ios/Runner/Secure.swift",
                    },
                ],
                "scan_metadata": {
                    "scopes": {
                        "flutter": {
                            "status": "success",
                            "configured_rule_ids": ["flutter.source.unsafe-platform-channel"],
                        },
                        "ios": {
                            "status": "success",
                            "configured_rule_ids": sorted(IOS_RAW_ONLY_RULE_REASONS),
                        },
                    }
                },
            },
        }
    )

    inventory = FlutterManualReviewInventory(context)

    assert inventory.assessed is True
    assert inventory.fully_assessed is True
    assert inventory.assessed_scopes == ["flutter", "ios"]
    assert [finding.rule_id for finding in inventory.findings] == [
        "flutter.source.unsafe-platform-channel",
        "private-api-usage-dynamic",
    ]
    assert inventory.findings[0].scope == "flutter"
    assert inventory.findings[0].severity == "Medium"
    assert inventory.findings[0].location == "lib/channel.dart:17"
    assert "manual review" in inventory.findings[0].reason.lower()
    assert inventory.findings[1].scope == "ios"
    assert inventory.findings[1].severity == "Info"
    assert inventory.findings[1].location == "ios/Runner/Bridge.swift:8"


def test_partial_raw_rule_inventory_is_not_fully_assessed() -> None:
    context = FlutterScanExtractionContext(
        {
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "flutter": {"status": "success", "configured_rule_ids": []},
                    }
                },
            }
        }
    )

    inventory = FlutterManualReviewInventory(context)

    assert inventory.assessed is False
    assert inventory.fully_assessed is False
    assert inventory.assessed_scopes == []
    assert inventory.findings == []

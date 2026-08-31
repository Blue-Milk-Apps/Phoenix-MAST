"""Tests for embedded-platform Flutter report projections."""

from __future__ import annotations

from dataclasses import asdict

from domain.post_scan.flutter import (
    FlutterAppComponents,
    FlutterApplication,
    FlutterDeepLinks,
    FlutterPermissions,
    FlutterScanExtractionContext,
    FlutterURLSchemes,
)


def test_builds_android_and_ios_report_projections() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/example_app"},
            "source_metadata": {
                "identity": {"package_name": "example_app"},
                "android": {
                    "available": True,
                    "metadata": {
                        "application": {
                            "debuggable": False,
                            "allow_backup": True,
                            "uses_cleartext_traffic": False,
                        },
                        "permissions": [
                            {"name": "android.permission.CAMERA"},
                            {"name": "android.permission.CAMERA"},
                            {"name": "com.example.permission.CUSTOM"},
                        ],
                        "components": {
                            "activities": [
                                {"name": "com.example.MainActivity", "exported": True},
                                {"name": "com.example.InternalActivity", "exported": False},
                            ],
                            "services": [],
                            "receivers": [{"name": "com.example.Receiver", "exported": True}],
                            "providers": [],
                        },
                        "deep_links": [{"scheme": "example", "host": "open"}],
                    },
                },
                "ios": {
                    "available": True,
                    "metadata": {
                        "identity": {"display_name": "Example iOS App"},
                        "permissions": [
                            {"key": "NSCameraUsageDescription", "purpose": "Take profile photos"},
                            {"key": "NSCameraUsageDescription", "purpose": "Duplicate"},
                        ],
                        "url_schemes": {
                            "declared_schemes": ["example", "example"],
                            "queried_schemes": ["partner", "partner"],
                        },
                    },
                },
            },
        }
    )

    assert asdict(FlutterApplication(context)) == {
        "debuggable": False,
        "allow_backup": True,
        "uses_cleartext_traffic": False,
    }
    assert asdict(FlutterAppComponents(context)) == {
        "activities": 2,
        "services": 0,
        "receivers": 1,
        "providers": 0,
        "exported_activities": 1,
        "exported_services": 0,
        "exported_receivers": 1,
        "exported_providers": 0,
    }
    permissions = FlutterPermissions(context)
    assert permissions.assessed_platforms == ["android", "ios"]
    assert [item["platform"] for item in permissions.items] == ["Android", "Android", "iOS"]
    assert permissions.items[0]["permission"] == "android.permission.CAMERA"
    assert permissions.items[0]["general_description"] == "Allows the app to access the device camera."
    assert permissions.items[1]["permission"] == "com.example.permission.CUSTOM"
    assert permissions.items[2] == {
        "platform": "iOS",
        "permission": "NSCameraUsageDescription",
        "status": "dangerous",
        "info": "Access Camera",
        "usage_description": "Take profile photos",
        "general_description": "Permits access to the device's camera hardware.",
    }
    assert asdict(FlutterDeepLinks(context)) == {"deep_links": [{"scheme": "example", "host": "open"}]}
    url_schemes = FlutterURLSchemes(context)
    assert url_schemes.assessed is True
    assert url_schemes.items == [{"url_name": "Example iOS App", "schemes": ["example"]}]
    assert url_schemes.queried_schemes == ["partner"]


def test_empty_platform_collections_are_assessed_as_empty() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "android": {
                    "available": True,
                    "metadata": {
                        "permissions": [],
                        "components": {
                            "activities": [],
                            "services": [],
                            "receivers": [],
                            "providers": [],
                        },
                        "deep_links": [],
                    },
                },
                "ios": {
                    "available": True,
                    "metadata": {"permissions": [], "url_schemes": {}},
                },
            }
        }
    )

    assert all(value == 0 for value in asdict(FlutterAppComponents(context)).values())
    assert FlutterPermissions(context).items == []
    assert FlutterPermissions(context).assessed_platforms == ["android", "ios"]
    assert FlutterDeepLinks(context).deep_links == []
    assert FlutterURLSchemes(context).assessed is True
    assert FlutterURLSchemes(context).items == []


def test_missing_or_malformed_platform_metadata_remains_unknown() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "android": {
                    "available": True,
                    "metadata": {"application": {"debuggable": "false"}},
                },
                "ios": {"available": True, "metadata": None},
            }
        }
    )

    assert asdict(FlutterApplication(context)) == {
        "debuggable": None,
        "allow_backup": None,
        "uses_cleartext_traffic": None,
    }
    assert all(value is None for value in asdict(FlutterAppComponents(context)).values())
    assert FlutterPermissions(context).items == []
    assert FlutterPermissions(context).assessed_platforms == []
    assert FlutterDeepLinks(context).deep_links is None
    assert FlutterURLSchemes(context).assessed is False
    assert FlutterURLSchemes(context).items == []

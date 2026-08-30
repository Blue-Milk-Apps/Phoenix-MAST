"""Tests for Flutter generated-platform and SDK inventory."""

from __future__ import annotations

from dataclasses import asdict

from domain.post_scan.flutter import FlutterPlatformInventory, FlutterScanExtractionContext


def test_builds_complete_platform_and_sdk_inventory() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "extraction": {"status": "complete", "warnings": []},
                "identity": {"version_name": "1.2.3", "version_code": "42"},
                "sdk": {
                    "dart_constraint": ">=3.3.0 <4.0.0",
                    "flutter_constraint": ">=3.22.0",
                },
                "platforms": {
                    "android": True,
                    "ios": True,
                    "web": True,
                    "linux": False,
                    "macos": True,
                    "windows": False,
                },
                "android": {
                    "available": True,
                    "metadata": {
                        "identity": {
                            "app_name": "Example App",
                            "package_name": "com.example.android",
                            "namespace": "com.example",
                            "main_activity": "com.example.android.MainActivity",
                            "compile_sdk": "35",
                            "min_sdk": "24",
                            "target_sdk": "35",
                            "version_name": "1.2.3-android",
                            "version_code": "43",
                        }
                    },
                },
                "ios": {
                    "available": True,
                    "metadata": {
                        "identity": {
                            "display_name": "Example iOS App",
                            "bundle_name": "ExampleApp",
                            "bundle_identifier": "com.example.ios",
                            "executable": "ExampleApp",
                            "minimum_os": "13.0",
                            "version": "1.2.3-ios",
                            "build": "44",
                        }
                    },
                },
            }
        }
    )

    assert asdict(FlutterPlatformInventory(context)) == {
        "source_metadata_assessed": True,
        "sdk": {
            "dart_constraint": ">=3.3.0 <4.0.0",
            "flutter_constraint": ">=3.22.0",
        },
        "android": {
            "detected": True,
            "metadata_assessed": True,
            "app_name": "Example App",
            "package_name": "com.example.android",
            "namespace": "com.example",
            "main_activity": "com.example.android.MainActivity",
            "compile_sdk": "35",
            "min_sdk": "24",
            "target_sdk": "35",
            "version_name": "1.2.3-android",
            "version_code": "43",
        },
        "ios": {
            "detected": True,
            "metadata_assessed": True,
            "display_name": "Example iOS App",
            "bundle_name": "ExampleApp",
            "bundle_identifier": "com.example.ios",
            "executable": "ExampleApp",
            "minimum_os": "13.0",
            "version_name": "1.2.3-ios",
            "version_code": "44",
        },
        "web_detected": True,
        "linux_detected": False,
        "macos_detected": True,
        "windows_detected": False,
        "warnings": [],
    }


def test_distinguishes_detected_platforms_from_failed_metadata_extraction() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "extraction": {
                    "status": "partial",
                    "warnings": ["Android metadata failed", "iOS metadata failed"],
                },
                "identity": {"version_name": "2.0.0", "version_code": "7"},
                "platforms": {"android": True, "ios": True},
                "android": {"available": True, "metadata": None},
                "ios": {"available": True, "metadata": None},
            }
        }
    )

    inventory = FlutterPlatformInventory(context)

    assert inventory.android.detected is True
    assert inventory.android.metadata_assessed is False
    assert inventory.android.version_name == "2.0.0"
    assert inventory.android.version_code == "7"
    assert inventory.ios.detected is True
    assert inventory.ios.metadata_assessed is False
    assert inventory.ios.version_name == "2.0.0"
    assert inventory.ios.version_code == "7"
    assert inventory.warnings == ["Android metadata failed", "iOS metadata failed"]


def test_missing_source_metadata_remains_unassessed_and_empty() -> None:
    inventory = FlutterPlatformInventory(FlutterScanExtractionContext({"source_metadata": None}))

    assert inventory.source_metadata_assessed is False
    assert inventory.android.detected is False
    assert inventory.android.metadata_assessed is False
    assert inventory.ios.detected is False
    assert inventory.ios.metadata_assessed is False
    assert inventory.web_detected is False
    assert inventory.sdk.dart_constraint == ""
    assert inventory.sdk.flutter_constraint == ""
    assert inventory.warnings == []

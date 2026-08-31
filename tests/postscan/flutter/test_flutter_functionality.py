"""Tests for Flutter embedded-platform functionality inventory."""

from __future__ import annotations

from domain.post_scan.android.rule_registry import FUNCTIONALITY_RULE_IDS as ANDROID_FUNCTIONALITY_RULE_IDS
from domain.post_scan.flutter import FlutterFunctionality, FlutterScanExtractionContext
from domain.post_scan.ios.rule_registry import FUNCTIONALITY_RULE_ID_TO_KEY as IOS_FUNCTIONALITY_RULES


def test_combines_android_ios_permissions_metadata_and_functionality_rules() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/app"},
            "source_metadata": {
                "platforms": {"android": True, "ios": True},
                "android": {
                    "available": True,
                    "metadata": {"permissions": [{"name": "android.permission.CAMERA"}]},
                },
                "ios": {
                    "available": True,
                    "metadata": {
                        "permissions": [{"key": "NSMicrophoneUsageDescription", "purpose": "Record audio"}],
                        "app_transport_security": {},
                        "url_schemes": {},
                        "background_modes": ["remote-notification"],
                        "entitlements": [
                            {
                                "path": "Runner.entitlements",
                                "metadata": {"keychain_access_groups": ["com.example.shared"]},
                            }
                        ],
                    },
                },
            },
            "opengrep": {
                "results": [
                    {
                        "check_id": "android.maps.usage.present",
                        "phoenix_scope": "android",
                        "path": "/workspace/app/android/app/Map.kt",
                        "start": {"line": 12},
                        "extra": {"metadata": {"phoenix": {"description": "Maps API detected"}}},
                    },
                    {
                        "check_id": "loc-usage-desc",
                        "phoenix_scope": "ios",
                        "path": "/workspace/app/ios/Runner/Info.plist",
                        "extra": {"message": "Location usage description detected"},
                    },
                ],
                "scan_metadata": {"scopes": {}},
            },
        }
    )

    functionality = FlutterFunctionality(context)

    assert functionality.assessed is True
    assert functionality.fully_assessed is False
    assert functionality.items["Camera"] == {
        "present": True,
        "explanation": "Declared Android permission: android.permission.CAMERA.",
    }
    assert functionality.items["Microphone"] == {
        "present": True,
        "explanation": "Declared iOS permission: NSMicrophoneUsageDescription.",
    }
    assert functionality.items["Maps"]["present"] is True
    assert "android/app/Map.kt:12" in functionality.items["Maps"]["explanation"]
    assert functionality.items["Location"]["present"] is True
    assert functionality.items["Keychain"]["present"] is True
    assert functionality.items["Push Notifications"]["present"] is True
    assert functionality.items["SMS"]["present"] is None


def test_complete_platform_sources_allow_negative_functionality_inventory() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"android": True, "ios": True},
                "android": {"available": True, "metadata": {"permissions": []}},
                "ios": {"available": True, "metadata": {"permissions": []}},
            },
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "android": {
                            "status": "success",
                            "configured_rule_ids": sorted(ANDROID_FUNCTIONALITY_RULE_IDS),
                        },
                        "ios": {
                            "status": "success",
                            "configured_rule_ids": sorted(IOS_FUNCTIONALITY_RULES),
                        },
                    }
                },
            },
        }
    )

    functionality = FlutterFunctionality(context)

    assert functionality.assessed is True
    assert functionality.fully_assessed is True
    assert all(item["present"] is False for item in functionality.items.values())


def test_missing_functionality_sources_remain_unknown() -> None:
    functionality = FlutterFunctionality(FlutterScanExtractionContext({}))

    assert functionality.assessed is False
    assert functionality.fully_assessed is False
    assert all(item["present"] is None for item in functionality.items.values())

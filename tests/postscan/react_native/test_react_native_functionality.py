"""Tests for React Native mobile functionality detection."""

from domain.post_scan.android.rule_registry import FUNCTIONALITY_RULE_IDS as ANDROID_FUNCTIONALITY_RULE_IDS
from domain.post_scan.ios.rule_registry import FUNCTIONALITY_RULE_ID_TO_KEY as IOS_FUNCTIONALITY_RULES
from domain.post_scan.react_native import ReactNativeFunctionality
from domain.post_scan.react_native.report_models import build_report_sections
from domain.post_scan.react_native.rule_registry import (
    FUNCTIONALITY_RULE_ID_TO_KEY as REACT_NATIVE_FUNCTIONALITY_RULES,
)
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


def test_combines_android_ios_metadata_and_functionality_rules() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/app"},
            "source_metadata": {
                "platforms": {"android": True, "ios": True, "web": True},
                "android": {
                    "available": True,
                    "metadata": {"permissions": [{"name": "android.permission.CAMERA"}]},
                },
                "ios": {
                    "available": True,
                    "metadata": {
                        "permissions": [{"key": "NSMicrophoneUsageDescription", "purpose": "Record audio"}],
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

    functionality = ReactNativeFunctionality(context)

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
    assert "Web" not in functionality.items


def test_absent_mobile_platform_does_not_block_negative_results() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"android": True, "ios": False},
                "android": {"available": True, "metadata": {"permissions": []}},
                "ios": {"available": False, "metadata": None},
            },
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "android": {
                            "status": "success",
                            "applicable": True,
                            "configured_rule_ids": sorted(ANDROID_FUNCTIONALITY_RULE_IDS),
                        },
                        "ios": {"status": "skipped", "applicable": False, "configured_rule_ids": []},
                    }
                },
            },
        }
    )

    functionality = ReactNativeFunctionality(context)

    assert functionality.assessed is True
    assert functionality.fully_assessed is True
    assert all(item["present"] is False for item in functionality.items.values())


def test_missing_functionality_sources_remain_unknown() -> None:
    functionality = ReactNativeFunctionality(ReactNativeScanExtractionContext({}))

    assert functionality.assessed is False
    assert functionality.fully_assessed is False
    assert all(item["present"] is None for item in functionality.items.values())


def test_complete_ios_sources_allow_negative_functionality_inventory() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"android": False, "ios": True},
                "android": {"available": False, "metadata": None},
                "ios": {"available": True, "metadata": {"permissions": []}},
            },
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "ios": {
                            "status": "success",
                            "applicable": True,
                            "configured_rule_ids": sorted(IOS_FUNCTIONALITY_RULES),
                        }
                    }
                },
            },
        }
    )

    functionality = ReactNativeFunctionality(context)

    assert functionality.fully_assessed is True
    assert all(item["present"] is False for item in functionality.items.values())


def test_javascript_only_react_native_scope_detects_functionality() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/app"},
            "source_metadata": {"platforms": {"android": False, "ios": False}},
            "opengrep": {
                "results": [
                    {
                        "check_id": "react-native.functionality.networking",
                        "phoenix_scope": "react_native",
                        "path": "/workspace/app/src/network.ts",
                        "start": {"line": 4},
                        "extra": {"message": "React Native-specific networking functionality is used."},
                    }
                ],
                "scan_metadata": {
                    "scopes": {
                        "react_native": {
                            "status": "success",
                            "applicable": True,
                            "configured_rule_ids": sorted(REACT_NATIVE_FUNCTIONALITY_RULES),
                        }
                    }
                },
            },
        }
    )

    functionality = ReactNativeFunctionality(context)

    assert functionality.applicable is True
    assert functionality.fully_assessed is True
    assert functionality.items["Networking"]["present"] is True
    assert "src/network.ts:4" in functionality.items["Networking"]["explanation"]
    assert functionality.items["Camera"]["present"] is False


def test_older_react_native_scan_without_functionality_rules_is_applicable_but_unknown() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "source_metadata": {"platforms": {"android": False, "ios": False}},
            "opengrep": {
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
            },
        }
    )

    functionality = ReactNativeFunctionality(context)

    assert functionality.applicable is True
    assert functionality.assessed is False
    assert functionality.fully_assessed is False
    assert all(item["present"] is None for item in functionality.items.values())
    assert all(item["present"] is None for item in build_report_sections(context)["functionality"].values())


def test_managed_expo_project_uses_react_native_scope_and_dependency_evidence() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "source_metadata": {
                "runtime": {"react_native_constraint": "0.81.5", "expo_constraint": "~54.0.33"},
                "platforms": {"android": True, "ios": True},
                "android": {"available": False, "metadata": None},
                "ios": {"available": False, "metadata": None},
                "dependencies": {
                    "declared": [
                        {"name": "@react-native-async-storage/async-storage"},
                        {"name": "@react-navigation/native"},
                        {"name": "axios"},
                    ],
                    "resolved": [],
                },
            },
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "react_native": {
                            "status": "success",
                            "applicable": True,
                            "configured_rule_ids": sorted(REACT_NATIVE_FUNCTIONALITY_RULES),
                        },
                        "android": {"status": "skipped", "applicable": False, "configured_rule_ids": []},
                        "ios": {"status": "skipped", "applicable": False, "configured_rule_ids": []},
                    }
                },
            },
        }
    )

    functionality = ReactNativeFunctionality(context)

    assert functionality.fully_assessed is True
    assert functionality.items["Data Storage"]["present"] is True
    assert functionality.items["Navigation"]["present"] is True
    assert functionality.items["Networking"]["present"] is True
    assert functionality.items["Camera"]["present"] is False


def test_web_react_dependencies_do_not_produce_mobile_functionality() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "source_metadata": {
                "runtime": {"react_native_constraint": "", "expo_constraint": ""},
                "dependencies": {
                    "declared": [{"name": "axios"}, {"name": "react-router-dom"}],
                    "resolved": [],
                },
            }
        }
    )

    functionality = ReactNativeFunctionality(context)

    assert functionality.items["Networking"]["present"] is None
    assert functionality.items["Navigation"]["present"] is None

from pathlib import Path

from domain.post_scan.react_native import ReactNativePermissions
from domain.post_scan.react_native.rule_registry import PERMISSION_INVENTORY_RULE_ID_TO_KEY
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


def test_correlates_native_expo_and_runtime_permissions() -> None:
    project = Path("/workspace/mobile")
    context = ReactNativeScanExtractionContext(
        {
            "scan_metadata": {"project_path": str(project)},
            "source_metadata": {
                "expo": {
                    "assessed": True,
                    "plugins": [{"name": "expo-location", "options": {}}],
                    "android": {
                        "permissions": ["CAMERA"],
                        "blocked_permissions": ["RECORD_AUDIO", "READ_CONTACTS"],
                    },
                    "ios": {"info_plist": {"NSCameraUsageDescription": "Take profile photos"}},
                },
                "android": {
                    "available": True,
                    "metadata": {"permissions": [{"name": "android.permission.INTERNET"}]},
                },
                "ios": {
                    "available": True,
                    "metadata": {
                        "permissions": [{"key": "NSMicrophoneUsageDescription", "purpose": "Record a message"}]
                    },
                },
            },
            "opengrep": {
                "results": [
                    _finding(
                        "react-native.inventory.android-permission-request",
                        "src/camera.ts",
                        4,
                        "PermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.CAMERA)",
                    ),
                    _finding(
                        "react-native.inventory.android-permission-request",
                        "src/audio.ts",
                        7,
                        "PermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.RECORD_AUDIO)",
                    ),
                    _finding(
                        "react-native.inventory.cross-platform-permission-request",
                        "src/audio.ts",
                        9,
                        "request(PERMISSIONS.IOS.MICROPHONE)",
                    ),
                    _finding(
                        "react-native.inventory.cross-platform-permission-request",
                        "src/photos.ts",
                        11,
                        "request(PERMISSIONS.IOS.PHOTO_LIBRARY)",
                    ),
                    _finding(
                        "react-native.inventory.expo-permission-request",
                        "src/location.ts",
                        3,
                        "Location.requestForegroundPermissionsAsync()",
                    ),
                ],
                "scan_metadata": {
                    "scopes": {
                        "react_native": {
                            "status": "success",
                            "applicable": True,
                            "configured_rule_ids": sorted(PERMISSION_INVENTORY_RULE_ID_TO_KEY),
                        }
                    }
                },
            },
        }
    )

    permissions = ReactNativePermissions(context)
    items = {(item["platform"], item["permission"]): item for item in permissions.items}

    assert permissions.assessed is True
    assert items[("Android", "android.permission.CAMERA")]["status"] == "Declared and Requested"
    assert items[("Android", "android.permission.RECORD_AUDIO")]["status"] == "Requested but Blocked"
    assert items[("Android", "android.permission.READ_CONTACTS")]["status"] == "Blocked by Expo Configuration"
    assert items[("Android", "android.permission.INTERNET")]["status"] == "Declared Only"
    assert items[("iOS", "NSMicrophoneUsageDescription")]["status"] == "Declared and Requested"
    assert items[("iOS", "NSPhotoLibraryUsageDescription")]["status"] == "Requested but Not Declared"
    assert items[("Android/iOS", "Location")]["status"] == "Requested and Inferred from Expo Plugin"
    assert items[("iOS", "NSCameraUsageDescription")]["usage_description"] == "Take profile photos"
    assert "cannot determine the final permissions" in permissions.DISCLAIMER


def _finding(rule_id: str, path: str, line: int, source: str) -> dict[str, object]:
    return {
        "check_id": rule_id,
        "phoenix_scope": "react_native",
        "path": f"/workspace/mobile/{path}",
        "start": {"line": line},
        "extra": {"lines": source},
    }

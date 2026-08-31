"""Tests for Flutter report metadata models."""

from __future__ import annotations

from dataclasses import asdict

from domain.post_scan.flutter import (
    FlutterAppInfo,
    FlutterFileInfo,
    FlutterMeta,
    FlutterScanExtractionContext,
)


def test_builds_flutter_report_metadata_from_normalized_context() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {
                "project_path": "/workspace/example_app",
                "scan_date": "2026-08-30 14:15:16",
                "target_type": "source",
            },
            "source_metadata": {
                "project": {
                    "project_path": "/metadata/fallback",
                    "pubspec_path": "pubspec.yaml",
                    "pubspec_lock_path": "pubspec.lock",
                },
                "identity": {
                    "package_name": "example_app",
                    "description": "Example Flutter application",
                    "version_name": "1.2.3",
                    "version_code": "42",
                    "homepage": "https://example.com",
                    "repository": "https://example.com/source",
                },
                "sdk": {
                    "dart_constraint": ">=3.3.0 <4.0.0",
                    "flutter_constraint": ">=3.22.0",
                },
                "android": {
                    "available": True,
                    "metadata": {
                        "identity": {
                            "app_name": "Example App",
                            "package_name": "com.example.android",
                            "main_activity": "com.example.android.MainActivity",
                            "target_sdk": "35",
                            "min_sdk": "24",
                        },
                        "application": {"icon": "android/app/src/main/res/mipmap/ic_launcher.png"},
                    },
                },
                "ios": {
                    "available": True,
                    "metadata": {
                        "identity": {
                            "display_name": "Example iOS App",
                            "bundle_identifier": "com.example.ios",
                        }
                    },
                },
            },
        }
    )

    assert asdict(FlutterMeta(context)) == {
        "app_display_name": "Example App",
        "file_name": "example_app",
        "package_name": "example_app",
        "platform": "Flutter",
        "reviewer_org": "Phoenix Security Report",
        "scan_date": "2026-08-30 14:15:16",
        "target_type": "SOURCE",
        "version_code": "42",
        "version_name": "1.2.3",
    }
    assert asdict(FlutterFileInfo(context)) == {
        "filename": "example_app",
        "size": "",
        "md5": "",
        "sha1": "",
        "sha256": "",
        "pubspec_path": "pubspec.yaml",
        "pubspec_lock_path": "pubspec.lock",
    }
    assert asdict(FlutterAppInfo(context)) == {
        "icon_path": "android/app/src/main/res/mipmap/ic_launcher.png",
        "name": "Example App",
        "package_name": "example_app",
        "main_activity": "com.example.android.MainActivity",
        "target_sdk": "35",
        "min_sdk": "24",
        "max_sdk": "",
        "version_name": "1.2.3",
        "version_code": "42",
        "description": "Example Flutter application",
        "homepage": "https://example.com",
        "repository": "https://example.com/source",
        "dart_sdk_constraint": ">=3.3.0 <4.0.0",
        "flutter_sdk_constraint": ">=3.22.0",
        "android_application_id": "com.example.android",
        "ios_bundle_identifier": "com.example.ios",
        "app_store_id": "",
        "developer": "",
        "categories": "",
        "trackers_detected": "",
    }


def test_metadata_models_use_safe_fallbacks_for_partial_output() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/FallbackProject"},
            "source_metadata": {
                "project": {"pubspec_path": "pubspec.yaml"},
                "identity": {"version_name": "2.0.0"},
                "android": {"available": True, "metadata": None},
                "ios": {"available": True, "metadata": None},
            },
        }
    )

    meta = FlutterMeta(context)
    file_info = FlutterFileInfo(context)
    app_info = FlutterAppInfo(context)

    assert meta.app_display_name == "FallbackProject"
    assert meta.file_name == "FallbackProject"
    assert meta.package_name == ""
    assert meta.target_type == "SOURCE"
    assert meta.version_name == "2.0.0"
    assert meta.version_code == ""
    assert file_info.pubspec_path == "pubspec.yaml"
    assert file_info.pubspec_lock_path == ""
    assert app_info.name == "FallbackProject"
    assert app_info.android_application_id == ""
    assert app_info.ios_bundle_identifier == ""
    assert app_info.dart_sdk_constraint == ""
    assert app_info.flutter_sdk_constraint == ""

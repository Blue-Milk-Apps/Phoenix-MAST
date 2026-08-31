"""Cross-model tests for Flutter metadata and inventory models."""

from __future__ import annotations

import json
from dataclasses import asdict

import domain.post_scan.flutter as flutter_models
from domain.post_scan.flutter import (
    FlutterAppInfo,
    FlutterDependencyInventory,
    FlutterFileInfo,
    FlutterMeta,
    FlutterPlatformInventory,
    FlutterScanExtractionContext,
)


def test_step_three_models_share_canonical_context_values() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {
                "project_path": "/workspace/example_app",
                "scan_date": "2026-08-30 16:17:18",
                "target_type": "SOURCE",
            },
            "source_metadata": {
                "project": {
                    "pubspec_path": "pubspec.yaml",
                    "pubspec_lock_path": "pubspec.lock",
                },
                "identity": {
                    "package_name": "example_app",
                    "version_name": "1.2.3",
                    "version_code": "42",
                },
                "sdk": {"dart_constraint": ">=3.3.0", "flutter_constraint": ">=3.22.0"},
                "platforms": {"android": True, "ios": True, "web": True},
                "android": {
                    "available": True,
                    "metadata": {
                        "identity": {
                            "app_name": "Example App",
                            "package_name": "com.example.android",
                        }
                    },
                },
                "ios": {
                    "available": True,
                    "metadata": {"identity": {"bundle_identifier": "com.example.ios"}},
                },
                "dependencies": {
                    "direct": [{"name": "http", "constraint": "^1.2.0", "source": "hosted"}],
                    "development": [],
                    "resolved": [{"name": "http", "version": "1.2.0", "source": "hosted"}],
                },
            },
            "syft_outputs": {"sbom.json": {"artifacts": [{"name": "http", "version": "1.2.0"}]}},
        }
    )

    meta = FlutterMeta(context)
    file_info = FlutterFileInfo(context)
    app_info = FlutterAppInfo(context)
    platforms = FlutterPlatformInventory(context)
    dependencies = FlutterDependencyInventory(context)

    assert meta.app_display_name == app_info.name == platforms.android.app_name == "Example App"
    assert meta.package_name == app_info.package_name == "example_app"
    assert app_info.android_application_id == platforms.android.package_name == "com.example.android"
    assert app_info.ios_bundle_identifier == platforms.ios.bundle_identifier == "com.example.ios"
    assert meta.version_name == app_info.version_name == platforms.android.version_name == "1.2.3"
    assert meta.version_code == app_info.version_code == platforms.ios.version_code == "42"
    assert file_info.filename == meta.file_name == "example_app"
    assert platforms.source_metadata_assessed is True
    assert dependencies.metadata_assessed is True
    assert dependencies.sbom_assessed is True

    json.dumps(
        {
            "meta": asdict(meta),
            "file_info": asdict(file_info),
            "app_info": asdict(app_info),
            "platform_inventory": asdict(platforms),
            "dependency_inventory": asdict(dependencies),
        }
    )


def test_step_three_models_keep_assessment_states_independent() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"android": True, "ios": True},
                "android": {"available": True, "metadata": None},
                "ios": {"available": True, "metadata": {}},
                "dependencies": {"direct": [], "development": [], "resolved": []},
            },
            "syft_outputs": {"sbom.json": {"success": False, "artifacts": []}},
        }
    )

    platforms = FlutterPlatformInventory(context)
    dependencies = FlutterDependencyInventory(context)

    assert platforms.source_metadata_assessed is True
    assert platforms.android.detected is True
    assert platforms.android.metadata_assessed is False
    assert platforms.ios.detected is True
    assert platforms.ios.metadata_assessed is True
    assert dependencies.metadata_assessed is True
    assert dependencies.sbom_assessed is False


def test_step_three_models_are_public_flutter_exports() -> None:
    expected_exports = {
        "FlutterAndroidPlatformInventory",
        "FlutterAppInfo",
        "FlutterDeclaredDependency",
        "FlutterDependencyInventory",
        "FlutterFileInfo",
        "FlutterIOSPlatformInventory",
        "FlutterMeta",
        "FlutterPlatformInventory",
        "FlutterResolvedDependency",
        "FlutterSbomPackage",
        "FlutterSdkInventory",
    }

    assert expected_exports <= set(flutter_models.__all__)
    assert all(hasattr(flutter_models, name) for name in expected_exports)

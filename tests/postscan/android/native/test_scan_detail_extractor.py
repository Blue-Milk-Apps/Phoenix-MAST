from __future__ import annotations

from adapters.post_scan import NativeAndroidScanDetailExtractor


def test_extracts_native_android_source_metadata_sections() -> None:
    loaded_outputs = {
        "scan_output_path": "/tmp/SAST_native_android_source_2026-08-27_12-00-00",
        "scan_metadata": {
            "platform": "ANDROID",
            "project_path": "/workspace/ExampleApp",
            "target_type": "SOURCE",
        },
        "source_metadata": {
            "identity": {
                "app_name": "Example",
                "package_name": "com.example.app",
                "main_activity": "com.example.app.MainActivity",
                "target_sdk": "35",
                "min_sdk": "24",
                "version_name": "1.2.3",
                "version_code": "42",
            },
            "application": {
                "debuggable": False,
                "allow_backup": True,
                "uses_cleartext_traffic": None,
                "icon": "@mipmap/ic_launcher",
            },
            "permissions": [
                {"name": "android.permission.CAMERA"},
                {"name": "com.example.permission.CUSTOM"},
                {"name": "android.permission.CAMERA"},
            ],
            "components": {
                "activities": [
                    {"name": "com.example.app.MainActivity", "exported": True},
                    {"name": "com.example.app.SettingsActivity", "exported": None},
                ],
                "services": [{"name": "com.example.app.SyncService", "exported": False}],
                "receivers": [],
                "providers": [{"name": "com.example.app.Provider", "exported": True}],
            },
            "deep_links": [{"component": "com.example.app.MainActivity", "scheme": "example"}],
        },
    }

    sections = NativeAndroidScanDetailExtractor().extract_sections(loaded_outputs)

    assert set(sections) == {
        "meta",
        "file_info",
        "app_info",
        "application",
        "app_components",
        "permissions",
        "deep_links",
    }
    assert sections["meta"] == {
        "app_display_name": "Example",
        "file_name": "ExampleApp",
        "package_name": "com.example.app",
        "platform": "Android",
        "reviewer_org": "Phoenix Security Report",
        "scan_date": "2026-08-27 12:00:00",
        "target_type": "SOURCE",
        "version_code": "42",
        "version_name": "1.2.3",
    }
    assert sections["file_info"] == {
        "filename": "ExampleApp",
        "size": "",
        "md5": "",
        "sha1": "",
        "sha256": "",
    }
    assert sections["app_info"]["main_activity"] == "com.example.app.MainActivity"
    assert sections["app_info"]["target_sdk"] == "35"
    assert sections["app_info"]["min_sdk"] == "24"
    assert sections["app_info"]["debuggable"] is False
    assert sections["app_info"]["allow_backup"] is True
    assert sections["application"] == {
        "debuggable": False,
        "allow_backup": True,
        "uses_cleartext_traffic": None,
    }
    assert sections["app_components"] == {
        "activities": 2,
        "services": 1,
        "receivers": 0,
        "providers": 1,
        "exported_activities": 1,
        "exported_services": 0,
        "exported_receivers": 0,
        "exported_providers": 1,
    }
    assert sections["permissions"][0] == {
        "permission": "android.permission.CAMERA",
        "status": "",
        "info": "",
        "usage_description": "",
        "general_description": "Allows the app to access the device camera.",
    }
    assert sections["permissions"][1]["general_description"] == "Custom."
    assert len(sections["permissions"]) == 2
    assert sections["deep_links"] == {
        "deep_links": [{"component": "com.example.app.MainActivity", "scheme": "example"}]
    }


def test_missing_source_metadata_preserves_unknown_values() -> None:
    sections = NativeAndroidScanDetailExtractor().extract_sections(
        {
            "scan_metadata": {
                "project_path": "/workspace/FallbackProject",
                "target_type": "SOURCE",
            }
        }
    )

    assert sections["meta"]["app_display_name"] == "FallbackProject"
    assert sections["meta"]["package_name"] == ""
    assert sections["application"] == {
        "debuggable": None,
        "allow_backup": None,
        "uses_cleartext_traffic": None,
    }
    assert all(value is None for value in sections["app_components"].values())
    assert sections["permissions"] == []
    assert sections["deep_links"] == {"deep_links": None}


def test_explicit_empty_source_collections_are_assessed_as_empty() -> None:
    sections = NativeAndroidScanDetailExtractor().extract_sections(
        {
            "source_metadata": {
                "components": {
                    "activities": [],
                    "services": [],
                    "receivers": [],
                    "providers": [],
                },
                "permissions": [],
                "deep_links": [],
            }
        }
    )

    assert all(value == 0 for value in sections["app_components"].values())
    assert sections["permissions"] == []
    assert sections["deep_links"] == {"deep_links": []}


def test_non_boolean_application_values_remain_unknown() -> None:
    sections = NativeAndroidScanDetailExtractor().extract_sections(
        {
            "source_metadata": {
                "application": {
                    "debuggable": "false",
                    "allow_backup": 1,
                    "uses_cleartext_traffic": "true",
                }
            }
        }
    )

    assert sections["application"] == {
        "debuggable": None,
        "allow_backup": None,
        "uses_cleartext_traffic": None,
    }

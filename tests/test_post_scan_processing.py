import json
from pathlib import Path

from adapters.post_scan import (
    AndroidBinaryScanDetailExtractor,
    AndroidBinaryScanOutputLoader,
    IOSBinaryScanDetailExtractor,
    IOSBinaryScanOutputLoader,
    NativeIOSScanDetailExtractor,
)
from adapters.storage.store_to_file import StoreToFile
from application.post_scan_processing_service import PostScanProcessingService


def test_native_ios_scan_detail_extractor_identifies_source_assessment(tmp_path: Path) -> None:
    result = NativeIOSScanDetailExtractor().extract_sections(
        {
            "scan_metadata": {
                "platform": "IOS",
                "project_path": str(tmp_path / "ExampleProject"),
                "target_type": "SOURCE",
            },
            "plist_outputs": {
                "Example/Info.json": {
                    "app_meta": {
                        "bundle_identifier": "com.example.app",
                        "bundle_name": "Example",
                    }
                }
            },
        }
    )

    assert result["meta"]["platform"] == "iOS"
    assert result["meta"]["target_type"] == "SOURCE"
    assert result["meta"]["package_name"] == "com.example.app"


def test_native_ios_structured_evidence_does_not_interpret_rule_ids() -> None:
    result = NativeIOSScanDetailExtractor().extract_sections(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "example.new-rule",
                        "extra": {"message": "UIWebView NSKeyedUnarchiver PBKDF2 MD5 migration notes"},
                    }
                ]
            }
        }
    )
    assert "code_evidence" not in result


def test_android_binary_scan_detail_extractor_builds_app_info_and_certificate() -> None:
    apk_path = Path("/tmp/APKPure.apk")
    loaded_outputs = {
        "scan_metadata": {
            "project_path": str(apk_path),
            "file_info": StoreToFile._input_file_info(apk_path),
        },
        "androguard_metadata": {
            "apk_path": str(apk_path),
            "app_name": "APKPure",
            "file_name": "APKPure.apk",
            "package": "com.apkpure.aegon",
            "target_sdk": "34",
            "min_sdk": "19",
            "version_name": "3.20.70",
        },
        "androguard_components": {
            "activities": [
                {"exported": True},
                {"exported": False},
                {"exported": None},
            ],
            "services": [
                {"exported": True},
                {"exported": False},
            ],
            "receivers": [
                {"exported": True},
                {"exported": True},
            ],
            "providers": [
                {"exported": False},
            ],
        },
        "aapt2_identity": {
            "application_label": "APKPure",
            "package_name": "com.apkpure.aegon",
            "launchable_activity": "com.apkpure.aegon.main.activity.FirstSeemPageActivity",
            "target_sdk_version": "34",
            "version_name": "3.20.70",
        },
        "aapt2_application": {
            "uses_cleartext_traffic": None,
            "debuggable": None,
            "allow_backup": None,
        },
        "aapt2_manifest_security_posture": {
            "cleartext_traffic_permitted": None,
        },
        "apktool_manifest_summary": {
            "application": {
                "debuggable": "false",
                "allow_backup": "true",
            }
        },
        "aapt2_permissions": {
            "permissions": [
                {
                    "name": "android.permission.ACCESS_FINE_LOCATION",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.CAMERA",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.RECORD_AUDIO",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.READ_CONTACTS",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.READ_CALENDAR",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.BLUETOOTH_CONNECT",
                    "protection_level_hint": "unknown_or_normal",
                },
                {
                    "name": "android.permission.INTERNET",
                    "protection_level_hint": "unknown_or_normal",
                },
                {
                    "name": "com.apkpure.aegon.permission.PROCESS_PUSH_MSG",
                    "protection_level_hint": "unknown_or_normal",
                },
            ]
        },
        "androguard_certificates": {
            "all": [
                {
                    "issuer": {
                        "common_name": "apkpure",
                        "organization_name": "apkpure",
                        "organizational_unit_name": "apkpure",
                    },
                    "not_valid_after": "2040-07-16 05:48:59+00:00",
                    "not_valid_before": "2015-07-23 05:48:59+00:00",
                    "serial_number": "1437630539",
                    "sha1": "ec330db8c45c5cceb66797163779bf1d186aecaf",  # pragma: allowlist secret
                    "sha256": "22311a95d67057b82318e23b3efd7cc878e190b8dcd55ac2e7bb745343957474",  # pragma: allowlist secret
                    "subject": {
                        "common_name": "apkpure",
                        "organization_name": "apkpure",
                        "organizational_unit_name": "apkpure",
                    },
                }
            ]
        },
        "apksigner_signing_evidence": {
            "apk": {
                "file_name": "APKPure.apk",
                "sha256": "9614118b4e75e72e4fb65909fe95649efd89d00fb8435e99e5bebbec75bb1a31",  # pragma: allowlist secret
                "size_bytes": 25760048,
            },
            "signature_schemes": {
                "v1": {"state": "VERIFIED"},
                "v2": {"state": "VERIFIED"},
                "v3": {"state": "MISSING"},
                "v4": {"state": "MISSING"},
            },
            "signers": [
                {
                    "certificate": {
                        "public_key_algorithm": "RSA",
                        "sha256": "22311A95D67057B82318E23B3EFD7CC878E190B8DCD55AC2E7BB745343957474",  # pragma: allowlist secret
                        "signature_algorithm": "UNKNOWN",
                        "subject_dn": "CN=apkpure, OU=apkpure, O=apkpure",
                    }
                }
            ],
        },
        "apktool_permissions": {
            "declared": [
                {
                    "context": {"protection_level": "signature"},
                    "value": "com.apkpure.aegon.permission.PROCESS_PUSH_MSG",
                }
            ]
        },
        "apktool_network_security_config": {
            "config_file_present": False,
            "effective_cleartext_traffic_default": "true",
            "manifest_uses_cleartext_traffic": "",
            "policy_source": "manifest_default_no_network_security_config",
            "domains": [],
            "debug_overrides": [],
            "provenance": {"path": "AndroidManifest.xml"},
            "reference": "",
        },
        "apktool_deep_links": {"deep_links": []},
        "apktool_secrets_endpoints": {
            "items": [
                {
                    "context": {"category": "domain"},
                    "value": "apkpure.com",
                },
                {
                    "context": {"category": "url"},
                    "value": "https://api.apkpure.com/v1/apps",
                },
                {
                    "context": {"category": "domain"},
                    "value": "apkpure.com",
                },
                {
                    "context": {"category": "email"},
                    "value": "support@apkpure.com",
                },
                {
                    "context": {"category": "secret_keyword"},
                    "provenance": {"path": "res/values/strings.xml", "line": 12},
                    "value": "API_KEY=super-secret",
                },
            ]
        },
        "opengrep": {
            "results": [
                {
                    "extra": {
                        "message": "App declares or uses Android location services.",
                        "metadata": {
                            "phoenix": {
                                "check_id": 55,
                                "description": (
                                    "Detect whether the app declares Android location permissions "
                                    "or uses Android location-related APIs."
                                ),
                                "title": "Location services declaration present",
                            }
                        },
                    }
                }
            ]
        },
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["meta"] == {
        "app_display_name": "APKPure",
        "file_name": "APKPure.apk",
        "package_name": "com.apkpure.aegon",
        "scan_date": "",
        "platform": "",
        "version_name": "3.20.70",
        "version_code": "",
        "reviewer_org": "Phoenix Security Report",
    }
    assert sections["app_info"] == {
        "icon_path": "",
        "name": "APKPure",
        "package_name": "com.apkpure.aegon",
        "main_activity": "com.apkpure.aegon.main.activity.FirstSeemPageActivity",
        "target_sdk": "34",
        "min_sdk": "19",
        "max_sdk": "",
        "version_name": "3.20.70",
        "debuggable": "false",
        "allow_backup": "true",
        "app_store_id": "",
        "developer": "",
        "categories": "",
        "trackers_detected": "",
    }
    assert sections["app_components"] == {
        "activities": 3,
        "services": 2,
        "receivers": 2,
        "providers": 1,
        "exported_activities": 1,
        "exported_services": 1,
        "exported_receivers": 2,
        "exported_providers": 0,
    }
    assert sections["certificate"]["owner_name"] == "apkpure"
    assert sections["certificate"]["organization"] == "apkpure"
    assert sections["certificate"]["organizational_unit"] == "apkpure"
    assert sections["certificate"]["serial_number"] == "1437630539"
    assert sections["certificate"]["signature_versions"] == {
        "v1": True,
        "v2": True,
        "v3": False,
        "v4": False,
    }
    assert (
        sections["certificate"]["fingerprint"]
        == "22311a95d67057b82318e23b3efd7cc878e190b8dcd55ac2e7bb745343957474"  # pragma: allowlist secret
    )
    assert sections["certificate"]["unique_certs"] == "1"
    assert sections["file_info"] == {
        "filename": "APKPure.apk",
        "size": "25760048",
        "md5": "",
        "sha1": "",
        "sha256": "9614118b4e75e72e4fb65909fe95649efd89d00fb8435e99e5bebbec75bb1a31",  # pragma: allowlist secret
    }
    assert sections["permissions"] == [
        {
            "permission": "android.permission.ACCESS_FINE_LOCATION",
            "status": "dangerous",
            "info": "dangerous",
            "usage_description": "",
            "general_description": "Allows the app to access precise location from GPS and other location providers.",
        },
        {
            "permission": "android.permission.CAMERA",
            "status": "dangerous",
            "info": "dangerous",
            "usage_description": "",
            "general_description": "Allows the app to access the device camera.",
        },
        {
            "permission": "android.permission.RECORD_AUDIO",
            "status": "dangerous",
            "info": "dangerous",
            "usage_description": "",
            "general_description": "Allows the app to capture audio using the microphone.",
        },
        {
            "permission": "android.permission.READ_CONTACTS",
            "status": "dangerous",
            "info": "dangerous",
            "usage_description": "",
            "general_description": "Allows the app to read the user's contacts data.",
        },
        {
            "permission": "android.permission.READ_CALENDAR",
            "status": "dangerous",
            "info": "dangerous",
            "usage_description": "",
            "general_description": "Allows the app to read calendar events and related details stored on the device.",
        },
        {
            "permission": "android.permission.BLUETOOTH_CONNECT",
            "status": "normal",
            "info": "unknown or normal",
            "usage_description": "",
            "general_description": "Allows the app to connect to nearby Bluetooth devices.",
        },
        {
            "permission": "android.permission.INTERNET",
            "status": "normal",
            "info": "unknown or normal",
            "usage_description": "",
            "general_description": "Allows the app to open network sockets and communicate over the internet.",
        },
        {
            "permission": "com.apkpure.aegon.permission.PROCESS_PUSH_MSG",
            "status": "normal",
            "info": "unknown or normal",
            "usage_description": "",
            "general_description": "Declared permission (signature)",
        },
    ]
    assert sections["application"] == {
        "debuggable": False,
        "allow_backup": True,
        "uses_cleartext_traffic": None,
    }
    assert sections["app_info"]["debuggable"] == "false"
    assert sections["app_info"]["allow_backup"] == "true"
    assert sections["endpoints"] == []


def test_ios_binary_scan_detail_extractor_returns_direct_ios_contract(tmp_path: Path) -> None:
    ipa_path = tmp_path / "DVIA-v2.ipa"
    ipa_path.write_bytes(b"ios-binary")
    loaded_outputs = {
        "scan_output_path": str(tmp_path),
        "scan_metadata": {
            "platform": "IOS",
            "project_path": str(ipa_path),
            "file_info": StoreToFile._input_file_info(ipa_path),
            "scan_date": "2026-07-22 10:51:49",
        },
        "ipsw_outputs": {
            "DVIA-v2.json": {
                "app_info": {
                    "bundle_id": "com.highaltitudehacks.DVIAswiftv2",
                    "bundle_name": "DVIA-v2",
                    "short_version": "2.0",
                    "bundle_version": "1",
                    "executable_name": "DVIA",
                    "minimum_os": "15.0",
                },
                "binary": {
                    "kind": "main",
                    "name": "DVIA",
                    "path": "DVIA",
                },
                "analysis": {
                    "macho": {"rpaths": ["@rpath"]},
                    "code_signature": {"present": True},
                    "entitlements": {
                        "values": {
                            "get-task-allow": True,
                        }
                    },
                },
            }
        },
        "lief_outputs": {
            "DVIA-v2.json": {
                "binary": {
                    "kind": "main",
                    "slices": [
                        {
                            "architecture": "ARM64",
                            "file_type": "EXECUTE",
                            "imported_functions": [
                                "___stack_chk_fail",
                                "___stack_chk_guard",
                                "_objc_release",
                            ],
                            "libraries": ["libSystem.B.dylib"],
                            "has_rpath": True,
                        }
                    ],
                    "name": "DVIA-LIEF",
                    "path": "DVIA-LIEF",
                }
            },
            "Frameworks/Some.framework/Some.json": {
                "binary": {
                    "kind": "framework",
                    "slices": [
                        {
                            "imported_functions": [
                                "___stack_chk_fail",
                                "___stack_chk_guard",
                                "_swift_release",
                            ]
                        }
                    ],
                }
            },
        },
        "opengrep": {
            "results": [
                {
                    "check_id": "ios.deprecated.api.uiwebview",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "title": "Deprecated API - UIWebView",
                                "description": "UIWebView reference detected.",
                            }
                        }
                    },
                },
                {
                    "check_id": "ios.insecure.serialization.nskeyedunarchiver",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "title": "Insecure Serialization API - NSKeyedUnarchiver",
                                "description": "decodeObject usage detected.",
                            }
                        }
                    },
                },
            ]
        },
        "gitleaks_outputs": {
            "report.json": "Secret Type: API Key\nLocation: Config.swift:12",
        },
    }

    result = IOSBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert set(result) == {
        "meta",
        "file_info",
        "app_info",
        "ipa_binary_evidence",
        "url_schemes",
        "functionality",
        "third_party_sdks",
        "permissions",
        "hardcoded_values",
        "endpoints",
    }
    assert result["meta"] == {
        "app_display_name": "DVIA-v2",
        "file_name": "DVIA-v2.ipa",
        "package_name": "com.highaltitudehacks.DVIAswiftv2",
        "scan_date": "2026-07-22 10:51:49",
        "platform": "iOS",
        "target_type": "BINARY",
        "version_name": "2.0",
        "version_code": "1",
        "reviewer_org": "Phoenix Security Report",
    }
    assert result["file_info"]["filename"] == "DVIA-v2.ipa"
    assert result["file_info"]["md5"] != ""
    assert result["file_info"]["sha1"] != ""
    assert result["file_info"]["sha256"] != ""
    assert result["app_info"] == {
        "icon_path": "",
        "icon_data_uri": "",
        "name": "DVIA-v2",
        "package_name": "com.highaltitudehacks.DVIAswiftv2",
        "main_activity": "DVIA",
        "version_name": "2.0 (1)",
        "app_store_id": "",
        "developer": "",
        "categories": "",
        "trackers_detected": "",
    }
    assert result["url_schemes"] == []
    assert result["permissions"] == []
    assert result["endpoints"] == []


def test_ios_meta_uses_lief_when_ipsw_is_partial() -> None:
    loaded_outputs = {
        "scan_metadata": {
            "platform": "IOS",
            "project_path": "/tmp/Unknown.ipa",
        },
        "ipsw_outputs": {
            "App.json": {
                "app_info": {
                    "bundle_id": "",
                    "bundle_name": "",
                    "short_version": "",
                    "bundle_version": "",
                },
                "binary": {
                    "kind": "main",
                    "name": "AppFromIpsw",
                    "path": "AppFromIpsw",
                },
            }
        },
        "lief_outputs": {
            "App.json": {
                "binary": {
                    "kind": "main",
                    "name": "AppFromLief",
                    "path": "AppFromLief",
                    "slices": [{"architecture": "ARM64", "file_type": "EXECUTE"}],
                }
            }
        },
    }

    result = IOSBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert result["meta"]["app_display_name"] == "AppFromLief"
    assert result["meta"]["file_name"] == "Unknown.ipa"
    assert result["meta"]["package_name"] == ""
    assert result["meta"]["version_name"] == ""
    assert result["meta"]["version_code"] == ""


def test_ios_meta_uses_strings_as_narrow_fallback() -> None:
    loaded_outputs = {
        "scan_metadata": {
            "platform": "IOS",
            "project_path": "",
        },
        "strings_outputs": {
            "Payload/FallbackApp.txt": "hello\nworld\n",
            "Frameworks/Foo.framework/Foo.txt": "framework\n",
        },
    }

    result = IOSBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert result["meta"]["app_display_name"] == "FallbackApp"
    assert result["meta"]["file_name"] == ""
    assert result["meta"]["package_name"] == ""


def test_ios_meta_derives_scan_date_from_output_directory_name() -> None:
    scan_dir = Path("/tmp/SAST_ios_binary_2026-07-23_10-00-00")
    loaded_outputs = {
        "scan_output_path": str(scan_dir),
        "scan_metadata": {
            "platform": "IOS",
            "project_path": "/tmp/App.ipa",
        },
        "ipsw_outputs": {
            "App.json": {
                "app_info": {
                    "bundle_id": "com.example.app",
                    "bundle_name": "ExampleApp",
                },
                "binary": {"kind": "main", "name": "App", "path": "App"},
            }
        },
    }

    result = IOSBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert result["meta"]["scan_date"] == "2026-07-23 10:00:00"


def test_post_scan_processing_service_returns_direct_ios_contract(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_ios_binary_2026-07-23_10-00-00"
    (scan_dir / "ipsw" / "Payload" / "ExampleApp.app").mkdir(parents=True)
    _write_json(
        scan_dir / "scan_metadata.json",
        {
            "platform": "IOS",
            "project_path": str(tmp_path / "Demo.ipa"),
            "scan_date": "2026-07-23 10:00:00",
        },
    )
    _write_json(
        scan_dir / "ipsw" / "Payload" / "ExampleApp.app" / "ExampleApp.json",
        {
            "app_info": {
                "bundle_id": "com.example.app",
                "bundle_name": "ExampleApp",
                "short_version": "1.0",
                "bundle_version": "3",
            },
            "binary": {"kind": "main", "name": "ExampleApp", "path": "ExampleApp"},
        },
    )

    result = PostScanProcessingService(
        scan_output_loader=IOSBinaryScanOutputLoader(),
        scan_detail_extractor=IOSBinaryScanDetailExtractor(),
    ).process(scan_dir)

    assert result["meta"]["platform"] == "iOS"
    assert result["meta"]["app_display_name"] == "ExampleApp"


def test_ios_permissions_deduplicate_and_keep_first_non_empty_usage_description() -> None:
    loaded_outputs = {
        "plist_outputs": {
            "Info.json": {
                "privacy": {
                    "permissions": [
                        {"key": "NSCameraUsageDescription", "purpose": ""},
                        {"key": "NSExampleCustomUsageDescription", "purpose": "Custom access"},
                    ]
                }
            },
            "Info-2.json": {
                "privacy": {
                    "permissions": [
                        {"key": "NSCameraUsageDescription", "purpose": "Take photos"},
                    ]
                }
            },
        }
    }

    sections = IOSBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["permissions"] == [
        {
            "permission": "NSCameraUsageDescription",
            "status": "dangerous",
            "info": "Access Camera",
            "usage_description": "Take photos",
            "general_description": "Permits access to the device's camera hardware.",
        },
        {
            "permission": "NSExampleCustomUsageDescription",
            "status": "normal",
            "info": "",
            "usage_description": "Custom access",
            "general_description": "",
        },
    ]


def test_post_scan_processing_service_merges_meta_and_extracted_sections(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_android_binary_2026-07-03_23-34-29"
    apk_path = tmp_path / "APKPure.apk"
    (scan_dir / "opengrep_source").mkdir(parents=True)
    (scan_dir / "androguard").mkdir()
    (scan_dir / "aapt2").mkdir()
    (scan_dir / "apksigner").mkdir()
    (scan_dir / "apktool").mkdir()
    apk_path.write_bytes(b"fake apk bytes")

    _write_json(
        scan_dir / "scan_metadata.json",
        {
            "platform": "ANDROID",
            "project_path": str(apk_path),
            "file_info": StoreToFile._input_file_info(apk_path),
        },
    )
    _write_json(scan_dir / "opengrep_source" / "opengrep_results.json", {"results": []})
    _write_json(
        scan_dir / "opengrep_source" / "opengrep_results.json",
        {
            "results": [
                {
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 55,
                                "description": "Detect whether the app declares Android location permissions or uses Android location-related APIs.",
                            }
                        }
                    }
                }
            ]
        },
    )
    _write_json(scan_dir / "androguard" / "permissions.json", {"items": []})
    _write_json(
        scan_dir / "androguard" / "components.json",
        {
            "activities": [
                {"exported": True},
                {"exported": False},
            ],
            "services": [
                {"exported": True},
            ],
            "receivers": [
                {"exported": False},
                {"exported": True},
            ],
            "providers": [
                {"exported": False},
                {"exported": False},
            ],
        },
    )
    _write_json(
        scan_dir / "androguard" / "metadata.json",
        {
            "app_name": "APKPure",
            "apk_path": str(apk_path),
            "file_name": "APKPure.apk",
            "package": "com.apkpure.aegon",
            "version_name": "3.20.70",
            "version_code": "3207037",
            "min_sdk": "19",
            "target_sdk": "34",
        },
    )
    _write_json(
        scan_dir / "androguard" / "certificates.json",
        {
            "all": [
                {
                    "issuer": {
                        "common_name": "apkpure",
                        "organization_name": "apkpure",
                        "organizational_unit_name": "apkpure",
                    },
                    "not_valid_after": "2040-07-16 05:48:59+00:00",
                    "not_valid_before": "2015-07-23 05:48:59+00:00",
                    "serial_number": "1437630539",
                    "sha1": "ec330db8c45c5cceb66797163779bf1d186aecaf",  # pragma: allowlist secret
                    "sha256": "22311a95d67057b82318e23b3efd7cc878e190b8dcd55ac2e7bb745343957474",  # pragma: allowlist secret
                    "subject": {
                        "common_name": "apkpure",
                        "organization_name": "apkpure",
                        "organizational_unit_name": "apkpure",
                    },
                }
            ]
        },
    )
    _write_json(
        scan_dir / "aapt2" / "components.json",
        {
            "activities": [{"exported": True}, {"exported": False}],
            "services": [{"exported": True}],
            "receivers": [{"exported": False}, {"exported": True}],
            "providers": [{"exported": False}, {"exported": False}],
        },
    )
    _write_json(
        scan_dir / "aapt2" / "identity.json",
        {
            "application_label": "APKPure",
            "package_name": "com.apkpure.aegon",
            "launchable_activity": "com.apkpure.aegon.main.activity.FirstSeemPageActivity",
            "target_sdk_version": "34",
            "version_name": "3.20.70",
        },
    )
    _write_json(scan_dir / "aapt2" / "application.json", {"id": "app"})
    _write_json(
        scan_dir / "aapt2" / "permissions.json",
        {
            "permissions": [
                {
                    "name": "android.permission.ACCESS_FINE_LOCATION",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.CAMERA",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.INTERNET",
                    "protection_level_hint": "unknown_or_normal",
                },
            ]
        },
    )
    _write_json(
        scan_dir / "apksigner" / "signing_evidence.json",
        {
            "apk": {
                "file_name": "APKPure.apk",
                "sha256": "9614118b4e75e72e4fb65909fe95649efd89d00fb8435e99e5bebbec75bb1a31",  # pragma: allowlist secret
                "size_bytes": apk_path.stat().st_size,
            },
            "signature_schemes": {
                "v1": {"state": "VERIFIED"},
                "v2": {"state": "VERIFIED"},
                "v3": {"state": "MISSING"},
                "v4": {"state": "MISSING"},
            },
            "signers": [
                {
                    "certificate": {
                        "public_key_algorithm": "RSA",
                        "sha256": "22311A95D67057B82318E23B3EFD7CC878E190B8DCD55AC2E7BB745343957474",  # pragma: allowlist secret
                        "signature_algorithm": "UNKNOWN",
                        "subject_dn": "CN=apkpure, OU=apkpure, O=apkpure",
                    }
                }
            ],
        },
    )
    _write_json(scan_dir / "apktool" / "permissions.json", {"declared": []})
    _write_json(
        scan_dir / "apktool" / "secrets_endpoints.json",
        {
            "items": [
                {
                    "context": {"category": "url"},
                    "value": "https://api.apkpure.com/v1/apps",
                },
                {
                    "context": {"category": "domain"},
                    "value": "apkpure.com",
                },
                {
                    "context": {"category": "secret_keyword"},
                    "provenance": {"path": "AndroidManifest.xml", "line": 88},
                    "value": "token=abc123",
                },
            ]
        },
    )

    result = PostScanProcessingService(
        scan_output_loader=AndroidBinaryScanOutputLoader(),
        scan_detail_extractor=AndroidBinaryScanDetailExtractor(),
    ).process(scan_dir)

    assert result["meta"] == {
        "app_display_name": "APKPure",
        "file_name": "APKPure.apk",
        "package_name": "com.apkpure.aegon",
        "scan_date": "2026-07-03 23:34:29",
        "platform": "Android",
        "version_name": "3.20.70",
        "version_code": "3207037",
        "reviewer_org": "Phoenix Security Report",
    }
    assert result["app_info"]["main_activity"] == "com.apkpure.aegon.main.activity.FirstSeemPageActivity"
    assert result["app_components"] == {
        "activities": 2,
        "services": 1,
        "receivers": 2,
        "providers": 2,
        "exported_activities": 1,
        "exported_services": 1,
        "exported_receivers": 1,
        "exported_providers": 0,
    }
    assert result["certificate"]["signature_versions"]["v2"] is True
    assert result["file_info"] == {
        "filename": "APKPure.apk",
        "size": str(apk_path.stat().st_size),
        "md5": "d8db041096e5576650d5c1b0ac38bcca",  # pragma: allowlist secret
        "sha1": "dadc430a84587e51b2231daa1024ee0506806f96",  # pragma: allowlist secret
        "sha256": "cb4870807289f0ebb14bbfc941421b08f5766fa0346c1828bd5f09a955ccd560",  # pragma: allowlist secret
    }
    assert result["permissions"] == [
        {
            "permission": "android.permission.ACCESS_FINE_LOCATION",
            "status": "dangerous",
            "info": "dangerous",
            "usage_description": "",
            "general_description": "Allows the app to access precise location from GPS and other location providers.",
        },
        {
            "permission": "android.permission.CAMERA",
            "status": "dangerous",
            "info": "dangerous",
            "usage_description": "",
            "general_description": "Allows the app to access the device camera.",
        },
        {
            "permission": "android.permission.INTERNET",
            "status": "normal",
            "info": "unknown or normal",
            "usage_description": "",
            "general_description": "Allows the app to open network sockets and communicate over the internet.",
        },
    ]
    assert result["deep_links"] == {"deep_links": []}
    assert result["endpoints"] == []


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_secret_scan_summary_preserves_counts_locations_and_verification(tmp_path: Path) -> None:
    from adapters.post_scan.ios.native.scan_output_loader import NativeIOSScanOutputLoader

    fixtures = {
        "scan_metadata.json": {"project_path": "/app"},
        "trufflehog/trufflehog_results.json": [
            {
                "DetectorName": "Example token",
                "Verified": True,
                "Raw": "do-not-copy-trufflehog-value",
                "SourceMetadata": {"Data": {"Filesystem": {"file": "/app/Config.swift", "line": 4}}},
            }
        ],
        "gitleaks/gitleaks_report.json": [
            {
                "RuleID": "example-key",
                "File": "/app/Config.swift",
                "StartLine": 8,
                "Secret": "do-not-copy-gitleaks-value",
            }
        ],
    }
    for name, content in fixtures.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(content))
    data = PostScanProcessingService(NativeIOSScanOutputLoader(), NativeIOSScanDetailExtractor()).process(tmp_path)
    trufflehog, gitleaks = data["secret_scans"]
    assert trufflehog["status"] == gitleaks["status"] == "Completed"
    assert trufflehog["findings"] == (
        {"detector": "Example token", "location": "Config.swift:4", "verification": "Verified"},
    )
    assert gitleaks["findings"] == (
        {"detector": "example-key", "location": "Config.swift:8", "verification": "Not checked"},
    )
    assert "do-not-copy" not in json.dumps(data["secret_scans"])


def test_secret_scan_summary_distinguishes_missing_empty_and_partial_results() -> None:
    from domain.post_scan.utilities import summarize_secret_scans

    partial, missing = summarize_secret_scans(
        {
            "trufflehog_outputs": {
                "trufflehog_results.json": {
                    "success": False,
                    "error": "Scanner interrupted",
                    "raw_output": [{"DetectorName": "Example token", "Verified": False}],
                }
            },
        }
    )
    assert partial.status == "Partial"
    assert len(partial.findings) == 1
    assert partial.reason == "Scanner interrupted"
    assert missing.status == "Unavailable"
    completed = summarize_secret_scans({"gitleaks_outputs": {"gitleaks_report.json": []}})[1]
    assert completed.status == "Completed"
    assert completed.findings == ()

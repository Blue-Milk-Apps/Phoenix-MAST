import json
from pathlib import Path

from adapters.post_scan import (
    AndroidBinaryScanDetailExtractor,
    AndroidBinaryScanOutputLoader,
    IOSBinaryScanDetailExtractor,
    IOSBinaryScanOutputLoader,
)
from application.post_scan_processing_service import PostScanProcessingService
from domain.post_scan.ios.network_evidence_builder import IOSNetworkEvidence


def test_android_binary_scan_output_loader_loads_expected_artifacts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_android_binary_2026-07-03_23-34-29"
    (scan_dir / "opengrep_source").mkdir(parents=True)
    (scan_dir / "androguard").mkdir()
    (scan_dir / "aapt2").mkdir()
    (scan_dir / "apksigner").mkdir()
    (scan_dir / "apktool").mkdir()

    _write_json(scan_dir / "scan_metadata.json", {"platform": "ANDROID"})
    _write_json(scan_dir / "opengrep_source" / "opengrep_results.json", {"results": []})
    _write_json(scan_dir / "androguard" / "components.json", {"activities": []})
    _write_json(scan_dir / "androguard" / "metadata.json", {"app_name": "APKPure"})
    _write_json(scan_dir / "androguard" / "permissions.json", {"items": []})
    _write_json(scan_dir / "androguard" / "api_calls.json", {"items": []})
    _write_json(scan_dir / "androguard" / "certificates.json", {"all": []})
    _write_json(scan_dir / "aapt2" / "components.json", {"activities": []})
    _write_json(scan_dir / "aapt2" / "identity.json", {"application_label": "APKPure"})
    _write_json(scan_dir / "aapt2" / "application.json", {"id": "app"})
    _write_json(scan_dir / "aapt2" / "manifest_security_posture.json", {"posture_kind": "facts"})
    _write_json(scan_dir / "aapt2" / "permissions.json", {"permissions": []})
    _write_json(scan_dir / "apksigner" / "signing_evidence.json", {"verification": {}})
    _write_json(scan_dir / "apktool" / "manifest_summary.json", {"application": {"debuggable": "true"}})
    _write_json(scan_dir / "apktool" / "permissions.json", {"declared": []})
    _write_json(scan_dir / "apktool" / "secrets_endpoints.json", {"items": []})
    _write_json(scan_dir / "apktool" / "network_security_config.json", {"config_file_present": False})
    _write_json(scan_dir / "apktool" / "deep_links.json", {"deep_links": []})

    loaded = AndroidBinaryScanOutputLoader().load(scan_dir)

    assert loaded["scan_output_path"] == str(scan_dir)
    assert loaded["scan_metadata"] == {"platform": "ANDROID"}
    assert loaded["opengrep"] == {"results": []}
    assert loaded["androguard_components"] == {"activities": []}
    assert loaded["androguard_metadata"] == {"app_name": "APKPure"}
    assert loaded["androguard_permissions"] == {"items": []}
    assert loaded["androguard_api_calls"] == {"items": []}
    assert loaded["androguard_certificates"] == {"all": []}
    assert loaded["aapt2_components"] == {"activities": []}
    assert loaded["aapt2_identity"] == {"application_label": "APKPure"}
    assert loaded["aapt2_application"] == {"id": "app"}
    assert loaded["aapt2_manifest_security_posture"] == {"posture_kind": "facts"}
    assert loaded["aapt2_permissions"] == {"permissions": []}
    assert loaded["apksigner_signing_evidence"] == {"verification": {}}
    assert loaded["apktool_manifest_summary"] == {"application": {"debuggable": "true"}}
    assert loaded["apktool_permissions"] == {"declared": []}
    assert loaded["apktool_secrets_endpoints"] == {"items": []}
    assert loaded["apktool_network_security_config"] == {"config_file_present": False}
    assert loaded["apktool_deep_links"] == {"deep_links": []}


def test_android_binary_scan_detail_extractor_builds_app_info_and_certificate() -> None:
    apk_path = Path("/tmp/APKPure.apk")
    loaded_outputs = {
        "scan_metadata": {
            "project_path": str(apk_path),
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
    assert sections["functionality"]["Location"] == {
        "present": True,
        "explanation": "Detect whether the app declares Android location permissions or uses Android location-related APIs.",
    }
    assert sections["application"] == {
        "debuggable": "false",
        "allow_backup": "true",
        "uses_cleartext_traffic": "",
    }
    assert sections["app_info"]["debuggable"] == "false"
    assert sections["app_info"]["allow_backup"] == "true"
    assert sections["functionality"]["Camera"] == {
        "present": True,
        "explanation": "permission android.permission.CAMERA, which may indicate camera functionality.",
    }
    assert sections["functionality"]["Microphone"] == {
        "present": True,
        "explanation": "permission android.permission.RECORD_AUDIO, which may indicate microphone functionality.",
    }
    assert sections["functionality"]["Contacts"] == {
        "present": True,
        "explanation": "permission android.permission.READ_CONTACTS, which may indicate contacts functionality.",
    }
    assert sections["functionality"]["Calendar"] == {
        "present": True,
        "explanation": "permission android.permission.READ_CALENDAR, which may indicate calendar functionality.",
    }
    assert sections["functionality"]["Bluetooth"] == {
        "present": True,
        "explanation": "permission android.permission.BLUETOOTH_CONNECT, which may indicate Bluetooth functionality.",
    }
    assert sections["functionality"]["Audio"] == {
        "present": False,
        "explanation": "No permission or scan evidence indicated audio functionality.",
    }
    assert sections["hardcoded_values"] == {
        "urls": [
            {
                "url": "https://api.apkpure.com/v1/apps",
                "country": "",
            }
        ],
        "emails": ["support@apkpure.com"],
        "secrets": [
            {
                "value": "API_KEY=super-secret",
                "location": "res/values/strings.xml:12",
            }
        ],
    }
    assert sections["endpoints"] == [
        {
            "endpoint": "apkpure.com",
            "tags": "domain",
            "ip_address": "",
            "country": "",
        },
        {
            "endpoint": "https://api.apkpure.com/v1/apps",
            "tags": "url",
            "ip_address": "",
            "country": "",
        },
    ]


def test_ios_binary_scan_output_loader_loads_expected_artifacts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_ios_binary_2026-07-23_10-00-00"
    (scan_dir / "opengrep_source").mkdir(parents=True)
    (scan_dir / "ipsw" / "Payload" / "App.app").mkdir(parents=True)
    (scan_dir / "lief" / "Payload" / "App.app").mkdir(parents=True)
    (scan_dir / "plist_binary").mkdir()
    (scan_dir / "strings").mkdir()
    (scan_dir / "trufflehog").mkdir()
    (scan_dir / "gitleaks").mkdir()
    (scan_dir / "syft").mkdir()

    _write_json(
        scan_dir / "scan_metadata.json",
        {
            "platform": "IOS",
            "project_path": str(tmp_path / "Demo.ipa"),
        },
    )
    _write_json(scan_dir / "opengrep_source" / "opengrep_results.json", {"results": []})
    _write_json(
        scan_dir / "ipsw" / "Payload" / "App.app" / "App.json",
        {"app_info": {"bundle_id": "com.example.app"}},
    )
    _write_json(
        scan_dir / "lief" / "Payload" / "App.app" / "App.json",
        {"binary": {"name": "App"}},
    )
    _write_json(
        scan_dir / "plist_binary" / "Info.json",
        {
            "app_meta": {
                "bundle_identifier": "com.example.app",
                "bundle_name": "ExampleApp",
                "display_name": "ExampleApp",
                "version": "1.2.3",
                "build": "7",
            },
            "plist": {"CFBundleExecutable": "ExampleApp"},
        },
    )
    _write_json(scan_dir / "plist_binary" / "scan_index.json", {"plists": []})
    (scan_dir / "strings" / "main.txt").write_text("hello\n", encoding="utf-8")
    (scan_dir / "trufflehog" / "report.json").write_text("{}", encoding="utf-8")
    (scan_dir / "gitleaks" / "report.json").write_text("{}", encoding="utf-8")
    (scan_dir / "syft" / "sbom.json").write_text("{}", encoding="utf-8")

    loaded = IOSBinaryScanOutputLoader().load(scan_dir)

    assert loaded["scan_output_path"] == str(scan_dir)
    assert loaded["scan_metadata"] == {"platform": "IOS", "project_path": str(tmp_path / "Demo.ipa")}
    assert loaded["opengrep"] == {"results": []}
    assert loaded["ipsw_outputs"] == {"Payload/App.app/App.json": {"app_info": {"bundle_id": "com.example.app"}}}
    assert loaded["lief_outputs"] == {"Payload/App.app/App.json": {"binary": {"name": "App"}}}
    assert loaded["plist_outputs"] == {
        "Info.json": {
            "app_meta": {
                "bundle_identifier": "com.example.app",
                "bundle_name": "ExampleApp",
                "display_name": "ExampleApp",
                "version": "1.2.3",
                "build": "7",
            },
            "plist": {"CFBundleExecutable": "ExampleApp"},
        }
    }
    assert loaded["plist_index"] == {"plists": []}
    assert loaded["strings_outputs"] == {"main.txt": "hello\n"}
    assert loaded["trufflehog_outputs"] == {"report.json": {}}
    assert loaded["gitleaks_outputs"] == {"report.json": {}}
    assert loaded["syft_outputs"] == {"sbom.json": {}}


def test_ios_binary_scan_output_loader_tolerates_missing_optional_artifacts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_ios_binary_2026-07-23_10-00-00"
    scan_dir.mkdir()
    _write_json(scan_dir / "scan_metadata.json", {"platform": "IOS"})

    loaded = IOSBinaryScanOutputLoader().load(scan_dir)

    assert loaded["scan_metadata"] == {"platform": "IOS"}
    assert loaded["opengrep"] is None
    assert loaded["ipsw_outputs"] == {}
    assert loaded["lief_outputs"] == {}
    assert loaded["plist_outputs"] == {}
    assert loaded["plist_index"] is None
    assert loaded["strings_outputs"] == {}
    assert loaded["trufflehog_outputs"] == {}
    assert loaded["gitleaks_outputs"] == {}
    assert loaded["syft_outputs"] == {}


def test_ios_binary_scan_detail_extractor_returns_direct_ios_contract(tmp_path: Path) -> None:
    ipa_path = tmp_path / "DVIA-v2.ipa"
    ipa_path.write_bytes(b"ios-binary")
    loaded_outputs = {
        "scan_output_path": str(tmp_path),
        "scan_metadata": {
            "platform": "IOS",
            "project_path": str(ipa_path),
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
        "code_evidence",
        "network_evidence",
        "data_evidence",
        "resilience_evidence",
        "hardcoded_values",
        "endpoints",
    }
    assert result["meta"] == {
        "app_display_name": "DVIA-v2",
        "file_name": "DVIA-v2.ipa",
        "package_name": "com.highaltitudehacks.DVIAswiftv2",
        "scan_date": "2026-07-22 10:51:49",
        "platform": "iOS",
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
        "name": "DVIA-v2",
        "package_name": "com.highaltitudehacks.DVIAswiftv2",
        "main_activity": "DVIA",
        "version_name": "2.0 (1)",
        "app_store_id": "",
        "developer": "",
        "categories": "",
        "trackers_detected": "",
    }
    assert result["ipa_binary_evidence"] == {
        "nx": False,
        "pie": False,
        "stack canary": True,
        "arc": True,
        "rpath": True,
        "code signature": True,
        "encrypted": False,
        "symbols stripped": False,
    }
    assert result["url_schemes"] == []
    assert result["permissions"] == []
    assert result["endpoints"] == []
    assert result["hardcoded_values"] == {"urls": [], "emails": [], "secrets": []}
    assert result["code_evidence"] == {
        "uses_uiwebview": {
            "present": True,
            "evidence": "UIWebView reference detected.",
        },
        "insecure_nanopb_library": {
            "present": False,
            "evidence": "no_insecure_nanopb_library_hits",
        },
        "insecure_nskeyedunarchiver_usage": {
            "present": True,
            "evidence": "decodeObject usage detected.",
        },
        "missing_arc": {
            "present": False,
            "evidence": "no_missing_arc_hits",
        },
        "pic_not_enabled": {
            "present": True,
            "evidence": "PIE flag not detected in main Mach-O metadata",
        },
        "stack_canaries_not_enabled": {
            "present": False,
            "evidence": "no_stack_canaries_not_enabled_hits",
        },
        "insecure_api_usage_in_binary": {
            "present": False,
            "evidence": "no_insecure_api_usage_in_binary_hits",
        },
        "malloc_instead_of_calloc": {
            "present": False,
            "evidence": "no_malloc_instead_of_calloc_hits",
        },
        "encodes_data_using_insecure_cryptography": {
            "present": False,
            "evidence": "no_encodes_data_using_insecure_cryptography_hits",
        },
        "utilizes_insecure_cryptography": {
            "present": False,
            "evidence": "no_utilizes_insecure_cryptography_hits",
        },
        "pbkdf2_iteration_count_below_10k": {
            "present": False,
            "evidence": "no_pbkdf2_iteration_count_below_10k_hits",
        },
        "hardcoded_api_keys_in_bundle": {
            "present": True,
            "evidence": "report.json: Secret Type: API Key",
        },
        "insecure_entitlements": {
            "present": True,
            "evidence": "get-task-allow",
        },
    }
    assert set(result["network_evidence"]) == {
        "ats_disabled",
        "vulnerable_openssl_ccs_injection",
        "uses_ftp",
        "vulnerable_openssl_heartbleed",
        "insecure_http_traffic",
        "ats_exceptions_configured",
        "cookie_missing_httponly",
        "cookie_missing_secure",
        "cleartext_http_advertiser_id",
        "cleartext_http_imei",
        "cleartext_http_gps_latitude",
        "cleartext_http_gps_longitude",
        "cleartext_http_sensitive_data",
        "cleartext_http_wifi_mac",
        "https_url_contains_imei",
        "https_url_contains_gps_latitude",
        "https_url_contains_gps_longitude",
        "https_url_contains_sensitive_data",
        "https_url_contains_wifi_mac",
        "insecure_tls_configuration",
        "certificate_pinning_not_implemented",
    }
    assert set(result["data_evidence"]) == {
        "deprecated_keychain_attributes",
        "advertiser_id_stored_insecurely",
        "imei_stored_insecurely",
        "global_write_permissions",
        "gps_latitude_stored_insecurely",
        "gps_longitude_stored_insecurely",
        "hardcoded_api_keys_stored_insecurely",
        "hardcoded_passwords_stored_insecurely",
        "sensitive_values_stored_insecurely",
        "wifi_ip_stored_insecurely",
        "wifi_mac_stored_insecurely",
        "keychain_plaintext_values",
        "nsuserdefaults_sensitive_values",
        "advertiser_id_logged_insecurely",
        "imei_logged_insecurely",
        "gps_latitude_logged_insecurely",
        "gps_longitude_logged_insecurely",
        "sensitive_data_logged_insecurely",
        "sensitive_values_in_memory",
        "wifi_mac_logged_insecurely",
        "keyboard_cache_exposure",
    }
    assert result["resilience_evidence"] == {
        "biometric_bypass_possible": {
            "present": False,
            "evidence": "no_biometric_bypass_possible_hits",
        },
        "debug_symbols_present": {
            "present": False,
            "evidence": "no_debug_symbols_present_hits",
        },
    }
    assert list(result["functionality"]) == [
        "Camera",
        "Biometric Authentication",
        "Networking",
        "Secure RNG",
        "Push Notifications",
        "Audio",
        "Contacts",
        "Geofencing",
        "Health Data",
        "Location",
        "Maps",
        "Payment Services",
        "SMS",
        "Bluetooth",
        "Camera Delegation",
        "Calendar",
        "In-App Purchases",
        "Keychain",
        "Microphone",
        "NFC",
        "Photos",
        "Sensors",
        "Telephony",
        "USB Devices",
        "Nearby Interaction",
    ]


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


def test_ios_ipa_binary_evidence_requires_both_canary_imports() -> None:
    loaded_outputs = {
        "lief_outputs": {
            "App.json": {
                "binary": {
                    "kind": "main",
                    "slices": [{"imported_functions": ["___stack_chk_fail"]}],
                }
            }
        }
    }

    result = IOSBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert result["ipa_binary_evidence"]["stack canary"] is False
    assert result["ipa_binary_evidence"]["arc"] is False


def test_ios_ipa_binary_evidence_ignores_framework_only_imports() -> None:
    loaded_outputs = {
        "lief_outputs": {
            "App.json": {
                "binary": {
                    "kind": "main",
                    "slices": [{"imported_functions": []}],
                }
            },
            "Frameworks/Foo.framework/Foo.json": {
                "binary": {
                    "kind": "framework",
                    "slices": [
                        {
                            "imported_functions": [
                                "___stack_chk_fail",
                                "___stack_chk_guard",
                                "_objc_release",
                            ]
                        }
                    ],
                }
            },
        }
    }

    result = IOSBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert result["ipa_binary_evidence"]["stack canary"] is False
    assert result["ipa_binary_evidence"]["arc"] is False


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
    assert result["code_evidence"]["uses_uiwebview"]["present"] is False
    assert result["network_evidence"]["ats_disabled"]["present"] is False


def test_ios_network_evidence_derives_ats_disabled_from_app_plist_only() -> None:
    enabled = IOSNetworkEvidence(
        {
            "plist_outputs": {
                "Info.json": {
                    "app_meta": {"bundle_identifier": "com.example.app"},
                    "ats": {"allows_arbitrary_loads": True},
                },
                "Frameworks/SDK.framework/Info.json": {
                    "framework_meta": {"bundle_identifier": "com.example.sdk"},
                    "ats": {"allows_arbitrary_loads": True},
                },
            }
        }
    )
    assert enabled.ats_disabled.present is True
    assert enabled.ats_disabled.evidence == "Info.json: NSAllowsArbitraryLoads=true"

    not_enabled = IOSNetworkEvidence(
        {
            "plist_outputs": {
                "Info.json": {
                    "app_meta": {"bundle_identifier": "com.example.app"},
                    "ats": {"allows_arbitrary_loads": False},
                },
                "Frameworks/SDK.framework/Info.json": {
                    "framework_meta": {"bundle_identifier": "com.example.sdk"},
                    "ats": {"allows_arbitrary_loads": True},
                },
            }
        }
    )
    assert not_enabled.ats_disabled.present is False
    assert not_enabled.ats_disabled.evidence == "no_ats_disabled_hits"


def test_ios_network_evidence_detects_vulnerable_openssl_ccs_versions() -> None:
    from_sbom = IOSNetworkEvidence(
        {
            "syft_outputs": {
                "sbom.json": {
                    "artifacts": [
                        {"name": "openssl", "version": "1.0.1g"},
                        {"name": "libssl", "version": "1.0.1h"},
                    ]
                }
            }
        }
    )
    assert from_sbom.vulnerable_openssl_ccs_injection.present is True
    assert from_sbom.vulnerable_openssl_ccs_injection.evidence == "sbom.json: openssl@1.0.1g"

    from_strings = IOSNetworkEvidence({"strings_outputs": {"Frameworks/SDK.txt": "OpenSSL 0.9.8z\n"}})
    assert from_strings.vulnerable_openssl_ccs_injection.present is True
    assert from_strings.vulnerable_openssl_ccs_injection.evidence == "Frameworks/SDK.txt: OpenSSL 0.9.8z"

    fixed_or_unversioned = IOSNetworkEvidence(
        {
            "syft_outputs": {"sbom.json": {"components": [{"name": "openssl", "version": "1.0.1h"}]}},
            "strings_outputs": {"main.txt": "OpenSSL\nlibssl 1.0.1g\n"},
        }
    )
    assert fixed_or_unversioned.vulnerable_openssl_ccs_injection.present is False
    assert fixed_or_unversioned.vulnerable_openssl_ccs_injection.evidence == "no_vulnerable_openssl_ccs_injection_hits"


def test_ios_network_evidence_detects_ftp_endpoints() -> None:
    from_strings = IOSNetworkEvidence(
        {"strings_outputs": {"main.txt": "download ftp://files.example.com/update.zip\n"}}
    )
    assert from_strings.uses_ftp.present is True
    assert from_strings.uses_ftp.evidence == "main.txt: ftp://files.example.com/update.zip"

    from_plist = IOSNetworkEvidence(
        {
            "plist_outputs": {
                "Info.json": {
                    "app_meta": {"bundle_identifier": "com.example.app"},
                    "plist": {"Download": {"URL": "ftps://files.example.com/update.zip"}},
                }
            }
        }
    )
    assert from_plist.uses_ftp.present is True
    assert from_plist.uses_ftp.evidence == "Info.json: ftps://files.example.com/update.zip"

    no_endpoint = IOSNetworkEvidence(
        {
            "strings_outputs": {"main.txt": "FTP support via libcurl\n"},
            "plist_outputs": {
                "Frameworks/SDK.framework/Info.json": {
                    "framework_meta": {"bundle_identifier": "com.example.sdk"},
                    "plist": {"Description": "FTP integration"},
                }
            },
        }
    )
    assert no_endpoint.uses_ftp.present is False
    assert no_endpoint.uses_ftp.evidence == "no_uses_ftp_hits"


def test_ios_network_evidence_detects_public_http_endpoints() -> None:
    from_strings = IOSNetworkEvidence({"strings_outputs": {"main.txt": "http://api.example.com/v1\n"}})
    assert from_strings.insecure_http_traffic.present is True
    assert from_strings.insecure_http_traffic.evidence == "main.txt: http://api.example.com/v1"

    from_plist = IOSNetworkEvidence(
        {
            "plist_outputs": {
                "Info.json": {
                    "app_meta": {"bundle_identifier": "com.example.app"},
                    "plist": {"API": "http://api.example.com/v1"},
                }
            }
        }
    )
    assert from_plist.insecure_http_traffic.present is True
    assert from_plist.insecure_http_traffic.evidence == "Info.json: http://api.example.com/v1"

    no_public_endpoint = IOSNetworkEvidence(
        {
            "strings_outputs": {
                "main.txt": (
                    "https://api.example.com/v1\n"
                    "http://localhost:8080\n"
                    "http://127.0.0.1:8080\n"
                    "http://www.apple.com/DTDs/PropertyList-1.0.dtd\n"
                )
            },
            "plist_outputs": {
                "Frameworks/SDK.framework/Info.json": {
                    "framework_meta": {"bundle_identifier": "com.example.sdk"},
                    "plist": {"API": "http://api.example.com/v1"},
                }
            },
        }
    )
    assert no_public_endpoint.insecure_http_traffic.present is False
    assert no_public_endpoint.insecure_http_traffic.evidence == "no_insecure_http_traffic_hits"


def test_ios_functionality_derives_capabilities_from_loaded_outputs() -> None:
    loaded_outputs = {
        "plist_outputs": {
            "Info.json": {
                "app_meta": {
                    "required_device_capabilities": ["arm64", "nfc"],
                },
                "ats": {
                    "allows_arbitrary_loads": False,
                    "exception_domains": [],
                },
                "background_modes": ["remote-notification"],
                "privacy": {
                    "permissions": [
                        {"key": "NSCameraUsageDescription", "purpose": "Take photos"},
                        {"key": "NSFaceIDUsageDescription", "purpose": "Sign in"},
                        {"key": "NSMicrophoneUsageDescription", "purpose": "Record audio"},
                        {"key": "NSContactsUsageDescription", "purpose": "Find friends"},
                        {"key": "NSCalendarsUsageDescription", "purpose": "Show events"},
                        {"key": "NSLocationWhenInUseUsageDescription", "purpose": "Find nearby stores"},
                        {"key": "NSBluetoothAlwaysUsageDescription", "purpose": "Connect accessories"},
                        {"key": "NSPhotoLibraryUsageDescription", "purpose": "Pick photos"},
                        {"key": "NSNearbyInteractionUsageDescription", "purpose": "Nearby devices"},
                    ]
                },
                "url_schemes": {
                    "declared_schemes": ["myapp"],
                    "queried_schemes": ["maps", "tel"],
                },
                "plist": {
                    "UISupportedExternalAccessoryProtocols": ["com.example.reader"],
                },
            },
            "Entitlements.json": {
                "entitlements": {
                    "aps_environment": "development",
                    "keychain_access_groups": ["ABC123.com.example.shared"],
                }
            },
        },
        "ipsw_outputs": {
            "Payload/App.app/App.json": {
                "analysis": {
                    "entitlements": {
                        "values": {
                            "aps-environment": "development",
                            "keychain-access-groups": ["ABC123.com.example.shared"],
                        }
                    }
                }
            }
        },
        "opengrep": {
            "results": [
                {
                    "check_id": "ios.secure.rng.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "description": "Secure RNG usage detected.",
                            }
                        }
                    },
                },
                {
                    "check_id": "ios.networking.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "description": "Networking usage detected.",
                            }
                        }
                    },
                },
                {
                    "check_id": "ios.telephony.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "description": "Telephony usage detected.",
                            }
                        }
                    },
                },
                {
                    "check_id": "ios.usb.devices.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "description": "USB devices usage detected.",
                            }
                        }
                    },
                },
            ]
        },
        "strings_outputs": {
            "main.txt": "https://api.example.com\nCoreTelephony\nExternalAccessory\n",
        },
    }

    sections = IOSBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["functionality"]["Camera"] == {
        "present": True,
        "explanation": "plist key NSCameraUsageDescription present.",
    }
    assert sections["functionality"]["Biometric Authentication"] == {
        "present": True,
        "explanation": "plist key NSFaceIDUsageDescription present.",
    }
    assert sections["functionality"]["Networking"] == {
        "present": True,
        "explanation": "Info.plist declares NSAppTransportSecurity. Info.plist declares URL scheme handling. Networking usage detected.",
    }
    assert sections["functionality"]["Secure RNG"] == {
        "present": True,
        "explanation": "Secure RNG usage detected.",
    }
    assert sections["functionality"]["Push Notifications"] == {
        "present": True,
        "explanation": "entitlement aps_environment present. background mode remote-notification declared.",
    }
    assert sections["functionality"]["Contacts"]["present"] is True
    assert sections["functionality"]["Calendar"]["present"] is True
    assert sections["functionality"]["Location"]["present"] is True
    assert sections["functionality"]["Bluetooth"]["present"] is True
    assert sections["functionality"]["Microphone"]["present"] is True
    assert sections["functionality"]["NFC"] == {
        "present": True,
        "explanation": "required device capabilities include nfc.",
    }
    assert sections["functionality"]["Photos"]["present"] is True
    assert sections["functionality"]["Maps"] == {
        "present": True,
        "explanation": "queried URL schemes maps declared.",
    }
    assert sections["functionality"]["Keychain"] == {
        "present": True,
        "explanation": "entitlement keychain_access_groups present.",
    }
    assert sections["functionality"]["Nearby Interaction"] == {
        "present": True,
        "explanation": "plist key NSNearbyInteractionUsageDescription present.",
    }
    assert sections["functionality"]["Audio"] == {
        "present": False,
        "explanation": "",
    }
    assert sections["functionality"]["Telephony"] == {
        "present": True,
        "explanation": "URL schemes tel declared or queried. Telephony usage detected.",
    }
    assert sections["functionality"]["USB Devices"] == {
        "present": True,
        "explanation": "external accessory protocols declared: com.example.reader. USB devices usage detected.",
    }
    assert sections["permissions"] == [
        {
            "permission": "NSBluetoothAlwaysUsageDescription",
            "status": "dangerous",
            "info": "Access Bluetooth",
            "usage_description": "Connect accessories",
            "general_description": "Permits scanning for and connecting to nearby Bluetooth devices.",
        },
        {
            "permission": "NSCalendarsUsageDescription",
            "status": "dangerous",
            "info": "Access Calendar",
            "usage_description": "Show events",
            "general_description": "Permits access to the user's calendar data.",
        },
        {
            "permission": "NSCameraUsageDescription",
            "status": "dangerous",
            "info": "Access Camera",
            "usage_description": "Take photos",
            "general_description": "Permits access to the device's camera hardware.",
        },
        {
            "permission": "NSContactsUsageDescription",
            "status": "dangerous",
            "info": "Access Contacts",
            "usage_description": "Find friends",
            "general_description": "Permits access to the user's contacts database.",
        },
        {
            "permission": "NSFaceIDUsageDescription",
            "status": "normal",
            "info": "Use Face ID",
            "usage_description": "Sign in",
            "general_description": "Permits use of Face ID for biometric authentication.",
        },
        {
            "permission": "NSLocationWhenInUseUsageDescription",
            "status": "dangerous",
            "info": "Access Location While Using App",
            "usage_description": "Find nearby stores",
            "general_description": "Permits access to the device's location while the app is in use.",
        },
        {
            "permission": "NSMicrophoneUsageDescription",
            "status": "dangerous",
            "info": "Access Microphone",
            "usage_description": "Record audio",
            "general_description": "Permits recording audio with the device microphone.",
        },
        {
            "permission": "NSNearbyInteractionUsageDescription",
            "status": "normal",
            "info": "Nearby Interaction",
            "usage_description": "Nearby devices",
            "general_description": "Permits use of nearby interaction features with supported devices.",
        },
        {
            "permission": "NSPhotoLibraryUsageDescription",
            "status": "dangerous",
            "info": "Access Photos",
            "usage_description": "Pick photos",
            "general_description": "Permits reading from the user's photo library.",
        },
    ]


def test_ios_code_evidence_uses_imports_and_opengrep_heuristics() -> None:
    loaded_outputs = {
        "lief_outputs": {
            "App.json": {
                "binary": {
                    "kind": "main",
                    "slices": [
                        {
                            "imported_functions": [
                                "_fopen",
                                "_malloc",
                                "_objc_release",
                            ],
                            "libraries": [],
                        }
                    ],
                }
            }
        },
        "gitleaks_outputs": {
            "report.json": [
                {
                    "RuleID": "generic-api-key",
                    "Description": "API Key",
                    "File": "Config.swift",
                    "StartLine": 12,
                    "EndLine": 14,
                }
            ]
        },
        "opengrep": {
            "results": [
                {
                    "check_id": "ios.pbkdf2.rule",
                    "extra": {
                        "message": "PBKDF2 iteration count 5000 detected.",
                        "metadata": {
                            "phoenix": {
                                "title": "PBKDF2 Iteration Count <10k",
                                "description": "PBKDF2 iteration count <10k detected.",
                            }
                        },
                    },
                },
                {
                    "check_id": "ios.crypto.encoding.md5",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "title": "Weak Hash Usage",
                                "description": "MD5 hashing detected during encoding flow.",
                            }
                        }
                    },
                },
            ]
        },
        "strings_outputs": {
            "main.txt": "CCCrypt using DES\n",
        },
        "syft_outputs": {
            "sbom.json": {
                "artifacts": [
                    {
                        "name": "nanopb",
                        "version": "1.0.0",
                    }
                ]
            }
        },
    }

    sections = IOSBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["code_evidence"]["insecure_nanopb_library"] == {
        "present": True,
        "evidence": "nanopb@1.0.0",
    }
    assert sections["code_evidence"]["missing_arc"] == {
        "present": False,
        "evidence": "no_missing_arc_hits",
    }
    assert sections["code_evidence"]["stack_canaries_not_enabled"] == {
        "present": True,
        "evidence": "main Mach-O imports do not expose ___stack_chk_fail and ___stack_chk_guard",
    }
    assert sections["code_evidence"]["insecure_api_usage_in_binary"] == {
        "present": True,
        "evidence": "_fopen",
    }
    assert sections["code_evidence"]["malloc_instead_of_calloc"] == {
        "present": True,
        "evidence": "_malloc",
    }
    assert sections["code_evidence"]["pbkdf2_iteration_count_below_10k"] == {
        "present": True,
        "evidence": "PBKDF2 iteration count 5000 detected.",
    }
    assert sections["code_evidence"]["encodes_data_using_insecure_cryptography"] == {
        "present": True,
        "evidence": "MD5 hashing detected during encoding flow.",
    }
    assert sections["code_evidence"]["utilizes_insecure_cryptography"] == {
        "present": True,
        "evidence": "des",
    }
    assert sections["code_evidence"]["hardcoded_api_keys_in_bundle"] == {
        "present": True,
        "evidence": "report.json: generic-api-key (Config.swift:12-14)",
    }


def test_ios_code_evidence_does_not_treat_strings_only_crypto_hints_as_confirmed_encoding() -> None:
    loaded_outputs = {
        "strings_outputs": {
            "main.txt": "CCCrypt using DES\n",
        }
    }

    sections = IOSBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["code_evidence"]["encodes_data_using_insecure_cryptography"] == {
        "present": False,
        "evidence": "no_encodes_data_using_insecure_cryptography_hits",
    }
    assert sections["code_evidence"]["utilizes_insecure_cryptography"] == {
        "present": True,
        "evidence": "des",
    }


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


def test_android_binary_scan_detail_extractor_maps_opengrep_functionality_checks() -> None:
    loaded_outputs = {
        "aapt2_permissions": {"permissions": []},
        "opengrep": {
            "results": [
                {
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 9,
                                "title": "Background execution modes declared by the app",
                                "description": "Background execution detected.",
                            }
                        }
                    }
                },
                {
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 53,
                                "title": "Camera usage declaration present",
                                "description": "Camera usage detected.",
                            }
                        }
                    }
                },
                {
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 54,
                                "title": "Microphone usage declaration present",
                                "description": "Microphone usage detected.",
                            }
                        }
                    }
                },
                {
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 56,
                                "title": "NFC usage declaration present",
                                "description": "NFC usage detected.",
                            }
                        }
                    }
                },
                {
                    "check_id": "android.fingerprint.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 57,
                                "title": "Fingerprint usage declaration present",
                                "description": "Fingerprint usage detected.",
                            }
                        }
                    },
                },
                {
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 58,
                                "title": "Bluetooth usage declaration present",
                                "description": "Bluetooth usage detected.",
                            }
                        }
                    }
                },
                {
                    "check_id": "android.sms.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 59,
                                "title": "SMS usage declaration present",
                                "description": "SMS usage detected.",
                            }
                        }
                    },
                },
                {
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 60,
                                "title": "Contacts usage declaration present",
                                "description": "Contacts usage detected.",
                            }
                        }
                    }
                },
                {
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 60,
                                "title": "Calendar usage declaration present",
                                "description": "Calendar usage detected.",
                            }
                        }
                    }
                },
                {
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 61,
                                "title": "Push notification registration and background push behavior present",
                                "description": "Push messaging usage detected.",
                            }
                        }
                    }
                },
            ]
        },
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["functionality"]["Background Execution"] == {
        "present": True,
        "explanation": "Background execution detected.",
    }
    assert sections["functionality"]["Camera"] == {
        "present": True,
        "explanation": "Camera usage detected.",
    }
    assert sections["functionality"]["Microphone"] == {
        "present": True,
        "explanation": "Microphone usage detected.",
    }
    assert sections["functionality"]["NFC"] == {
        "present": True,
        "explanation": "NFC usage detected.",
    }
    assert sections["functionality"]["Fingerprint"] == {
        "present": True,
        "explanation": "Fingerprint usage detected.",
    }
    assert sections["functionality"]["Bluetooth"] == {
        "present": True,
        "explanation": "Bluetooth usage detected.",
    }
    assert sections["functionality"]["SMS"] == {
        "present": True,
        "explanation": "SMS usage detected.",
    }
    assert sections["functionality"]["Contacts"] == {
        "present": True,
        "explanation": "Contacts usage detected.",
    }
    assert sections["functionality"]["Calendar"] == {
        "present": True,
        "explanation": "Calendar usage detected.",
    }
    assert sections["functionality"]["Google Cloud Messaging"] == {
        "present": True,
        "explanation": "Push messaging usage detected.",
    }


def test_android_binary_scan_detail_extractor_maps_recent_opengrep_functionality_checks() -> None:
    loaded_outputs = {
        "aapt2_permissions": {"permissions": []},
        "opengrep": {
            "results": [
                {
                    "check_id": "android.maps.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 62, "description": "Maps usage detected."}}},
                },
                {
                    "check_id": "android.networking.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 63, "description": "Networking usage detected."}}},
                },
                {
                    "check_id": "android.telephony.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 64, "description": "Telephony usage detected."}}},
                },
                {
                    "check_id": "android.photos.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 65, "description": "Photos usage detected."}}},
                },
                {
                    "check_id": "android.in_app_purchases.usage.present",
                    "extra": {
                        "metadata": {"phoenix": {"check_id": 66, "description": "In-app purchases usage detected."}}
                    },
                },
                {
                    "check_id": "android.device.administrator.usage.present",
                    "extra": {
                        "metadata": {"phoenix": {"check_id": 67, "description": "Device administrator usage detected."}}
                    },
                },
                {
                    "check_id": "android.camera.delegation.usage.present",
                    "extra": {
                        "metadata": {"phoenix": {"check_id": 68, "description": "Camera delegation usage detected."}}
                    },
                },
                {
                    "check_id": "android.sensors.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 69, "description": "Sensors usage detected."}}},
                },
                {
                    "check_id": "android.usb.devices.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 70, "description": "USB devices usage detected."}}},
                },
                {
                    "check_id": "android.geofencing.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 71, "description": "Geofencing usage detected."}}},
                },
                {
                    "check_id": "android.health.data.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 72, "description": "Health data usage detected."}}},
                },
                {
                    "check_id": "android.infrared.led.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 73, "description": "Infrared LED usage detected."}}},
                },
                {
                    "check_id": "android.audio.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 74, "description": "Audio usage detected."}}},
                },
                {
                    "check_id": "android.payment.services.usage.present",
                    "extra": {
                        "metadata": {"phoenix": {"check_id": 75, "description": "Payment services usage detected."}}
                    },
                },
                {
                    "check_id": "android.secure.rng.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 76, "description": "Secure RNG usage detected."}}},
                },
                {
                    "check_id": "android.keystore.usage.present",
                    "extra": {"metadata": {"phoenix": {"check_id": 77, "description": "Keystore usage detected."}}},
                },
            ]
        },
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["functionality"]["Maps"] == {"present": True, "explanation": "Maps usage detected."}
    assert sections["functionality"]["Networking"] == {"present": True, "explanation": "Networking usage detected."}
    assert sections["functionality"]["Telephony"] == {"present": True, "explanation": "Telephony usage detected."}
    assert sections["functionality"]["Photos"] == {"present": True, "explanation": "Photos usage detected."}
    assert sections["functionality"]["In-App Purchases"] == {
        "present": True,
        "explanation": "In-app purchases usage detected.",
    }
    assert sections["functionality"]["Device Administrator"] == {
        "present": True,
        "explanation": "Device administrator usage detected.",
    }
    assert sections["functionality"]["Camera Delegation"] == {
        "present": True,
        "explanation": "Camera delegation usage detected.",
    }
    assert sections["functionality"]["Sensors"] == {"present": True, "explanation": "Sensors usage detected."}
    assert sections["functionality"]["USB Devices"] == {"present": True, "explanation": "USB devices usage detected."}
    assert sections["functionality"]["Geofencing"] == {"present": True, "explanation": "Geofencing usage detected."}
    assert sections["functionality"]["Health Data"] == {"present": True, "explanation": "Health data usage detected."}
    assert sections["functionality"]["Infrared LED"] == {
        "present": True,
        "explanation": "Infrared LED usage detected.",
    }
    assert sections["functionality"]["Audio"] == {"present": True, "explanation": "Audio usage detected."}
    assert sections["functionality"]["Payment Services"] == {
        "present": True,
        "explanation": "Payment services usage detected.",
    }
    assert sections["functionality"]["Secure RNG"] == {
        "present": True,
        "explanation": "Secure RNG usage detected.",
    }
    assert sections["functionality"]["Keystore"] == {"present": True, "explanation": "Keystore usage detected."}


def test_android_binary_scan_detail_extractor_combines_permission_and_opengrep_functionality_evidence() -> None:
    loaded_outputs = {
        "aapt2_permissions": {
            "permissions": [
                {
                    "name": "android.permission.RECEIVE_BOOT_COMPLETED",
                    "protection_level_hint": "unknown_or_normal",
                },
                {
                    "name": "android.permission.READ_CALENDAR",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.SEND_SMS",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.USE_BIOMETRIC",
                    "protection_level_hint": "unknown_or_normal",
                },
            ]
        },
        "opengrep": {
            "results": [
                {
                    "check_id": "android.background.execution.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 9,
                                "title": "Background execution modes declared by the app",
                                "description": "Background execution detected.",
                            }
                        }
                    },
                },
                {
                    "check_id": "android.calendar.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 60,
                                "title": "Calendar usage declaration present",
                                "description": "Calendar usage detected.",
                            }
                        }
                    },
                },
                {
                    "check_id": "android.sms.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 59,
                                "title": "SMS usage declaration present",
                                "description": "SMS usage detected.",
                            }
                        }
                    },
                },
                {
                    "check_id": "android.fingerprint.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 57,
                                "title": "Fingerprint usage declaration present",
                                "description": "Fingerprint usage detected.",
                            }
                        }
                    },
                },
            ]
        },
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["functionality"]["Background Execution"] == {
        "present": True,
        "explanation": (
            "Background execution detected. "
            "The app also declares permission android.permission.RECEIVE_BOOT_COMPLETED, "
            "which may indicate background execution functionality."
        ),
    }
    assert sections["functionality"]["Calendar"] == {
        "present": True,
        "explanation": (
            "Calendar usage detected. "
            "The app also declares permission android.permission.READ_CALENDAR, "
            "which may indicate calendar functionality."
        ),
    }
    assert sections["functionality"]["SMS"] == {
        "present": True,
        "explanation": (
            "SMS usage detected. "
            "The app also declares permission android.permission.SEND_SMS, "
            "which may indicate SMS functionality."
        ),
    }
    assert sections["functionality"]["Fingerprint"] == {
        "present": True,
        "explanation": (
            "Fingerprint usage detected. "
            "The app also declares permission android.permission.USE_BIOMETRIC, "
            "which may indicate fingerprint functionality."
        ),
    }


def test_android_binary_scan_detail_extractor_maps_sms_permission_only_functionality_evidence() -> None:
    loaded_outputs = {
        "aapt2_permissions": {
            "permissions": [
                {
                    "name": "android.permission.RECEIVE_SMS",
                    "protection_level_hint": "dangerous",
                }
            ]
        },
        "opengrep": {"results": []},
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["functionality"]["SMS"] == {
        "present": True,
        "explanation": "permission android.permission.RECEIVE_SMS, which may indicate SMS functionality.",
    }


def test_android_binary_scan_detail_extractor_maps_fingerprint_permission_only_functionality_evidence() -> None:
    loaded_outputs = {
        "aapt2_permissions": {
            "permissions": [
                {
                    "name": "android.permission.USE_FINGERPRINT",
                    "protection_level_hint": "unknown_or_normal",
                }
            ]
        },
        "opengrep": {"results": []},
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["functionality"]["Fingerprint"] == {
        "present": True,
        "explanation": "permission android.permission.USE_FINGERPRINT, which may indicate fingerprint functionality.",
    }


def test_android_binary_scan_detail_extractor_maps_recent_permission_only_functionality_evidence() -> None:
    loaded_outputs = {
        "aapt2_permissions": {
            "permissions": [
                {"name": "android.permission.READ_PHONE_STATE", "protection_level_hint": "dangerous"},
                {"name": "android.permission.READ_MEDIA_IMAGES", "protection_level_hint": "dangerous"},
                {"name": "android.permission.BODY_SENSORS", "protection_level_hint": "dangerous"},
            ]
        },
        "opengrep": {"results": []},
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["functionality"]["Telephony"] == {
        "present": True,
        "explanation": "permission android.permission.READ_PHONE_STATE, which may indicate telephony functionality.",
    }
    assert sections["functionality"]["Photos"] == {
        "present": True,
        "explanation": "permission android.permission.READ_MEDIA_IMAGES, which may indicate photo functionality.",
    }
    assert sections["functionality"]["Sensors"] == {
        "present": True,
        "explanation": "permission android.permission.BODY_SENSORS, which may indicate sensor functionality.",
    }


def test_android_binary_scan_detail_extractor_maps_shared_check_id_60_with_rule_ids() -> None:
    loaded_outputs = {
        "aapt2_permissions": {"permissions": []},
        "opengrep": {
            "results": [
                {
                    "check_id": "android.contacts.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 60,
                                "title": "Contacts usage declaration present",
                                "description": "Contacts usage detected.",
                            }
                        }
                    },
                },
                {
                    "check_id": "android.calendar.usage.present",
                    "extra": {
                        "metadata": {
                            "phoenix": {
                                "check_id": 60,
                                "title": "Calendar usage declaration present",
                                "description": "Calendar usage detected.",
                            }
                        }
                    },
                },
            ]
        },
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["functionality"]["Contacts"] == {
        "present": True,
        "explanation": "Contacts usage detected.",
    }
    assert sections["functionality"]["Calendar"] == {
        "present": True,
        "explanation": "Calendar usage detected.",
    }


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
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
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
    assert result["functionality"]["Location"]["present"] is True
    assert result["functionality"]["Camera"] == {
        "present": True,
        "explanation": "permission android.permission.CAMERA, which may indicate camera functionality.",
    }
    assert result["network_evidence"] == {
        "allows_cleartext_traffic_for_all_domains": {
            "present": False,
            "evidence": "",
        },
        "contains_hostname_verifier_accepts_all": {
            "present": None,
            "evidence": "",
        },
        "contains_x509_trust_manager_accepts_all": {
            "present": None,
            "evidence": "",
        },
        "does_not_perform_certificate_pinning": {
            "present": True,
            "evidence": "",
        },
        "opens_listening_port": {
            "present": None,
            "evidence": "",
        },
        "sensitive_cookies_lack_security_attributes": {
            "present": None,
            "evidence": "",
        },
        "unnecessary_information_transmitted": {
            "present": False,
            "evidence": "no_unique_identifier_network_overlap",
        },
        "sensitive_information_unencrypted_in_transit": {
            "present": False,
            "evidence": "no_http_endpoints_detected",
        },
        "password_not_hashed_in_transit": {
            "present": None,
            "evidence": "",
        },
        "weak_certificate_validation_enables_mitm": {
            "present": False,
            "evidence": "",
        },
        "manifest_cleartext_traffic_permitted": None,
    }
    assert result["deep_links"] == {"deep_links": []}
    assert result["hardcoded_values"] == {
        "urls": [
            {
                "url": "https://api.apkpure.com/v1/apps",
                "country": "",
            }
        ],
        "emails": [],
        "secrets": [
            {
                "value": "token=abc123",
                "location": "AndroidManifest.xml:88",
            }
        ],
    }
    assert result["endpoints"] == [
        {
            "endpoint": "https://api.apkpure.com/v1/apps",
            "tags": "url",
            "ip_address": "",
            "country": "",
        },
        {
            "endpoint": "apkpure.com",
            "tags": "domain",
            "ip_address": "",
            "country": "",
        },
    ]


def test_android_binary_scan_detail_extractor_builds_storage_evidence_from_permissions_and_api_calls() -> None:
    loaded_outputs = {
        "aapt2_permissions": {
            "permissions": [
                {
                    "name": "android.permission.READ_EXTERNAL_STORAGE",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.WRITE_EXTERNAL_STORAGE",
                    "protection_level_hint": "dangerous",
                },
            ]
        },
        "androguard_api_calls": {
            "items": [
                {
                    "callee": {
                        "method_name": "getSharedPreferences",
                        "signature": (
                            "Landroid/content/Context; getSharedPreferences "
                            "(Ljava/lang/String; I)Landroid/content/SharedPreferences;"
                        ),
                    },
                    "caller": {
                        "signature": ("Lcom/example/LoginActivity; savePassword (Ljava/lang/String;)V"),
                    },
                }
            ]
        },
        "opengrep": {"results": []},
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["storage_evidence"] == {
        "accesses_external_storage": {
            "present": True,
            "evidence": ("android.permission.READ_EXTERNAL_STORAGE, android.permission.WRITE_EXTERNAL_STORAGE"),
        },
        "authentication_credentials_not_protected_with_android_keystore": {
            "present": True,
            "evidence": "Lcom/example/LoginActivity; savePassword (Ljava/lang/String;)V",
        },
        "sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage": {
            "present": False,
            "evidence": "no_world_readable_internal_storage_hits",
        },
        "sensitive_information_stored_in_external_storage": {
            "present": False,
            "evidence": "no_external_storage_sensitive_hits",
        },
        "does_not_prevent_screen_capture_of_sensitive_information": {
            "present": None,
            "evidence": "",
        },
    }


def test_android_binary_scan_detail_extractor_marks_password_not_hashed_in_transit_present() -> None:
    loaded_outputs = {
        "aapt2_application": {},
        "aapt2_manifest_security_posture": {},
        "apktool_network_security_config": {},
        "androguard_api_calls": {
            "items": [
                {
                    "callee": {
                        "method_name": "openConnection",
                        "signature": "Ljava/net/URL; openConnection ()Ljava/net/URLConnection;",
                    },
                    "caller": {
                        "signature": ("Lcom/example/LoginActivity; submitPassword (Ljava/lang/String;)V"),
                    },
                    "categories": ["network"],
                }
            ]
        },
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["network_evidence"]["password_not_hashed_in_transit"] == {
        "present": True,
        "evidence": "Lcom/example/LoginActivity; submitPassword (Ljava/lang/String;)V",
    }


def test_android_binary_scan_detail_extractor_marks_password_not_hashed_in_transit_not_present_when_hash_seen() -> None:
    loaded_outputs = {
        "aapt2_application": {},
        "aapt2_manifest_security_posture": {},
        "apktool_network_security_config": {},
        "androguard_api_calls": {
            "items": [
                {
                    "callee": {
                        "method_name": "openConnection",
                        "signature": "Ljava/net/URL; openConnection ()Ljava/net/URLConnection;",
                    },
                    "caller": {
                        "signature": ("Lcom/example/LoginActivity; submitPassword (Ljava/lang/String;)V"),
                    },
                    "categories": ["network"],
                },
                {
                    "callee": {
                        "method_name": "digest",
                        "signature": "Ljava/security/MessageDigest; digest ([B)[B",
                    },
                    "caller": {
                        "signature": ("Lcom/example/LoginActivity; submitPassword (Ljava/lang/String;)V"),
                    },
                    "categories": ["crypto"],
                },
            ]
        },
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["network_evidence"]["password_not_hashed_in_transit"] == {
        "present": False,
        "evidence": "Lcom/example/LoginActivity; submitPassword (Ljava/lang/String;)V",
    }


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")

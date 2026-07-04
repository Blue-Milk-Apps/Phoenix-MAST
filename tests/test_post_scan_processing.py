import json
from pathlib import Path

from adapters.post_scan import (
    AndroidBinaryScanDetailExtractor,
    AndroidBinaryScanOutputLoader,
)
from application.post_scan_processing_service import PostScanProcessingService


def test_android_binary_scan_output_loader_loads_expected_artifacts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_android_binary_2026-07-03_23-34-29"
    (scan_dir / "opengrep_source").mkdir(parents=True)
    (scan_dir / "androguard").mkdir()
    (scan_dir / "aapt2").mkdir()
    (scan_dir / "apksigner").mkdir()

    _write_json(scan_dir / "scan_metadata.json", {"platform": "ANDROID"})
    _write_json(scan_dir / "opengrep_source" / "opengrep_results.json", {"results": []})
    _write_json(scan_dir / "androguard" / "components.json", {"activities": []})
    _write_json(scan_dir / "androguard" / "metadata.json", {"app_name": "APKPure"})
    _write_json(scan_dir / "androguard" / "certificates.json", {"all": []})
    _write_json(scan_dir / "aapt2" / "components.json", {"activities": []})
    _write_json(scan_dir / "aapt2" / "identity.json", {"application_label": "APKPure"})
    _write_json(scan_dir / "aapt2" / "application.json", {"id": "app"})
    _write_json(scan_dir / "apksigner" / "signing_evidence.json", {"verification": {}})

    loaded = AndroidBinaryScanOutputLoader().load(scan_dir)

    assert loaded["scan_output_path"] == str(scan_dir)
    assert loaded["scan_metadata"] == {"platform": "ANDROID"}
    assert loaded["opengrep"] == {"results": []}
    assert loaded["androguard_components"] == {"activities": []}
    assert loaded["androguard_metadata"] == {"app_name": "APKPure"}
    assert loaded["androguard_certificates"] == {"all": []}
    assert loaded["aapt2_components"] == {"activities": []}
    assert loaded["aapt2_identity"] == {"application_label": "APKPure"}
    assert loaded["aapt2_application"] == {"id": "app"}
    assert loaded["apksigner_signing_evidence"] == {"verification": {}}


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
                    "sha1": "ec330db8c45c5cceb66797163779bf1d186aecaf",
                    "sha256": "22311a95d67057b82318e23b3efd7cc878e190b8dcd55ac2e7bb745343957474",
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
                "sha256": "9614118b4e75e72e4fb65909fe95649efd89d00fb8435e99e5bebbec75bb1a31",
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
                        "sha256": "22311A95D67057B82318E23B3EFD7CC878E190B8DCD55AC2E7BB745343957474",
                        "signature_algorithm": "UNKNOWN",
                        "subject_dn": "CN=apkpure, OU=apkpure, O=apkpure",
                    }
                }
            ],
        },
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["app_info"] == {
        "icon_path": "",
        "name": "APKPure",
        "package_name": "com.apkpure.aegon",
        "main_activity": "com.apkpure.aegon.main.activity.FirstSeemPageActivity",
        "target_sdk": "34",
        "min_sdk": "19",
        "max_sdk": "",
        "version_name": "3.20.70",
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
    assert sections["certificate"]["fingerprint"] == (
        "22311a95d67057b82318e23b3efd7cc878e190b8dcd55ac2e7bb745343957474"
    )
    assert sections["certificate"]["unique_certs"] == "1"
    assert sections["file_info"] == {
        "filename": "APKPure.apk",
        "size": "25760048",
        "md5": "",
        "sha1": "",
        "sha256": "9614118b4e75e72e4fb65909fe95649efd89d00fb8435e99e5bebbec75bb1a31",
    }


def test_post_scan_processing_service_merges_meta_and_extracted_sections(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_android_binary_2026-07-03_23-34-29"
    apk_path = tmp_path / "APKPure.apk"
    (scan_dir / "opengrep_source").mkdir(parents=True)
    (scan_dir / "androguard").mkdir()
    (scan_dir / "aapt2").mkdir()
    (scan_dir / "apksigner").mkdir()
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
                    "sha1": "ec330db8c45c5cceb66797163779bf1d186aecaf",
                    "sha256": "22311a95d67057b82318e23b3efd7cc878e190b8dcd55ac2e7bb745343957474",
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
        scan_dir / "apksigner" / "signing_evidence.json",
        {
            "apk": {
                "file_name": "APKPure.apk",
                "sha256": "9614118b4e75e72e4fb65909fe95649efd89d00fb8435e99e5bebbec75bb1a31",
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
                        "sha256": "22311A95D67057B82318E23B3EFD7CC878E190B8DCD55AC2E7BB745343957474",
                        "signature_algorithm": "UNKNOWN",
                        "subject_dn": "CN=apkpure, OU=apkpure, O=apkpure",
                    }
                }
            ],
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
        "reviewer_org": "AppCritique Security Report",
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
        "md5": "d8db041096e5576650d5c1b0ac38bcca",
        "sha1": "dadc430a84587e51b2231daa1024ee0506806f96",
        "sha256": "cb4870807289f0ebb14bbfc941421b08f5766fa0346c1828bd5f09a955ccd560",
    }


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")

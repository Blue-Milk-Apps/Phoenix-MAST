import json
from pathlib import Path

from adapters.output.appcritiq_report.generate_report import load_report_data


BASE_DIR = Path(__file__).resolve().parents[2] / "adapters" / "output" / "appcritiq_report" / "data"
CANONICAL_NETWORK_CHECKS = [
    "Allows Cleartext Traffic for All Domains",
    "Contains HostnameVerifier That Accepts All Hostnames",
    "Contains X509TrustManager that Accepts All Certificates",
    "Does not Perform Certificate Pinning",
    "Opens a Listening Port",
    "Sensitive Cookies Lack Security Attributes",
    "Unnecessary Information Transmitted",
    "Sensitive Information is Unencrypted in Transit",
    "Password is not Hashed in Transit",
    "Weak Certificate Validation Enables MitM Attacks",
]
CANONICAL_STORAGE_CHECKS = [
    "Accesses External Storage",
    "Authentication Credentials Not Protected with Android Keystore",
    "Sensitive Information Stored in World Readable or Writable File in Internal Storage",
    "Sensitive Information Stored in External Storage",
    "Does not Prevent Screen Capture of Sensitive Information",
]


def _network_checks(path: Path) -> list[dict[str, str]]:
    report = load_report_data(json.loads(path.read_text(encoding="utf-8")))
    for section in report["vulnerability_sections"]:
        if section["section_name"] == "Network":
            return section["checks"]
    raise AssertionError("Network section missing")


def _check_map(checks: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    return {check["check"]: check for check in checks}


def _storage_checks(path: Path) -> list[dict[str, str]]:
    report = load_report_data(json.loads(path.read_text(encoding="utf-8")))
    for section in report["vulnerability_sections"]:
        if section["section_name"] == "Storage":
            return section["checks"]
    raise AssertionError("Storage section missing")


def test_load_report_data_preserves_legacy_network_checks_in_canonical_form() -> None:
    checks = _network_checks(BASE_DIR / "sample_insecurebankv2.json")

    assert [check["check"] for check in checks] == CANONICAL_NETWORK_CHECKS
    check_map = _check_map(checks)
    assert check_map["Allows Cleartext Traffic for All Domains"]["result"] == "Present"
    assert check_map["Does not Perform Certificate Pinning"]["result"] == "Present"
    assert check_map["Weak Certificate Validation Enables MitM Attacks"]["result"] == "Present"


def test_load_report_data_maps_newer_network_vocabulary_to_canonical_checks() -> None:
    checks = _network_checks(BASE_DIR / "sample_mirrcast.json")

    assert [check["check"] for check in checks] == CANONICAL_NETWORK_CHECKS
    check_map = _check_map(checks)
    assert check_map["Allows Cleartext Traffic for All Domains"]["result"] == "Present"
    assert check_map["Allows Cleartext Traffic for All Domains"]["evidence"] == "res/xml/network_security_config.xml"
    assert check_map["Weak Certificate Validation Enables MitM Attacks"]["result"] == "Present"
    assert check_map["Weak Certificate Validation Enables MitM Attacks"]["evidence"] == "res/xml/network_security_config.xml"


def test_load_report_data_derives_mitm_from_hostname_verifier() -> None:
    report = load_report_data(
        {
            "vulnerability_sections": [
                {
                    "section_name": "Network",
                    "findings_text": "",
                    "checks": [
                        {
                            "check": "Contains HostnameVerifier That Accepts All Hostnames",
                            "result": "Present",
                            "explanation": "A weak verifier was found.",
                            "compliance": "",
                            "remediation_link": "",
                            "evidence": "VerifierClass.java",
                            "severity": "High",
                        }
                    ],
                }
            ]
        }
    )

    for section in report["vulnerability_sections"]:
        if section["section_name"] != "Network":
            continue
        check_map = _check_map(section["checks"])
        assert check_map["Contains HostnameVerifier That Accepts All Hostnames"]["result"] == "Present"
        assert check_map["Weak Certificate Validation Enables MitM Attacks"]["result"] == "Present"
        assert check_map["Weak Certificate Validation Enables MitM Attacks"]["evidence"] == "VerifierClass.java"
        break
    else:
        raise AssertionError("Network section missing")


def test_load_report_data_uses_network_evidence_bundle_for_actual_checks() -> None:
    report = load_report_data(
        {
            "network_evidence": {
                "allows_cleartext_traffic_for_all_domains": {
                    "present": True,
                    "evidence": "AndroidManifest.xml",
                },
                "does_not_perform_certificate_pinning": {
                    "present": True,
                    "evidence": "res/xml/network_security_config.xml",
                },
                "weak_certificate_validation_enables_mitm": {
                    "present": True,
                    "evidence": "res/xml/network_security_config.xml",
                },
            }
        }
    )

    for section in report["vulnerability_sections"]:
        if section["section_name"] != "Network":
            continue
        check_map = _check_map(section["checks"])
        assert check_map["Allows Cleartext Traffic for All Domains"]["result"] == "Present"
        assert check_map["Allows Cleartext Traffic for All Domains"]["evidence"] == "AndroidManifest.xml"
        assert check_map["Does not Perform Certificate Pinning"]["result"] == "Present"
        assert check_map["Weak Certificate Validation Enables MitM Attacks"]["result"] == "Present"
        break
    else:
        raise AssertionError("Network section missing")


def test_load_report_data_keeps_network_defaults_when_no_supporting_evidence_exists() -> None:
    checks = _network_checks(BASE_DIR / "blank_template.json")

    assert [check["check"] for check in checks] == CANONICAL_NETWORK_CHECKS
    assert all(check["result"] == "Not Present" for check in checks)


def test_load_report_data_preserves_canonical_storage_checks() -> None:
    checks = _storage_checks(BASE_DIR / "sample_insecurebankv2.json")

    assert [check["check"] for check in checks] == CANONICAL_STORAGE_CHECKS
    check_map = _check_map(checks)
    assert check_map["Accesses External Storage"]["result"] == "Present"
    assert check_map["Sensitive Information Stored in External Storage"]["result"] == "Present"


def test_load_report_data_maps_legacy_storage_vocabulary_to_canonical_checks() -> None:
    checks = _storage_checks(BASE_DIR / "sample_mirrcast.json")

    assert [check["check"] for check in checks] == CANONICAL_STORAGE_CHECKS
    check_map = _check_map(checks)
    assert check_map["Accesses External Storage"]["result"] == "Present"


def test_load_report_data_uses_storage_evidence_bundle_for_actual_checks() -> None:
    report = load_report_data(
        {
            "storage_evidence": {
                "accesses_external_storage": {
                    "present": True,
                    "evidence": "android.permission.WRITE_EXTERNAL_STORAGE",
                },
                "authentication_credentials_not_protected_with_android_keystore": {
                    "present": True,
                    "evidence": "Lcom/example/LoginActivity; saveCreds (Ljava/lang/String;)V",
                },
            }
        }
    )

    for section in report["vulnerability_sections"]:
        if section["section_name"] != "Storage":
            continue
        check_map = _check_map(section["checks"])
        assert check_map["Accesses External Storage"]["result"] == "Present"
        assert check_map["Accesses External Storage"]["evidence"] == "android.permission.WRITE_EXTERNAL_STORAGE"
        assert check_map["Authentication Credentials Not Protected with Android Keystore"]["result"] == "Present"
        break
    else:
        raise AssertionError("Storage section missing")


def test_load_report_data_keeps_storage_defaults_when_no_supporting_evidence_exists() -> None:
    checks = _storage_checks(BASE_DIR / "blank_template.json")

    assert [check["check"] for check in checks] == CANONICAL_STORAGE_CHECKS
    assert all(check["result"] == "Not Present" for check in checks)


def test_load_report_data_orders_present_functionalities_before_absent_ones() -> None:
    report = load_report_data(
        {
            "functionality": {
                "Audio": {
                    "present": False,
                    "explanation": "No permission or scan evidence indicated audio functionality.",
                },
                "Camera": {
                    "present": True,
                    "explanation": "permission android.permission.CAMERA, which may indicate camera functionality.",
                },
                "Bluetooth": {
                    "present": False,
                    "explanation": "No permission or scan evidence indicated Bluetooth functionality.",
                },
                "Location": {
                    "present": True,
                    "explanation": "Location usage detected.",
                },
            }
        }
    )

    functionality_items = list(report["functionality"].items())
    assert {name for name, _details in functionality_items[:2]} == {"Camera", "Location"}
    assert all(details["present"] is False for _name, details in functionality_items[2:])
    assert report["functionality"]["Audio"]["explanation"] == (
        "No permission or scan evidence indicated audio functionality."
    )
    assert report["functionality"]["Contacts"]["explanation"] == (
        "No permission or scan evidence indicated Contacts functionality."
    )

import json
from pathlib import Path

from adapters.output.phoenix_report.generate_report import (
    _build_overall_evaluation,
    load_report_data,
    result_badge,
    risk_badge,
)

BASE_DIR = Path(__file__).resolve().parents[2] / "adapters" / "output" / "phoenix_report" / "data"
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
CANONICAL_DATA_STORAGE_CHECKS = [
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


def _render_report_html(data: dict) -> str:
    from jinja2 import Environment, FileSystemLoader

    environment = Environment(loader=FileSystemLoader(str(BASE_DIR.parent / "templates")))
    environment.globals["risk_badge"] = risk_badge
    environment.globals["result_badge"] = result_badge
    return environment.get_template("report.html.jinja").render(
        data=load_report_data(data),
        css="",
        charts={"overall_risk_polar": ""},
        app_icon_uri="",
        phoenix_brand_icon_uri="",
        show_confidence_caveats=False,
    )


def _data_storage_checks(path: Path) -> list[dict[str, str]]:
    report = load_report_data(json.loads(path.read_text(encoding="utf-8")))
    for section in report["vulnerability_sections"]:
        if section["section_name"] == "Data Storage":
            return section["checks"]
    raise AssertionError("Data Storage section missing")


def test_overall_evaluation_summarizes_only_the_highest_present_severity() -> None:
    section_to_area = {"network": ("Networking", "networking")}

    high_and_medium = _build_overall_evaluation(
        {
            "vulnerability_sections": [
                {
                    "section_name": "Network",
                    "checks": [
                        {"check": "High finding", "result": "Present", "severity": "High"},
                        {"check": "Medium finding", "result": "Present", "severity": "Medium"},
                        {"check": "Absent critical finding", "result": "Not Present", "severity": "Critical"},
                    ],
                }
            ]
        },
        section_to_area,
    )
    assert high_and_medium[0]["risk_rating"] == "High"
    assert high_and_medium[0]["summary_findings"] == ["High finding"]

    medium_and_low = _build_overall_evaluation(
        {
            "vulnerability_sections": [
                {
                    "section_name": "Network",
                    "checks": [
                        {"check": "First medium finding", "result": "Present", "severity": "Medium"},
                        {"check": "Second medium finding", "result": "Present", "severity": "Medium"},
                        {"check": "Low finding", "result": "Present", "severity": "Low"},
                    ],
                }
            ]
        },
        section_to_area,
    )
    assert medium_and_low[0]["risk_rating"] == "Medium"
    assert medium_and_low[0]["summary_findings"] == ["First medium finding", "Second medium finding"]

    no_present_findings = _build_overall_evaluation(
        {
            "vulnerability_sections": [
                {
                    "section_name": "Network",
                    "checks": [{"check": "Absent finding", "result": "Not Present", "severity": "High"}],
                }
            ]
        },
        section_to_area,
    )
    assert no_present_findings[0]["summary_findings"] == ["No findings identified in this scan"]


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
    assert (
        check_map["Weak Certificate Validation Enables MitM Attacks"]["evidence"]
        == "res/xml/network_security_config.xml"
    )


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


def test_load_report_data_preserves_canonical_data_storage_checks() -> None:
    checks = _data_storage_checks(BASE_DIR / "sample_insecurebankv2.json")

    assert [check["check"] for check in checks] == CANONICAL_DATA_STORAGE_CHECKS
    check_map = _check_map(checks)
    assert check_map["Accesses External Storage"]["result"] == "Present"
    assert check_map["Sensitive Information Stored in External Storage"]["result"] == "Present"


def test_load_report_data_maps_legacy_data_storage_vocabulary_to_canonical_checks() -> None:
    checks = _data_storage_checks(BASE_DIR / "sample_mirrcast.json")

    assert [check["check"] for check in checks] == CANONICAL_DATA_STORAGE_CHECKS
    check_map = _check_map(checks)
    assert check_map["Accesses External Storage"]["result"] == "Present"


def test_load_report_data_uses_data_storage_evidence_bundle_for_actual_checks() -> None:
    report = load_report_data(
        {
            "data_storage_evidence": {
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
        if section["section_name"] != "Data Storage":
            continue
        check_map = _check_map(section["checks"])
        assert check_map["Accesses External Storage"]["result"] == "Present"
        assert check_map["Accesses External Storage"]["evidence"] == "android.permission.WRITE_EXTERNAL_STORAGE"
        assert check_map["Authentication Credentials Not Protected with Android Keystore"]["result"] == "Present"
        break
    else:
        raise AssertionError("Data Storage section missing")


def test_load_report_data_keeps_data_storage_defaults_when_no_supporting_evidence_exists() -> None:
    checks = _data_storage_checks(BASE_DIR / "blank_template.json")

    assert [check["check"] for check in checks] == CANONICAL_DATA_STORAGE_CHECKS
    assert all(check["result"] == "Not Present" for check in checks)


def test_load_report_data_uses_data_storage_section_for_android_and_ios() -> None:
    for platform in ("Android", "iOS"):
        report = load_report_data({"meta": {"platform": platform}})

        section_names = [section["section_name"] for section in report["vulnerability_sections"]]
        assert "Data Storage" in section_names
        assert "Data" not in section_names
        assert "Storage" not in section_names
        assert report["risk_summary"]["data_storage"] == "Low"
        assert any(row["area_of_concern"] == "Data Storage" for row in report["overall_evaluation"])


def test_load_report_data_uses_ios_data_storage_evidence() -> None:
    evidence = {
        "deprecated_keychain_attributes": {
            "present": True,
            "evidence": "kSecAttrAccessibleAlways",
        }
    }

    report = load_report_data(
        {
            "meta": {"platform": "iOS"},
            "data_storage_evidence": evidence,
        }
    )
    data_storage_section = next(
        section for section in report["vulnerability_sections"] if section["section_name"] == "Data Storage"
    )
    check_map = _check_map(data_storage_section["checks"])
    deprecated_check = check_map["Application Utilizes Deprecated Keychain Attributes"]
    assert deprecated_check["result"] == "Present"
    assert deprecated_check["evidence"] == "kSecAttrAccessibleAlways"


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


def test_load_report_data_adds_display_permission_names() -> None:
    report = load_report_data(
        {
            "permissions": [
                {
                    "permission": "android.permission.ACCESS_COARSE_LOCATION",
                    "status": "dangerous",
                    "info": "dangerous",
                    "usage_description": "",
                    "general_description": "Allows the app to access approximate location.",
                },
                {
                    "permission": "com.example.app.permission.C2D_MESSAGE",
                    "status": "normal",
                    "info": "unknown or normal",
                    "usage_description": "",
                    "general_description": "Custom application permission.",
                },
            ]
        }
    )

    assert report["permissions"][0]["permission"] == "android.permission.ACCESS_COARSE_LOCATION"
    assert report["permissions"][0]["display_permission"] == "ACCESS_COARSE_LOCATION"
    assert report["permissions"][1]["permission"] == "com.example.app.permission.C2D_MESSAGE"
    assert report["permissions"][1]["display_permission"] == "com.example.app.permission.C2D_MESSAGE"


def test_load_report_data_limits_ios_source_reports_to_assessed_content() -> None:
    report = load_report_data(
        {
            "meta": {
                "app_display_name": "Example",
                "file_name": "Example",
                "platform": "iOS",
                "target_type": "SOURCE",
            },
            "code_evidence": {
                "uses_uiwebview": {
                    "present": True,
                    "evidence": "Sources/WebView.swift: UIWebView",
                }
            },
            "ipa_binary_evidence": {
                "arc": False,
                "pie": False,
                "stack canary": False,
            },
        }
    )

    assert report["report_scope"] == {
        "platform": "iOS",
        "target_type": "SOURCE",
        "assessment_label": "Source Code",
        "assessment_title": "Source Code Vulnerability Assessment",
        "target_label": "Project Name",
        "target_information_heading": "Source Project Information",
        "show_file_hashes": False,
        "show_ios_binary_analysis": False,
        "assessed_sections": ("code", "network", "data storage"),
    }
    assert [section["section_name"] for section in report["vulnerability_sections"]] == [
        "Code",
        "Network",
        "Data Storage",
    ]
    code_section = next(section for section in report["vulnerability_sections"] if section["section_name"] == "Code")
    check_map = _check_map(code_section["checks"])
    assert check_map["Deprecated API - UIWebView"]["result"] == "Present"
    assert "Missing ARC Binary Protections" not in check_map
    assert "Position-Independent Code (PIC) Not Enabled" not in check_map
    assert "Stack Canaries Not Enabled" not in check_map
    assert "Insecure API Usage in Binary" not in check_map
    assert "Usage of malloc Instead of calloc in Binary" not in check_map
    assert report["ipa_binary_protections"] == []
    assert set(report["risk_summary"]) == {"code_vulnerability", "data_storage", "networking"}


def test_report_template_switches_between_ios_source_and_binary_presentation() -> None:
    source_html = _render_report_html(
        {
            "meta": {
                "app_display_name": "Example",
                "file_name": "ExampleProject",
                "platform": "iOS",
                "target_type": "SOURCE",
            }
        }
    )
    assert "Source Code Vulnerability Assessment" in source_html
    assert "Source Project Information" in source_html
    assert "Project Name" in source_html
    assert "IPA Binary Code Analysis" not in source_html
    assert '<td class="k">MD5</td>' not in source_html
    assert "Custom URL Schemes" in source_html

    binary_html = _render_report_html(
        {
            "meta": {
                "app_display_name": "Example",
                "file_name": "Example.ipa",
                "platform": "iOS",
                "target_type": "BINARY",
            }
        }
    )
    assert "Application Vulnerability Assessment" in binary_html
    assert "File Information" in binary_html
    assert "IPA Binary Code Analysis" in binary_html
    assert '<td class="k">MD5</td>' in binary_html


def test_load_report_data_uses_imported_function_confidence_caveats_for_ios_arc_and_stack_canary() -> None:
    report = load_report_data(
        {
            "meta": {"platform": "iOS"},
            "ipa_binary_evidence": {
                "arc": True,
                "stack canary": True,
            },
            "vulnerability_sections": [
                {"section_name": "Code", "findings_text": "", "checks": []},
                {"section_name": "Network", "findings_text": "", "checks": []},
                {"section_name": "Data", "findings_text": "", "checks": []},
                {"section_name": "Resilience", "findings_text": "", "checks": []},
            ],
        }
    )

    code_section = next(section for section in report["vulnerability_sections"] if section["section_name"] == "Code")
    check_map = _check_map(code_section["checks"])

    assert report["report_scope"]["target_type"] == "BINARY"
    assert report["report_scope"]["show_ios_binary_analysis"] is True
    assert (
        check_map["Missing ARC Binary Protections"]["confidence_caveat"]
        == "Inferred from Mach-O imported-function presence (_objc_release/_swift_release), not a direct "
        "compiler flag; absence is less reliable if imports are stripped or unavailable."
    )
    assert (
        check_map["Stack Canaries Not Enabled"]["confidence_caveat"]
        == "Inferred from Mach-O imported-function presence (___stack_chk_fail and ___stack_chk_guard); "
        "absence is less reliable if imports are stripped or unavailable."
    )

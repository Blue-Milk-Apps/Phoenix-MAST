from __future__ import annotations

import json
import plistlib
from pathlib import Path

from adapters.output import FileScanOutput
from adapters.source_code_scanners.plist_source_scanner import PlistSourceScanner
from domain.models import ScanConfig, ScanType


def test_plist_metadata() -> None:
    scanner = PlistSourceScanner()

    assert scanner.scan_type is ScanType.PLIST_SOURCE
    assert scanner.name == "Plist Source Saver"
    assert "plist" in scanner.description.lower()


def test_plist_scan_writes_app_plist_and_index(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    project_path.mkdir()
    nested_dir = project_path / "ios"
    nested_dir.mkdir()

    source_plist = nested_dir / "Info.plist"
    with source_plist.open("wb") as handle:
        plistlib.dump(
            {
                "CFBundleIdentifier": "com.example.app",
                "CFBundleName": "ExampleApp",
            },
            handle,
            fmt=plistlib.FMT_BINARY,
        )

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="source",
    )

    results = PlistSourceScanner().scan(config)

    assert len(results) == 2
    plist_result = next(result for result in results if result.relative_target_path == "ios/Info.json")
    index_result = next(result for result in results if result.relative_target_path == "scan_index.json")
    assert plist_result.success
    plist_report = json.loads(plist_result.raw_output)
    assert set(plist_report) == {
        "app_meta",
        "ats",
        "background_modes",
        "entitlements",
        "other_important_items",
        "plist",
        "privacy",
        "url_schemes",
    }
    assert plist_report["app_meta"]["bundle_identifier"] == "com.example.app"
    assert plist_report["app_meta"]["bundle_name"] == "ExampleApp"
    assert plist_report["plist"]["CFBundleIdentifier"] == "com.example.app"
    index = json.loads(index_result.raw_output)
    assert index["plist_count"] == 1
    assert index["emitted_plist_count"] == 1
    assert index["plists"][0]["output_path"] == "ios/Info.json"
    assert index["plists"][0]["role"] == "app"

    for result in results:
        FileScanOutput(config.output_path).write_result(result)
    output_file = config.output_path / "plist_source" / "ios" / "Info.json"
    assert output_file.exists()
    index_file = config.output_path / "plist_source" / "scan_index.json"
    assert index_file.exists()


def test_plist_scan_groups_app_and_framework_bundles(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    app_dir = project_path / "App"
    framework_dir = project_path / "Frameworks" / "Foo.framework"
    app_dir.mkdir(parents=True)
    framework_dir.mkdir(parents=True)

    with (app_dir / "Info.plist").open("wb") as handle:
        plistlib.dump(
            {
                "CFBundleIdentifier": "com.example.app",
                "CFBundleName": "ExampleApp",
                "CFBundlePackageType": "APPL",
                "CFBundleShortVersionString": "1.0",
                "CFBundleVersion": "7",
                "CFBundleURLTypes": [
                    {"CFBundleURLSchemes": ["example"]},
                ],
                "NSAppTransportSecurity": {
                    "NSAllowsArbitraryLoads": True,
                    "NSExceptionDomains": {
                        "api.example.com": {
                            "NSExceptionAllowsInsecureHTTPLoads": True,
                            "NSExceptionMinimumTLSVersion": "TLSv1.1",
                            "NSExceptionRequiresForwardSecrecy": False,
                        },
                        "third-party.example.com": {
                            "NSThirdPartyExceptionMinimumTLSVersion": "TLSv1.0",
                            "NSThirdPartyExceptionRequiresForwardSecrecy": False,
                        },
                    },
                },
                "NSCameraUsageDescription": "Scan codes",
            },
            handle,
            fmt=plistlib.FMT_BINARY,
        )
    with (framework_dir / "Info.plist").open("wb") as handle:
        plistlib.dump(
            {
                "CFBundleIdentifier": "com.example.foo",
                "CFBundleName": "Foo",
                "CFBundlePackageType": "FMWK",
                "CFBundleShortVersionString": "2.0",
                "CFBundleVersion": "11",
                "MinimumOSVersion": "15.0",
            },
            handle,
            fmt=plistlib.FMT_BINARY,
        )

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="source",
    )

    results = PlistSourceScanner().scan(config)

    outputs = {result.relative_target_path: json.loads(result.raw_output) for result in results}
    assert set(outputs) == {
        "App/Info.json",
        "Frameworks/Foo.framework/Info.json",
        "scan_index.json",
    }
    assert outputs["App/Info.json"]["app_meta"]["bundle_identifier"] == "com.example.app"
    assert outputs["App/Info.json"]["ats"]["allows_arbitrary_loads"] is True
    assert outputs["App/Info.json"]["ats"]["exception_domains"] == [
        {
            "allows_insecure_http_loads": True,
            "domain": "api.example.com",
            "minimum_tls_version": "TLSv1.1",
            "requires_forward_secrecy": False,
        },
        {
            "allows_insecure_http_loads": False,
            "domain": "third-party.example.com",
            "minimum_tls_version": "TLSv1.0",
            "requires_forward_secrecy": False,
        },
    ]
    assert outputs["App/Info.json"]["privacy"]["permissions"] == [
        {"key": "NSCameraUsageDescription", "purpose": "Scan codes"}
    ]
    assert outputs["App/Info.json"]["plist"]["NSAppTransportSecurity"] == {
        "NSAllowsArbitraryLoads": True,
        "NSExceptionDomains": {
            "api.example.com": {
                "NSExceptionAllowsInsecureHTTPLoads": True,
                "NSExceptionMinimumTLSVersion": "TLSv1.1",
                "NSExceptionRequiresForwardSecrecy": False,
            },
            "third-party.example.com": {
                "NSThirdPartyExceptionMinimumTLSVersion": "TLSv1.0",
                "NSThirdPartyExceptionRequiresForwardSecrecy": False,
            },
        },
    }
    assert outputs["Frameworks/Foo.framework/Info.json"]["framework_meta"]["bundle_identifier"] == ("com.example.foo")
    assert outputs["Frameworks/Foo.framework/Info.json"]["framework_meta"]["package_type"] == "FMWK"
    assert outputs["scan_index.json"]["emitted_plist_count"] == 2
    assert [item["role"] for item in outputs["scan_index.json"]["plists"]] == [
        "app",
        "framework",
    ]


def test_plist_scan_skips_xcode_project_plists(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    app_dir = project_path / "App"
    xcode_dir = project_path / "App.xcodeproj" / "xcuserdata" / "user.xcuserdatad"
    app_dir.mkdir(parents=True)
    xcode_dir.mkdir(parents=True)

    with (app_dir / "Info.plist").open("wb") as handle:
        plistlib.dump(
            {
                "CFBundleIdentifier": "com.example.app",
                "CFBundleName": "ExampleApp",
                "CFBundlePackageType": "APPL",
            },
            handle,
            fmt=plistlib.FMT_BINARY,
        )
    with (xcode_dir / "xcschememanagement.plist").open("wb") as handle:
        plistlib.dump({"SchemeUserState": {}}, handle, fmt=plistlib.FMT_BINARY)

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="source",
    )

    results = PlistSourceScanner().scan(config)

    outputs = {result.relative_target_path: json.loads(result.raw_output) for result in results}
    assert set(outputs) == {"App/Info.json", "scan_index.json"}
    assert outputs["scan_index.json"]["plist_count"] == 2
    assert outputs["scan_index.json"]["skipped_plist_count"] == 1


def test_plist_scan_can_write_xml(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    project_path.mkdir()
    plist_path = project_path / "Info.plist"
    with plist_path.open("wb") as handle:
        plistlib.dump({"Name": "ExampleApp"}, handle, fmt=plistlib.FMT_BINARY)

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="source",
    )

    results = PlistSourceScanner(output_format="xml").scan(config)

    assert len(results) == 1
    assert results[0].success
    assert results[0].relative_target_path == "Info.xml"
    assert results[0].raw_output.startswith("<?xml")

    for result in results:
        FileScanOutput(config.output_path).write_result(result)
    output_file = config.output_path / "plist_source" / "Info.xml"
    assert output_file.exists()


def test_plist_scan_reports_sensitive_keys_without_copying_plist(
    tmp_path: Path,
) -> None:
    project_path = tmp_path / "project"
    project_path.mkdir()
    plist_path = project_path / "Info.plist"
    with plist_path.open("wb") as handle:
        plistlib.dump({"APIToken": b"\x01\x02"}, handle, fmt=plistlib.FMT_BINARY)

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="source",
    )

    results = PlistSourceScanner().scan(config)

    assert len(results) == 2
    plist_result = next(result for result in results if result.relative_target_path == "Info.json")
    report = json.loads(plist_result.raw_output)
    assert report["important_items"]["ats"] == {}
    assert report["plist"]["APIToken"] == "0102"


def test_plist_scan_skips_when_no_plists_found(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    project_path.mkdir()

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="source",
    )

    results = PlistSourceScanner().scan(config)

    assert len(results) == 1
    assert results[0].skipped
    assert "No plist files" in results[0].error_message


def test_plist_scan_works_with_temporary_project_fixture(tmp_path: Path) -> None:
    project_path = tmp_path / "plist_example"
    project_path.mkdir()
    with (project_path / "Info.plist").open("wb") as handle:
        plistlib.dump(
            {
                "CFBundleIdentifier": "com.example.fixture",
                "CFBundleName": "FixtureApp",
                "CFBundlePackageType": "APPL",
            },
            handle,
            fmt=plistlib.FMT_BINARY,
        )

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="source",
    )

    results = PlistSourceScanner().scan(config)

    assert len(results) == 2
    plist_result = next(result for result in results if result.relative_target_path == "Info.json")
    assert plist_result.success
    index_result = next(result for result in results if result.relative_target_path == "scan_index.json")
    assert json.loads(index_result.raw_output)["plist_count"] == 1

    for result in results:
        FileScanOutput(config.output_path).write_result(result)
    output_file = config.output_path / "plist_source" / "Info.json"
    assert output_file.exists()

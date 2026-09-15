from __future__ import annotations

import json
import plistlib
import zipfile
from pathlib import Path

from adapters.binary_scanners.plist_binary_scanner import PlistBinaryScanner
from adapters.output import FileScanOutput
from domain.models import ScanConfig, ScanType


def test_plist_binary_metadata() -> None:
    scanner = PlistBinaryScanner()

    assert scanner.scan_type is ScanType.PLIST_BINARY
    assert scanner.name == "Plist Binary Saver"
    assert "plist" in scanner.description.lower()


def test_plist_binary_scan_writes_normalized_plists(tmp_path: Path) -> None:
    project_path = tmp_path / "project.ipa"
    app_bundle_name = "Test.app"

    with zipfile.ZipFile(project_path, "w") as archive:
        archive.writestr(
            f"Payload/{app_bundle_name}/Info.plist",
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "com.example.app",
                    "CFBundleName": "ExampleApp",
                    "CFBundleExecutable": "Test",
                },
                fmt=plistlib.FMT_BINARY,
            ),
        )
        archive.writestr(f"Payload/{app_bundle_name}/Test", b"stub-binary")
        archive.writestr(
            f"Payload/{app_bundle_name}/Frameworks/Foo.framework/Info.plist",
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "com.example.foo",
                },
                fmt=plistlib.FMT_BINARY,
            ),
        )

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="binary",
    )

    results = PlistBinaryScanner().scan(config)

    assert len(results) == 3
    assert all(result.success for result in results)
    outputs = {
        result.relative_target_path: json.loads(result.raw_output) for result in results
    }
    assert outputs["Info.json"]["app_meta"]["bundle_identifier"] == "com.example.app"
    assert outputs["Info.json"]["app_meta"]["executable"] == "Test"
    assert outputs["Info.json"]["plist"]["CFBundleName"] == "ExampleApp"
    assert outputs["Frameworks/Foo.framework/Info.json"]["framework_meta"][
        "bundle_identifier"
    ] == ("com.example.foo")
    assert outputs["Frameworks/Foo.framework/Info.json"]["plist"][
        "CFBundleIdentifier"
    ] == ("com.example.foo")
    assert outputs["scan_index.json"]["emitted_plist_count"] == 2
    assert {item["role"] for item in outputs["scan_index.json"]["plists"]} == {
        "app",
        "framework",
    }

    for result in results:
        FileScanOutput(config.output_path).write_result(result)
    output_root = config.output_path / "plist_binary"
    main_output = output_root / "Info.json"
    framework_output = output_root / "Frameworks" / "Foo.framework" / "Info.json"
    index_output = output_root / "scan_index.json"
    assert main_output.exists()
    assert framework_output.exists()
    assert index_output.exists()


def test_plist_binary_scan_can_write_xml(tmp_path: Path) -> None:
    project_path = tmp_path / "project.ipa"
    app_bundle_name = "Test.app"

    with zipfile.ZipFile(project_path, "w") as archive:
        archive.writestr(
            f"Payload/{app_bundle_name}/Info.plist",
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "com.example.app",
                    "CFBundleExecutable": "Test",
                },
                fmt=plistlib.FMT_BINARY,
            ),
        )
        archive.writestr(f"Payload/{app_bundle_name}/Test", b"stub-binary")

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="binary",
    )

    results = PlistBinaryScanner(output_format="xml").scan(config)

    assert len(results) == 1
    assert results[0].success
    assert results[0].relative_target_path == "Info.xml"
    assert results[0].raw_output.startswith("<?xml")

    for result in results:
        FileScanOutput(config.output_path).write_result(result)
    output_file = config.output_path / "plist_binary" / "Info.xml"
    assert output_file.exists()


def test_plist_binary_scan_json_safe_stringifies_unknown_types(tmp_path: Path) -> None:
    project_path = tmp_path / "project.ipa"
    app_bundle_name = "Test.app"

    with zipfile.ZipFile(project_path, "w") as archive:
        archive.writestr(
            f"Payload/{app_bundle_name}/Info.plist",
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "com.example.app",
                    "CFBundleExecutable": "Test",
                    "Payload": b"\x01\x02",
                },
                fmt=plistlib.FMT_BINARY,
            ),
        )
        archive.writestr(f"Payload/{app_bundle_name}/Test", b"stub-binary")

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="binary",
    )

    results = PlistBinaryScanner().scan(config)

    assert len(results) == 2
    plist_result = next(
        result for result in results if result.relative_target_path == "Info.json"
    )
    assert json.loads(plist_result.raw_output)["plist"]["Payload"] == "0102"


def test_plist_binary_scan_skips_when_no_ipa_found(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    project_path.mkdir()

    config = ScanConfig(
        project_path=project_path,
        output_path=tmp_path / "scan-results",
        mode="binary",
    )

    results = PlistBinaryScanner().scan(config)

    assert len(results) == 1
    assert results[0].skipped
    assert "No IPA files" in results[0].error_message

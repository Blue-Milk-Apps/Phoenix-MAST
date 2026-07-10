from __future__ import annotations

import json
import plistlib
import subprocess
import zipfile
from pathlib import Path

from adapters.binary_scanners.ipsw_scanner import IpswScanner
from domain.models import ScanConfig, ScanType


def test_ipsw_metadata() -> None:
    scanner = IpswScanner()

    assert scanner.scan_type is ScanType.IPSW
    assert scanner.name == "ipsw Mach-O Analyzer"
    assert "ipa" in scanner.description.lower()


def test_ipsw_is_available_checks_path(monkeypatch) -> None:
    monkeypatch.setattr(
        "adapters.binary_scanners.ipsw_scanner.shutil.which",
        lambda command: "/usr/local/bin/ipsw" if command == "ipsw" else None,
    )

    assert IpswScanner().is_available()

    monkeypatch.setattr(
        "adapters.binary_scanners.ipsw_scanner.shutil.which",
        lambda command: None,
    )

    assert not IpswScanner().is_available()


def test_ipsw_scan_requires_ipa(tmp_path: Path) -> None:
    target = tmp_path / "sample.apk"
    target.write_bytes(b"fake-apk")
    config = ScanConfig(
        project_path=target,
        output_path=tmp_path / "scan-results",
        mode="binary",
    )

    results = IpswScanner().scan(config)

    assert len(results) == 1
    assert results[0].skipped
    assert "IPA files" in results[0].error_message


def test_ipsw_scan_returns_raw_command_outputs(monkeypatch, tmp_path: Path) -> None:
    ipa_path = tmp_path / "sample.ipa"
    with zipfile.ZipFile(ipa_path, "w") as archive:
        archive.writestr(
            "Payload/Test.app/Info.plist",
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "com.example.test",
                    "CFBundleName": "TestApp",
                    "CFBundleExecutable": "TestApp",
                    "CFBundleShortVersionString": "1.2.3",
                    "CFBundleVersion": "123",
                    "MinimumOSVersion": "15.0",
                }
            ),
        )
        archive.writestr("Payload/Test.app/TestApp", b"fake-binary")
        archive.writestr("Payload/Test.app/Frameworks/Foo.framework/Foo", b"fake")

    monkeypatch.setattr(
        "adapters.binary_scanners.ipsw_scanner.shutil.which",
        lambda command: "/usr/local/bin/ipsw" if command == "ipsw" else None,
    )
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["check"] is False

        if argv == ["/usr/local/bin/ipsw", "version"]:
            return subprocess.CompletedProcess(argv, 0, "ipsw version 3.1.687\n", "")

        binary_name = Path(argv[3]).name
        if argv[-1] == "--json":
            stdout = json.dumps({"header": {"type": "EXECUTE"}, "binary": binary_name})
        elif argv[-1] == "--sig":
            stdout = f"Identifier=com.example.{binary_name}\nTeamIdentifier=ABCDE12345\n"
        elif argv[-1] == "--ent":
            stdout = plistlib.dumps(
                {
                    "application-identifier": binary_name,
                    "com.apple.developer.team-identifier": "ABCDE12345",  # pragma: allowlist secret
                }
            ).decode("utf-8")
        else:
            raise AssertionError(f"Unexpected command: {argv}")

        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr(
        "adapters.binary_scanners.ipsw_scanner.subprocess.run",
        fake_run,
    )

    config = ScanConfig(
        project_path=ipa_path,
        output_path=tmp_path / "scan-results",
        mode="binary",
    )

    results = IpswScanner().scan(config)

    assert len(results) == 2
    assert all(result.success for result in results)
    assert not (config.output_path / "ipsw").exists()
    assert [result.relative_target_path for result in results] == [
        "TestApp.json",
        "Frameworks/Foo.framework/Foo.json",
    ]

    outputs = {result.relative_target_path: json.loads(result.raw_output) for result in results}
    app_output = outputs["TestApp.json"]
    framework_output = outputs["Frameworks/Foo.framework/Foo.json"]

    assert app_output["app_info"]["bundle_id"] == "com.example.test"
    assert app_output["binary"] == {
        "kind": "main",
        "name": "TestApp",
        "path": "TestApp",
    }
    assert framework_output["binary"] == {
        "kind": "framework",
        "name": "Foo",
        "path": "Frameworks/Foo.framework/Foo",
    }
    assert app_output["scan_metadata"]["ipsw_version"] == "ipsw version 3.1.687"
    assert app_output["scan_metadata"]["execution_status"] == "SUCCESS"
    assert [command["purpose"] for command in app_output["commands"]] == [
        "macho_info_json",
        "code_signature",
        "entitlements",
    ]
    assert "stdout" not in app_output["commands"][0]
    assert "stderr" not in app_output["commands"][0]
    assert app_output["commands"][0]["argv"] == [
        "ipsw",
        "macho",
        "info",
        "<binary>",
        "--json",
    ]
    assert app_output["analysis"]["macho"]["header"] == {"type": "EXECUTE"}
    assert app_output["analysis"]["code_signature"] == {
        "present": True,
        "team_identifier": "ABCDE12345",  # pragma: allowlist secret
        "signing_identifier": "com.example.TestApp",
        "cdhashes": [],
        "authorities": [],
        "line_count": 2,
        "raw_output_omitted": True,
    }
    assert app_output["analysis"]["entitlements"]["keys"] == [
        "application-identifier",
        "com.apple.developer.team-identifier",
    ]
    assert app_output["analysis"]["entitlements"]["values"] == {
        "application-identifier": "TestApp",
        "com.apple.developer.team-identifier": "ABCDE12345",  # pragma: allowlist secret
    }
    assert len(calls) == 7

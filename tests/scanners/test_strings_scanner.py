import zipfile
from pathlib import Path

from adapters.source_code_scanners import strings_scanner
from adapters.source_code_scanners.strings_scanner import StringsScanner
from domain.models import ScanConfig, ScanType


def test_strings_metadata() -> None:
    scanner = StringsScanner()

    assert scanner.scan_type is ScanType.STRINGS
    assert scanner.name == "Strings Extractor"
    assert "strings" in scanner.description.lower()


def test_strings_availability(monkeypatch) -> None:
    monkeypatch.setattr(strings_scanner.shutil, "which", lambda _: "/usr/bin/strings")

    assert StringsScanner().is_available()


def test_strings_scan_returns_raw_output(monkeypatch, tmp_path: Path) -> None:
    source_file = tmp_path / "sample.bin"
    source_file.write_bytes(b"fake-binary")
    config = ScanConfig(
        project_path=source_file,
        output_path=tmp_path / "scan-results",
        mode="binary",
        enabled_scans=[ScanType.STRINGS],
    )

    monkeypatch.setattr(strings_scanner.shutil, "which", lambda _: "/usr/bin/strings")

    def fake_run(cmd, capture_output, text, check):
        class FakeResult:
            returncode = 0
            stdout = "HELLO_WORLD\nSECRET_TOKEN\n"
            stderr = ""

        assert cmd[-1] == str(source_file)
        return FakeResult()

    monkeypatch.setattr(strings_scanner.subprocess, "run", fake_run)

    results = StringsScanner().scan(config)

    assert len(results) == 1
    assert results[0].success
    assert results[0].raw_output.splitlines() == [
        "HELLO_WORLD",
        "SECRET_TOKEN",
    ]
    assert results[0].relative_target_path == "sample.txt"


def test_strings_scan_for_apk_returns_raw_output_for_multiple_targets(
    monkeypatch, tmp_path: Path
) -> None:
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"manifest")
        zf.writestr("classes.dex", b"dex")
        zf.writestr("classes2.dex", b"dex2")
        zf.writestr("resources.arsc", b"resources")
        zf.writestr("assets/config.json", b'{"key": "value"}')
        zf.writestr("lib/arm64-v8a/libfoo.so", b"libfoo")

    config = ScanConfig(
        project_path=apk_path,
        output_path=tmp_path / "scan-results",
        mode="binary",
        enabled_scans=[ScanType.STRINGS],
    )

    monkeypatch.setattr(strings_scanner.shutil, "which", lambda _: "/usr/bin/strings")

    outputs = {
        "AndroidManifest.xml": "MANIFEST_STRING\n",
        "classes.dex": "DEX_STRING\n",
        "classes2.dex": "DEX2_STRING\n",
        "resources.arsc": "RES_STRING\n",
        "assets/config.json": "ASSET_STRING\n",
        "lib/arm64-v8a/libfoo.so": "LIB_STRING\n",
    }

    def fake_run(cmd, capture_output, text, check):
        class FakeResult:
            returncode = 0
            stderr = ""

            def __init__(self, stdout: str):
                self.stdout = stdout

        target = Path(cmd[-1]).as_posix()
        for key, value in outputs.items():
            if target.endswith(key):
                return FakeResult(value)
        raise AssertionError(f"unexpected target {target}")

    monkeypatch.setattr(strings_scanner.subprocess, "run", fake_run)

    results = StringsScanner().scan(config)

    assert len(results) == 6
    assert all(result.success for result in results)
    outputs_by_path = {
        result.relative_target_path: result.raw_output for result in results
    }
    assert outputs_by_path == {
        "AndroidManifest.txt": "MANIFEST_STRING",
        "assets/config.txt": "ASSET_STRING",
        "classes.txt": "DEX_STRING",
        "classes2.txt": "DEX2_STRING",
        "lib/arm64-v8a/libfoo.txt": "LIB_STRING",
        "resources.txt": "RES_STRING",
    }


def test_strings_scan_for_ipa_paths_are_relative_to_app_bundle(
    monkeypatch, tmp_path: Path
) -> None:
    ipa_path = tmp_path / "sample.ipa"
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr(
            "Payload/Test.app/Info.plist",
            (
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
                b'<plist version="1.0"><dict>'
                b"<key>CFBundleExecutable</key><string>TestApp</string>"
                b"</dict></plist>"
            ),
        )
        zf.writestr("Payload/Test.app/TestApp", b"fake-binary")
        zf.writestr("Payload/Test.app/Frameworks/Foo.framework/Foo", b"fake-framework")

    config = ScanConfig(
        project_path=ipa_path,
        output_path=tmp_path / "scan-results",
        mode="binary",
        enabled_scans=[ScanType.STRINGS],
    )

    monkeypatch.setattr(strings_scanner.shutil, "which", lambda _: "/usr/bin/strings")

    outputs = {
        "TestApp": "APP_STRING\n",
        "Frameworks/Foo.framework/Foo": "FRAMEWORK_STRING\n",
    }

    def fake_run(cmd, capture_output, text, check):
        class FakeResult:
            returncode = 0
            stderr = ""

            def __init__(self, stdout: str):
                self.stdout = stdout

        target = Path(cmd[-1]).as_posix()
        for key, value in outputs.items():
            if target.endswith(key):
                return FakeResult(value)
        raise AssertionError(f"unexpected target {target}")

    monkeypatch.setattr(strings_scanner.subprocess, "run", fake_run)

    results = StringsScanner().scan(config)

    assert {result.relative_target_path: result.raw_output for result in results} == {
        "TestApp.txt": "APP_STRING",
        "Frameworks/Foo.framework/Foo.txt": "FRAMEWORK_STRING",
    }

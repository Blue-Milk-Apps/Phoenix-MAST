from __future__ import annotations

import json
import plistlib
import types
import zipfile
from enum import Enum
from pathlib import Path

from adapters.scanners.ios.lief_scanner import LIEFScanner
from domain.models import ScanConfig, ScanType


def test_lief_metadata() -> None:
    scanner = LIEFScanner()

    assert scanner.scan_type is ScanType.LIEF
    assert scanner.name == "LIEF Binary Analyzer"
    assert "ipa" in scanner.description.lower()


def test_lief_scan_requires_ipa(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "sample.apk"
    target.write_bytes(b"fake-apk")
    config = ScanConfig(
        project_path=target,
        output_path=tmp_path / "scan-results",
        mode="binary",
    )

    results = LIEFScanner().scan(config)

    assert len(results) == 1
    assert results[0].skipped
    assert "IPA files" in results[0].error_message


def test_lief_scan_returns_raw_output(monkeypatch, tmp_path: Path) -> None:
    ipa_path = tmp_path / "sample.ipa"
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr(
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
        zf.writestr("Payload/Test.app/TestApp", b"fake-binary")
        zf.writestr("Payload/Test.app/Frameworks/Foo.framework/Foo", b"fake-framework")

    config = ScanConfig(
        project_path=ipa_path,
        output_path=tmp_path / "scan-results",
        mode="binary",
    )

    class FakeSection:
        def __init__(self, name: str, size: int) -> None:
            self.name = name
            self.size = size

    class FakeSegment:
        def __init__(self, name: str, sections: list[FakeSection]) -> None:
            self.name = name
            self.sections = sections

    class FakeHeader:
        class CpuType(Enum):
            ARM64 = "ARM64"
            ARM64E = "ARM64E"

        class FileType(Enum):
            EXECUTE = "EXECUTE"
            DYLIB = "DYLIB"

        def __init__(self, cpu_type: CpuType, file_type: FileType, flags: list[str]) -> None:
            self.cpu_type = cpu_type
            self.file_type = file_type
            self.flags_list = flags

    def make_macho(
        cpu_type: FakeHeader.CpuType,
        file_type: FakeHeader.FileType,
        library_name: str,
        imported_functions: list[str],
    ) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            header=FakeHeader(cpu_type, file_type, ["PIE", "NO_HEAP_EXECUTION"]),
            has_nx=True,
            has_nx_heap=True,
            has_nx_stack=True,
            has_rpath=False,
            imported_functions=imported_functions,
            libraries=[types.SimpleNamespace(name=library_name)],
            segments=[
                FakeSegment(
                    "__TEXT",
                    [FakeSection("__cstring", 42), FakeSection("__swift5_types", 12)],
                )
            ],
        )

    class FakeBinary:
        def __init__(self, machos: list[types.SimpleNamespace]) -> None:
            self._machos = machos

        def __len__(self) -> int:
            return len(self._machos)

        def at(self, index: int) -> types.SimpleNamespace:
            return self._machos[index]

    def fake_parse(path: str) -> FakeBinary:
        if path.endswith("TestApp"):
            return FakeBinary(
                [
                    make_macho(
                        FakeHeader.CpuType.ARM64,
                        FakeHeader.FileType.EXECUTE,
                        "libSystem.B.dylib",
                        ["___stack_chk_fail", "___stack_chk_guard", "_objc_release"],
                    ),
                    make_macho(
                        FakeHeader.CpuType.ARM64E,
                        FakeHeader.FileType.EXECUTE,
                        "libobjc.A.dylib",
                        ["_swift_release"],
                    ),
                ]
            )
        return FakeBinary(
            [
                make_macho(
                    FakeHeader.CpuType.ARM64,
                    FakeHeader.FileType.DYLIB,
                    "Foo.framework/Foo",
                    ["_objc_release"],
                ),
            ]
        )

    fake_lief = types.SimpleNamespace(MachO=types.SimpleNamespace(parse=fake_parse))
    monkeypatch.setattr("adapters.scanners.ios.lief_scanner.lief", fake_lief)

    results = LIEFScanner().scan(config)

    assert len(results) == 2
    assert all(result.success for result in results)
    assert not (config.output_path / "lief").exists()

    results_by_path = {result.relative_target_path: json.loads(result.raw_output) for result in results}
    assert set(results_by_path) == {
        "TestApp.json",
        "Frameworks/Foo.framework/Foo.json",
    }

    app_contents = results_by_path["TestApp.json"]
    framework_contents = results_by_path["Frameworks/Foo.framework/Foo.json"]

    assert app_contents["target"].endswith("TestApp")
    assert app_contents["app_info"]["bundle_id"] == "com.example.test"
    assert framework_contents["app_info"]["bundle_id"] == "com.example.test"

    main_binary = app_contents["binary"]
    framework_binary = framework_contents["binary"]

    assert main_binary["kind"] == "main"
    assert main_binary["path"] == "TestApp"
    assert len(main_binary["slices"]) == 2
    assert main_binary["slices"][0]["architecture"] == "ARM64"
    assert main_binary["slices"][0]["file_type"] == "EXECUTE"
    assert main_binary["slices"][0]["has_nx"] is True
    assert main_binary["slices"][0]["has_nx_heap"] is True
    assert main_binary["slices"][0]["has_nx_stack"] is True
    assert main_binary["slices"][0]["has_rpath"] is False
    assert main_binary["slices"][0]["imported_functions"] == [
        "___stack_chk_fail",
        "___stack_chk_guard",
        "_objc_release",
    ]
    assert "libSystem.B.dylib" in main_binary["slices"][0]["libraries"]

    assert framework_binary["kind"] == "framework"
    assert framework_binary["path"] == "Frameworks/Foo.framework/Foo"
    assert len(framework_binary["slices"]) == 1
    assert framework_binary["slices"][0]["file_type"] == "DYLIB"
    assert "Foo.framework/Foo" in framework_binary["slices"][0]["libraries"]

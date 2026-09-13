from pathlib import Path

from adapters.scanners.ios.plist_source_scanner import PlistSourceScanner


def test_xcode_build_variables_ignore_section_comments(tmp_path: Path) -> None:
    project = tmp_path / "Example.xcodeproj"
    project.mkdir()
    (project / "project.pbxproj").write_text(
        "/* Begin PBXNativeTarget section */\n123 /* ExampleApp */ = { isa = PBXNativeTarget; };\n",
        encoding="utf-8",
    )

    variables = PlistSourceScanner()._xcode_build_variables(tmp_path)

    assert variables["TARGET_NAME"] == "ExampleApp"

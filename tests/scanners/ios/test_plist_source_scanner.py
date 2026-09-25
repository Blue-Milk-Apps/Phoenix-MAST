import base64
import io
import json
import plistlib
import shutil
from pathlib import Path

from PIL import Image

from adapters.output import FileScanOutput
from adapters.output.phoenix_report.builders.ios import NativeIOSReportDataBuilder
from adapters.output.phoenix_report.pdf_report import PdfReportGenerator
from adapters.output.phoenix_report.pdf_report.common import get_app_icon_data_uri
from adapters.post_scan.ios.native.scan_detail_extractor import NativeIOSScanDetailExtractor
from adapters.post_scan.ios.native.scan_output_loader import NativeIOSScanOutputLoader
from adapters.scanners.ios.plist_source_scanner import PlistSourceScanner
from application.report_generation_service import ReportGenerationService
from domain.models import ScanConfig


def test_xcode_build_variables_ignore_section_comments(tmp_path: Path) -> None:
    project = tmp_path / "Example.xcodeproj"
    project.mkdir()
    (project / "project.pbxproj").write_text(
        "/* Begin PBXNativeTarget section */\n123 /* ExampleApp */ = { isa = PBXNativeTarget; };\n",
        encoding="utf-8",
    )

    variables = PlistSourceScanner()._xcode_build_variables(tmp_path)

    assert variables["TARGET_NAME"] == "ExampleApp"


def test_app_icon_survives_source_cleanup_through_report_pipeline(tmp_path: Path) -> None:
    project = tmp_path / "ExampleApp"
    project.mkdir()
    (project / "Info.plist").write_bytes(
        plistlib.dumps({"CFBundleName": "ExampleApp", "CFBundleIdentifier": "com.example.app"})
    )
    xcode = project / "ExampleApp.xcodeproj"
    xcode.mkdir()
    (xcode / "project.pbxproj").write_text("ASSETCATALOG_COMPILER_APPICON_NAME = Brand;\n")
    catalog = project / "Assets.xcassets" / "Brand.appiconset"
    catalog.mkdir(parents=True)
    Image.new("RGB", (64, 64), "red").save(catalog / "default.png")
    Image.new("RGB", (128, 128), "black").save(catalog / "dark.png")
    (catalog / "Contents.json").write_text(
        json.dumps(
            {
                "images": [
                    {"filename": "dark.png", "size": "128x128", "appearances": [{"value": "dark"}]},
                    {"filename": "default.png", "size": "64x64", "idiom": "universal", "platform": "ios"},
                ]
            }
        )
    )
    config = ScanConfig(project_path=project, output_path=tmp_path / "scan")
    for result in PlistSourceScanner().scan(config):
        assert result.success
        FileScanOutput(config.output_path).write_result(result)
    shutil.rmtree(project)

    loaded = NativeIOSScanOutputLoader().load(config.output_path)
    sections = NativeIOSScanDetailExtractor().extract_sections(loaded)
    sections["target_information"] = {
        "target_kind": "native_ios_source",
        "platform": "ios",
        "target_type": "source",
        "stack": "native_ios",
    }
    report = ReportGenerationService([NativeIOSReportDataBuilder()]).build_report_data(sections)
    uri = get_app_icon_data_uri(PdfReportGenerator._merged_presentation_data(report))
    assert uri == sections["app_info"]["icon_data_uri"]
    with Image.open(io.BytesIO(base64.b64decode(uri.split(",")[1]))) as icon:
        assert icon.size == (64, 64)
        assert icon.getpixel((0, 0)) == (255, 0, 0)

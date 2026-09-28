import json
import time
from dataclasses import asdict
from pathlib import Path

from adapters.output.console_output import ConsoleScanOutput
from adapters.output.file_output import FileScanOutput
from adapters.output.phoenix_report.builders.android import (
    AndroidBinaryReportDataBuilder,
    NativeAndroidReportDataBuilder,
)
from adapters.output.phoenix_report.builders.flutter import FlutterReportDataBuilder
from adapters.output.phoenix_report.builders.ios import IOSBinaryReportDataBuilder, NativeIOSReportDataBuilder
from adapters.output.phoenix_report.builders.react_native import ReactNativeReportDataBuilder
from adapters.post_scan import (
    AndroidBinaryScanDetailExtractor,
    AndroidBinaryScanOutputLoader,
    FlutterScanDetailExtractor,
    FlutterScanOutputLoader,
    IOSBinaryScanDetailExtractor,
    IOSBinaryScanOutputLoader,
    NativeAndroidScanDetailExtractor,
    NativeAndroidScanOutputLoader,
    NativeIOSScanDetailExtractor,
    NativeIOSScanOutputLoader,
    ReactNativeScanDetailExtractor,
    ReactNativeScanOutputLoader,
)
from adapters.scanners.android import (
    Aapt2Scanner,
    AndroguardScanner,
    ApkidScanner,
    ApksignerScanner,
    ApktoolScanner,
    NativeAndroidSourceMetadataScanner,
)
from adapters.scanners.common import (
    GitleaksScanner,
    OpenGrepScanner,
    StringsScanner,
    SyftScanner,
    TrufflehogScanner,
)
from adapters.scanners.common.opengrep_scanner import CategoryOpenGrepScanner
from adapters.scanners.flutter import FlutterOpenGrepScanner, FlutterSourceMetadataScanner
from adapters.scanners.ios import (
    IpswScanner,
    LIEFScanner,
    PlistBinaryScanner,
    PlistSourceScanner,
)
from adapters.scanners.react_native import ReactNativeOpenGrepScanner, ReactNativeSourceMetadataScanner
from application.post_scan_processing_service import PostScanProcessingService
from application.report_generation_service import ReportGenerationService
from application.scanner_service import ScannerService
from domain.models import ExtractedBinary, ScanConfig, ScanResult, ScanType
from domain.report import ReportMetadata, ReportTargetFactory
from ports.scanner_port import ScannerPort
from utilities.apk_utils import extract_apk, is_apk_file
from utilities.exclusions import prune_excluded, source_scan_workspace
from utilities.ipa_utils import extract_ipa, is_ipa_file


class MobileScannerFactory:
    """Build the scanner list for a mobile analysis workflow."""

    def build_scanner_list(self, config: ScanConfig) -> list[ScannerPort]:
        return self._base_scanners(config)

    def _base_scanners(self, config: ScanConfig) -> list[ScannerPort]:
        match (config.target_type, config.platform, config.stack):
            case ("BINARY", "ANDROID", _):
                return [
                    AndroguardScanner(),
                    Aapt2Scanner(),
                    ApktoolScanner(),
                    ApksignerScanner(),
                    ApkidScanner(),
                    StringsScanner(),
                    SyftScanner(),
                    TrufflehogScanner(),
                    GitleaksScanner(),
                ]
            case ("BINARY", "IOS", _):
                return [
                    IpswScanner(),
                    SyftScanner(),
                    LIEFScanner(),
                    StringsScanner(),
                    TrufflehogScanner(),
                    GitleaksScanner(),
                    PlistBinaryScanner(),
                ]
            case ("SOURCE", _, "FLUTTER"):
                return [
                    FlutterSourceMetadataScanner(),
                    TrufflehogScanner(),
                    GitleaksScanner(),
                    *([PlistSourceScanner()] if (config.project_path / "ios").is_dir() else []),
                    SyftScanner(),
                ]
            case ("SOURCE", _, "REACT_NATIVE"):
                return [
                    ReactNativeSourceMetadataScanner(),
                    TrufflehogScanner(),
                    GitleaksScanner(),
                    *([PlistSourceScanner()] if (config.project_path / "ios").is_dir() else []),
                    SyftScanner(),
                ]
            case ("SOURCE", "ANDROID", "NATIVE_ANDROID"):
                return [
                    NativeAndroidSourceMetadataScanner(),
                    TrufflehogScanner(),
                    GitleaksScanner(),
                    SyftScanner(),
                ]
            case ("SOURCE", "IOS", "NATIVE_IOS"):
                return [
                    TrufflehogScanner(),
                    GitleaksScanner(),
                    PlistSourceScanner(),
                    SyftScanner(),
                ]
            case _:
                raise ValueError(
                    "Unsupported scan configuration: "
                    f"target_type={config.target_type}, platform={config.platform}, stack={config.stack}"
                )

    @staticmethod
    def _get_opengrep_scan_paths(config: ScanConfig) -> list[Path]:
        if config.target_type == "SOURCE":
            paths = [config.project_path]
            plist_output = config.output_path / ScanType.PLIST_SOURCE.value / "xml"
            if config.stack == "NATIVE_IOS" and plist_output.is_dir():
                paths.append(plist_output)
            return paths
        if config.target_type == "BINARY":
            evidence_types = (
                ScanType.STRINGS,
                ScanType.APKTOOL,
                ScanType.AAPT2,
                ScanType.APKSIGNER,
                ScanType.ANDROGUARD,
                ScanType.APKID,
                ScanType.LIEF,
                ScanType.IPSW,
                ScanType.PLIST_BINARY,
            )
            return [
                config.output_path / kind.value for kind in evidence_types if (config.output_path / kind.value).is_dir()
            ]
        raise ValueError(f"Unsupported target type for OpenGrep scan paths: {config.target_type}")


class MobileAnalysisWorkflowService:
    POST_SCAN_OUTPUT_FILE_NAME = "post_scan_processing.json"
    GENERATED_REPORT_FILE_NAME = "phoenix_Report.pdf"

    def __init__(self) -> None:
        self.console = ConsoleScanOutput()

    def run(self, scan_config: ScanConfig) -> None:
        with source_scan_workspace(scan_config) as execution_config:
            self._run(execution_config)

    def _run(self, scan_config: ScanConfig) -> None:
        self.console.scan_started(scan_config)

        scan_config.output_path.mkdir(parents=True, exist_ok=True)
        scan_output_method = FileScanOutput(scan_config.output_path)
        scan_output_method.write_scan_metadata(scan_config)
        extracted_binary = self._extract_binary(scan_config)
        scan_config.extracted_binary = extracted_binary
        try:
            if extracted_binary is not None and scan_config.exclude_patterns:
                prune_excluded(extracted_binary.scan_root_path, scan_config.exclude_patterns)
                if hasattr(extracted_binary, "native_libs"):
                    extracted_binary.native_libs = [p for p in extracted_binary.native_libs if p.is_file()]
                    extracted_binary.analysis_targets = [p for p in extracted_binary.analysis_targets if p.is_file()]
            scanners = MobileScannerFactory().build_scanner_list(scan_config)
            scanner_service = ScannerService(scanners)

            wall_start = time.perf_counter()
            scan_results = scanner_service.scan_project(scan_config, output=scan_output_method, retain_output=False)

            opengrep_results = self._perform_opengrep_scan(scan_config, scan_output_method)
            scan_results.extend(opengrep_results)

            post_scan_output = self._run_post_scan_processing(scan_config.output_path, scan_config)
            post_scan_output["target_information"] = asdict(ReportTargetFactory.from_scan_config(scan_config))
            report_data = ReportGenerationService(
                [
                    AndroidBinaryReportDataBuilder(),
                    IOSBinaryReportDataBuilder(),
                    FlutterReportDataBuilder(),
                    ReactNativeReportDataBuilder(),
                    NativeAndroidReportDataBuilder(),
                    NativeIOSReportDataBuilder(),
                ]
            ).build_report_data(post_scan_output)
            if scan_config.json_report:
                target = scan_config.output_path / self.POST_SCAN_OUTPUT_FILE_NAME
                target.write_text(json.dumps(report_data.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
                self.console.report_written("JSON", target)
            if scan_config.pdf_report:
                from adapters.output.phoenix_report.pdf_report import PdfReportGenerator

                report_path = self._report_output_path(scan_config.output_path, report_data.metadata)
                PdfReportGenerator().generate(report_data, report_path)
                self.console.report_written("PDF", report_path)
            executions = len({result.scanner_name for result in scan_results if not result.skipped})
            self.console.scan_summary(report_data, scan_config, executions, time.perf_counter() - wall_start)
        finally:
            if extracted_binary is not None:
                extracted_binary.cleanup()
            scan_config.extracted_binary = None

    @staticmethod
    def _extract_binary(scan_config: ScanConfig) -> ExtractedBinary | None:
        if scan_config.target_type != "BINARY":
            return None
        if scan_config.platform == "IOS" and is_ipa_file(scan_config.project_path):
            return extract_ipa(scan_config.project_path)
        if scan_config.platform == "ANDROID" and is_apk_file(scan_config.project_path):
            return extract_apk(scan_config.project_path)
        return None

    def _perform_opengrep_scan(self, scan_config: ScanConfig, scan_output_method: FileScanOutput):
        open_grep_rules_path = self._get_opengrep_rules_path(scan_config)
        opengrep_scan_paths = self._get_opengrep_scan_paths(scan_config)
        self.console.message("OpenGrep rules", open_grep_rules_path)
        self.console.message("OpenGrep inputs", ", ".join(str(path) for path in opengrep_scan_paths))
        if (
            scan_config.target_type == "BINARY"
            and open_grep_rules_path
            and not OpenGrepScanner()._has_rule_files(Path(open_grep_rules_path))
        ):
            reason = "Binary OpenGrep rules have not been provided; security findings were not evaluated."
            result = ScanResult(
                scanner_name="OpenGrep",
                scan_type=ScanType.OPENGREP_SOURCE,
                skipped=True,
                error_message=reason,
                relative_target_path="opengrep_results.json",
                raw_output=json.dumps(
                    {
                        "results": [],
                        "scan_metadata": {
                            "platform": scan_config.platform.lower(),
                            "mode": "binary",
                            "rule_catalog": [],
                            "rule_execution": {},
                            "status": "not_evaluated",
                            "reason": reason,
                        },
                    }
                ),
            )
            if scan_output_method is not None:
                scan_output_method.write_result(result)
            self.console.tool_status("OpenGrep", "SKIPPED", reason)
            return [result]
        if open_grep_rules_path and opengrep_scan_paths:
            if scan_config.stack == "FLUTTER":
                opengrep_scanner = FlutterOpenGrepScanner(
                    flutter_rules_path=Path(open_grep_rules_path),
                    android_rules_path=scan_config.opengrep_rules_root / "android/source"
                    if scan_config.opengrep_rules_root
                    else None,
                    ios_rules_path=scan_config.opengrep_rules_root / "ios/source"
                    if scan_config.opengrep_rules_root
                    else None,
                )
            elif scan_config.stack == "REACT_NATIVE":
                opengrep_scanner = ReactNativeOpenGrepScanner(
                    react_native_rules_path=Path(open_grep_rules_path),
                    android_rules_path=scan_config.opengrep_rules_root / "android/source"
                    if scan_config.opengrep_rules_root
                    else None,
                    ios_rules_path=scan_config.opengrep_rules_root / "ios/source"
                    if scan_config.opengrep_rules_root
                    else None,
                )
            elif scan_config.platform == "IOS" or scan_config.stack == "NATIVE_ANDROID":
                opengrep_scanner = CategoryOpenGrepScanner(
                    platform=scan_config.platform.lower(),
                    rules_directory=Path(open_grep_rules_path),
                    scan_paths=opengrep_scan_paths,
                )
            else:
                opengrep_scanner = OpenGrepScanner(
                    rules_path=Path(open_grep_rules_path),
                    scan_paths=opengrep_scan_paths,
                )
            return ScannerService([opengrep_scanner]).scan_project(
                scan_config, output=scan_output_method, retain_output=False
            )
        raise RuntimeError("OpenGrep cannot run without a rules path and scan inputs.")

    def _get_opengrep_rules_path(self, config: ScanConfig) -> str | None:
        if config.opengrep_rules_path:
            return str(config.opengrep_rules_path)
        platform = {"FLUTTER": "flutter", "REACT_NATIVE": "react_native"}.get(config.stack, config.platform.lower())
        root = config.opengrep_rules_root or Path(__file__).resolve().parents[1] / "rules"
        return str(root / platform / config.mode.lower())

    @staticmethod
    def _get_opengrep_scan_paths(config: ScanConfig) -> list[Path]:
        return MobileScannerFactory._get_opengrep_scan_paths(config)

    def _run_post_scan_processing(self, output_path: Path, scan_config: ScanConfig) -> dict:
        service = self._build_post_scan_processing_service(scan_config)
        return service.process(output_path)

    def _report_output_path(self, output_path: Path, metadata: ReportMetadata) -> Path:
        file_stem = self._report_file_stem(metadata)
        return output_path / f"{file_stem}_{self.GENERATED_REPORT_FILE_NAME}"

    @staticmethod
    def _report_file_stem(metadata: ReportMetadata) -> str:
        candidates = (metadata.app_display_name, metadata.file_name)
        for candidate in candidates:
            text = str(candidate or "").strip()
            if not text:
                continue
            sanitized = "".join(char if char.isalnum() else "_" for char in Path(text).stem).strip("_")
            if sanitized:
                return sanitized
        return "scan"

    @staticmethod
    def _build_post_scan_processing_service(
        scan_config: ScanConfig,
    ) -> PostScanProcessingService:
        match (scan_config.target_type, scan_config.platform, scan_config.stack):
            case ("BINARY", "ANDROID", _):
                return PostScanProcessingService(
                    scan_output_loader=AndroidBinaryScanOutputLoader(),
                    scan_detail_extractor=AndroidBinaryScanDetailExtractor(),
                )
            case ("BINARY", "IOS", _):
                return PostScanProcessingService(
                    scan_output_loader=IOSBinaryScanOutputLoader(),
                    scan_detail_extractor=IOSBinaryScanDetailExtractor(),
                )
            case ("SOURCE", _, "FLUTTER"):
                return PostScanProcessingService(
                    scan_output_loader=FlutterScanOutputLoader(),
                    scan_detail_extractor=FlutterScanDetailExtractor(),
                )
            case ("SOURCE", _, "REACT_NATIVE"):
                return PostScanProcessingService(
                    scan_output_loader=ReactNativeScanOutputLoader(),
                    scan_detail_extractor=ReactNativeScanDetailExtractor(),
                )
            case ("SOURCE", "IOS", "NATIVE_IOS"):
                return PostScanProcessingService(
                    scan_output_loader=NativeIOSScanOutputLoader(),
                    scan_detail_extractor=NativeIOSScanDetailExtractor(),
                )
            case ("SOURCE", "ANDROID", "NATIVE_ANDROID"):
                return PostScanProcessingService(
                    scan_output_loader=NativeAndroidScanOutputLoader(),
                    scan_detail_extractor=NativeAndroidScanDetailExtractor(),
                )
            case _:
                raise ValueError(
                    f"Post-scan processing not supported for target_type={scan_config.target_type}, "
                    f"platform={scan_config.platform}, stack={scan_config.stack}"
                )

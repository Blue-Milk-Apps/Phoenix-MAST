import json
import os
import time
from pathlib import Path

from adapters.binary_scanners import (
    Aapt2Scanner,
    AndroguardScanner,
    ApkidScanner,
    ApksignerScanner,
    ApktoolScanner,
    IpswScanner,
    LIEFScanner,
    MobSFScanner,
    PlistBinaryScanner,
)
from adapters.output.appcritiq_report.generate_report import generate_report
from adapters.output.file_output import FileScanOutput
from adapters.post_scan import (
    AndroidBinaryScanDetailExtractor,
    AndroidBinaryScanOutputLoader,
)
from adapters.source_code_scanners import (
    DependencyCheckScanner,
    GitleaksScanner,
    OpenGrepScanner,
    PlistSourceScanner,
    StringsScanner,
    SyftScanner,
    TrufflehogScanner,
)
from application.post_scan_processing_service import PostScanProcessingService
from application.scanner_service import ScannerService
from domain.models import ScanConfig
from ports.scanner_port import ScannerPort


class MobileScannerFactory:
    """Build the scanner list for a mobile analysis workflow."""

    def build_scanner_list(self, config: ScanConfig) -> list[ScannerPort]:
        scanners = self._base_scanners(config)

        if self._mobsf_url_configured():
            scanners.append(MobSFScanner())

        return scanners

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
                ]
            case ("BINARY", "IOS", _):
                return [
                    IpswScanner(),
                    LIEFScanner(),
                    StringsScanner(),
                    PlistBinaryScanner(),
                ]
            case ("SOURCE", _, "FLUTTER") | ("SOURCE", _, "REACT_NATIVE"):
                return [
                    TrufflehogScanner(),
                    GitleaksScanner(),
                    PlistSourceScanner(),
                    DependencyCheckScanner(),
                    SyftScanner(output_format=config.syft_output_format),
                ]
            case ("SOURCE", "ANDROID", "NATIVE_ANDROID"):
                return [
                    TrufflehogScanner(),
                    GitleaksScanner(),
                    DependencyCheckScanner(),
                    SyftScanner(output_format=config.syft_output_format),
                ]
            case ("SOURCE", "IOS", "NATIVE_IOS"):
                return [
                    TrufflehogScanner(),
                    GitleaksScanner(),
                    PlistSourceScanner(),
                    SyftScanner(output_format=config.syft_output_format),
                ]
            case _:
                raise ValueError(
                    "Unsupported scan configuration: "
                    f"target_type={config.target_type}, platform={config.platform}, stack={config.stack}"
                )

    @staticmethod
    def _mobsf_url_configured() -> bool:
        return bool(os.environ.get("MOBSF_URL", "").strip())

    @staticmethod
    def _get_opengrep_scan_paths(config: ScanConfig) -> list[Path]:
        if config.target_type == "SOURCE":
            return [config.project_path, config.output_path]
        if config.target_type == "BINARY":
            return [config.output_path]
        raise ValueError(f"Unsupported target type for OpenGrep scan paths: {config.target_type}")


class MobileAnalysisWorkflowService:
    POST_SCAN_OUTPUT_FILE_NAME = "post_scan_processing.json"
    GENERATED_REPORT_FILE_NAME = "AppCritique_Report.pdf"

    def run(self, scan_config: ScanConfig) -> None:
        print("AppcritIQ scan")
        print(f"Project: {scan_config.project_path}")
        print(f"Output: {scan_config.output_path}")
        print(f"Scan type: {scan_config.scan_label}")
        print(f"Proceeding with {scan_config.scan_label} scan")

        scan_config.output_path.mkdir(parents=True, exist_ok=True)
        scan_output_method = FileScanOutput(scan_config.output_path)
        scan_output_method.write_scan_metadata(scan_config)
        scanners = MobileScannerFactory().build_scanner_list(scan_config)
        scanner_service = ScannerService(scanners)

        wall_start = time.perf_counter()
        scan_results = scanner_service.scan_project(scan_config)
        for result in scan_results:
            scan_output_method.write_result(result)

        opengrep_results = self._perform_opengrep_scan(scan_config, scan_output_method)
        scan_results.extend(opengrep_results)
        for result in opengrep_results:
            scan_output_method.write_result(result)

        post_scan_output = self._run_post_scan_processing(scan_config.output_path, scan_config)
        target = scan_config.output_path / self.POST_SCAN_OUTPUT_FILE_NAME
        target.write_text(
            json.dumps(post_scan_output, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        if post_scan_output:
            generate_report(post_scan_output, self._report_output_path(scan_config.output_path, post_scan_output))
        print(f"Results: {len(scan_results)}")
        print(f"Duration: {time.perf_counter() - wall_start:.2f} seconds")

    def _perform_opengrep_scan(self, scan_config: ScanConfig, scan_output_method: FileScanOutput):
        open_grep_rules_path = self._get_opengrep_rules_path(scan_config)
        opengrep_scan_paths = self._get_opengrep_scan_paths(scan_config)
        print(f"OpenGrep rules path: {open_grep_rules_path}")
        print(f"OpenGrep scan paths: {opengrep_scan_paths}")
        opengrep_results = []
        if open_grep_rules_path:
            opengrep_scanner = OpenGrepScanner(
                rules_path=Path(open_grep_rules_path),
                scan_paths=opengrep_scan_paths,
            )
            results = opengrep_scanner.scan(scan_config)
            opengrep_results.extend(results)
        return opengrep_results

    def _get_opengrep_rules_path(self, config: ScanConfig) -> str | None:
        if config.opengrep_rules_path:
            return str(config.opengrep_rules_path)
        if config.target_type == "SOURCE":
            return None
        if config.platform == "ANDROID":
            return "opengrep_rules/android_binary"
        if config.platform == "IOS":
            return "opengrep_rules/ios_binary"
        return None

    @staticmethod
    def _get_opengrep_scan_paths(config: ScanConfig) -> list[Path]:
        return MobileScannerFactory._get_opengrep_scan_paths(config)

    def _run_post_scan_processing(self, output_path: Path, scan_config: ScanConfig) -> dict:
        service = self._build_post_scan_processing_service(scan_config)
        if service is None:
            return {}

        post_scan_output = service.process(output_path)
        return post_scan_output

    def _report_output_path(self, output_path: Path, post_scan_output: dict) -> Path:
        file_stem = self._report_file_stem(post_scan_output)
        return output_path / f"{file_stem}_{self.GENERATED_REPORT_FILE_NAME}"

    @staticmethod
    def _report_file_stem(post_scan_output: dict) -> str:
        candidates = (
            (post_scan_output.get("meta") or {}).get("app_display_name"),
            (post_scan_output.get("file_info") or {}).get("filename"),
            (post_scan_output.get("meta") or {}).get("file_name"),
        )
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
    ) -> PostScanProcessingService | None:
        match (scan_config.target_type, scan_config.platform, scan_config.stack):
            case ("BINARY", "ANDROID", _):
                return PostScanProcessingService(
                    scan_output_loader=AndroidBinaryScanOutputLoader(),
                    scan_detail_extractor=AndroidBinaryScanDetailExtractor(),
                )
            case _:
                return None

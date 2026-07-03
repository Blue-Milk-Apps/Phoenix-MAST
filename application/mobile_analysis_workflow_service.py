import os
import time
from pathlib import Path

from adapters.binary_scanners import (
    Aapt2Scanner,
    AndroguardScanner,
    ApkidScanner,
    ApksignerScanner,
    ApktoolScanner,
    BinaryOpenGrepScanner,
    IpswScanner,
    LIEFScanner,
    MobSFScanner,
    PlistBinaryScanner,
)
from adapters.output.file_output import FileScanOutput
from adapters.source_code_scanners import (
    DependencyCheckScanner,
    GitleaksScanner,
    OpenGrepScanner,
    PlistSourceScanner,
    StringsScanner,
    SyftScanner,
    TrufflehogScanner,
)
from application.scanner_service import ScannerService
from domain.models import ScanConfig
from ports.scanner_port import ScannerPort


class MobileScannerFactory:
    """Build the scanner list for a mobile analysis workflow."""

    def build_scanner_list(self, config: ScanConfig) -> list[ScannerPort]:
        scanners = self._base_scanners(config)

        if config.opengrep_rules_path:
            if config.target_type == "BINARY":
                scanners.append(BinaryOpenGrepScanner(rules_path=config.opengrep_rules_path))
            else:
                scanners.insert(0, OpenGrepScanner(rules_path=config.opengrep_rules_path))

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


class MobileAnalysisWorkflowService:
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

        open_grep_rules_path = self._get_opengrep_rules_path(scan_config)
        opengrep_scan_paths = self._get_opengrep_scan_paths(scan_config)

        print(f"Results: {len(scan_results)}")
        print(f"Duration: {time.perf_counter() - wall_start:.2f} seconds")

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

    def _get_opengrep_scan_paths(self, config: ScanConfig) -> list[Path]:
        if config.target_type == "SOURCE":
            return [config.project_path, config.output_path]
        if config.target_type == "BINARY":
            return [config.output_path]
        raise ValueError(f"Unsupported target type for OpenGrep scan paths: {config.target_type}")

from adapters.output.file_output import FileScanOutput
from application.scanner_service import ScannerService
from domain.models import ScanConfig
import time


class MobileAnalysisWorkflowService:
    def run(self, scan_config: ScanConfig):
        # Implement the logic to run the mobile analysis workflow based on the scan_config
        print("AppcritIQ scan")
        print(f"Project: {scan_config.project_path}")
        print(f"Output: {scan_config.output_path}")
        print(f"Scan type: {scan_config.scan_label}")
        print(f"Proceeding with {scan_config.scan_label} scan")

        scan_config.output_path.mkdir(parents=True, exist_ok=True)
        report_context = self._report_context_from_scan_config(scan_config)
        scan_output_method = FileScanOutput(scan_config.output_path)
        scan_output_method.write_scan_metadata(scan_config, report_context)
        scanner_service = ScannerService(scan_config.scanners)

        wall_start = time.perf_counter()
        scan_results = scanner_service.scan_project(scan_config)
        for result in scan_results:
            scan_output_method.write_result(result)
        print(f"Results: {len(scan_results)}")
        print(f"Duration: {time.perf_counter() - wall_start:.2f} seconds")

    def _report_context_from_scan_config(scan_config: ScanConfig) -> dict[str, str]:
        scan_label = scan_config.scan_label.lower()
        platform = "ANY"
        if "ios" in scan_label:
            platform = "IOS"
        elif "android" in scan_label:
            platform = "ANDROID"

        stack = "ANY"
        if "flutter" in scan_label:
            stack = "FLUTTER"
        elif "react native" in scan_label:
            stack = "REACT_NATIVE"
        elif "native ios" in scan_label:
            stack = "NATIVE_IOS"
        elif "native android" in scan_label:
            stack = "NATIVE_ANDROID"

        return {
            "platform": platform,
            "target_type": scan_config.mode.upper(),
            "stack": stack,
        }

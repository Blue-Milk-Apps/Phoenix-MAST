import time

from adapters.output.file_output import FileScanOutput
from application.scanner_service import ScannerService
from domain.models import ScanConfig


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
        scanner_service = ScannerService(scan_config.scanners)

        wall_start = time.perf_counter()
        scan_results = scanner_service.scan_project(scan_config)
        for result in scan_results:
            scan_output_method.write_result(result)
        print(f"Results: {len(scan_results)}")
        print(f"Duration: {time.perf_counter() - wall_start:.2f} seconds")

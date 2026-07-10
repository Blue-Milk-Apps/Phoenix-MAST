from pathlib import Path

from application.scanner_service import ScannerService
from domain.models import ScanConfig, ScanResult, ScanType
from ports.scan_output_port import ScanOutputPort


class RecordingOutput(ScanOutputPort):
    def __init__(self) -> None:
        self.results: list[ScanResult] = []

    def write_result(self, result: ScanResult) -> None:
        self.results.append(result)


class FakeScanner:
    scan_type = ScanType.GITLEAKS
    name = "Gitleaks"

    def __init__(self, raw_output: str) -> None:
        self._raw_output = raw_output

    @property
    def description(self) -> str:
        return ""

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        return [
            ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                raw_output=self._raw_output,
            )
        ]


def test_scanner_service_returns_empty_results_without_scanners(tmp_path: Path) -> None:
    config = ScanConfig(
        project_path=tmp_path,
        output_path=tmp_path / "scan-results",
    )

    results = ScannerService(scanners=[]).scan_project(config)

    assert results == []


def test_scanner_service_writes_scan_results_to_output(tmp_path: Path) -> None:
    output = RecordingOutput()
    scanner = FakeScanner('{"results": []}')
    config = ScanConfig(
        project_path=tmp_path,
        output_path=tmp_path / "scan-results",
    )

    results = ScannerService(scanners=[scanner]).scan_project(config)
    for result in results:
        output.write_result(result)

    assert results == output.results
    assert output.results[0].scanner_name == "Gitleaks"
    assert output.results[0].raw_output == '{"results": []}'
    assert output.results[0].duration_seconds >= 0


def test_scanner_service_writes_unavailable_result_to_output(tmp_path: Path) -> None:
    output = RecordingOutput()
    scanner = FakeScanner('{"results": []}')
    scanner.is_available = lambda: False
    config = ScanConfig(
        project_path=tmp_path,
        output_path=tmp_path / "scan-results",
    )

    results = ScannerService(scanners=[scanner]).scan_project(config)
    for result in results:
        output.write_result(result)

    assert results == output.results
    assert output.results[0].skipped is True
    assert output.results[0].success is False

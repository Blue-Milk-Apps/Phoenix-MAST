import json

from adapters.source_code_scanners import trufflehog_scanner
from adapters.source_code_scanners.trufflehog_scanner import TrufflehogScanner
from domain.models import ScanType


def test_trufflehog_metadata() -> None:
    scanner = TrufflehogScanner()

    assert scanner.scan_type is ScanType.TRUFFLEHOG
    assert scanner.name == "Trufflehog Secrets Scanner"
    assert "secrets" in scanner.description


def test_trufflehog_availability(monkeypatch) -> None:
    monkeypatch.setattr(
        trufflehog_scanner.shutil, "which", lambda _: "/usr/local/bin/trufflehog"
    )

    assert TrufflehogScanner().is_available()


def test_trufflehog_scan_success_returns_raw_output(
    monkeypatch, tmp_path, scan_config
) -> None:
    config = scan_config(tmp_path)

    class FakeProcess:
        returncode = 0

        def communicate(self) -> tuple[str, str]:
            return '{"SourceMetadata": {}}\n', "status line\n"

    monkeypatch.setattr(
        trufflehog_scanner.subprocess, "Popen", lambda *args, **kwargs: FakeProcess()
    )

    results = TrufflehogScanner().scan(config)

    assert len(results) == 1
    assert results[0].success
    assert json.loads(results[0].raw_output) == [{"SourceMetadata": {}}]
    assert results[0].relative_target_path == "trufflehog_results.json"

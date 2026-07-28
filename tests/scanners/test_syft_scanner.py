from pathlib import Path

from adapters.source_code_scanners import syft_scanner
from adapters.source_code_scanners.syft_scanner import SyftScanner
from domain.models import ScanType
from utilities.apk_utils import ExtractedAPK


def test_syft_metadata() -> None:
    scanner = SyftScanner()

    assert scanner.scan_type is ScanType.SYFT
    assert scanner.name == "Syft SBOM Generator"
    assert "Software Bill of Materials" in scanner.description


def test_syft_availability(monkeypatch) -> None:
    monkeypatch.setattr(syft_scanner.shutil, "which", lambda _: "/usr/local/bin/syft")

    assert SyftScanner().is_available()


def test_syft_scan_success_loads_raw_output(monkeypatch, tmp_path: Path, scan_config) -> None:
    config = scan_config(tmp_path)
    captured_cmd = []

    class FakeProcess:
        def __init__(self, cmd: list[str]):
            captured_cmd.extend(cmd)
            self.cmd = cmd
            self.returncode = 0

        def communicate(self) -> tuple[str, str]:
            return '{"components": []}', ""

    monkeypatch.setattr(syft_scanner.subprocess, "Popen", lambda cmd, *args, **kwargs: FakeProcess(cmd))

    results = SyftScanner().scan(config)

    assert len(results) == 1
    assert results[0].success
    assert results[0].raw_output == '{"components": []}'
    assert results[0].relative_target_path == "sbom.json"
    assert captured_cmd[captured_cmd.index("-o") + 1] == "cyclonedx-json"


def test_syft_scan_uses_configured_stdout_format(monkeypatch, tmp_path, scan_config) -> None:
    config = scan_config(tmp_path)
    captured_cmd = []

    class FakeProcess:
        def __init__(self, cmd: list[str]):
            captured_cmd.extend(cmd)
            self.returncode = 0

        def communicate(self) -> tuple[str, str]:
            return '{"spdxVersion": "SPDX-2.3"}', ""

    monkeypatch.setattr(syft_scanner.subprocess, "Popen", lambda cmd, *args, **kwargs: FakeProcess(cmd))

    results = SyftScanner(output_format="spdx-json").scan(config)

    assert results[0].success
    assert results[0].raw_output == '{"spdxVersion": "SPDX-2.3"}'
    assert results[0].relative_target_path == "sbom.json"
    assert captured_cmd[captured_cmd.index("-o") + 1] == "spdx-json"


def test_syft_scans_shared_extracted_binary_root(monkeypatch, tmp_path: Path, scan_config) -> None:
    config = scan_config(tmp_path)
    extracted_root = tmp_path / "extracted"
    extracted_root.mkdir()
    config.extracted_binary = ExtractedAPK(temp_dir=extracted_root)
    captured_cmd = []

    class FakeProcess:
        returncode = 0

        def communicate(self) -> tuple[str, str]:
            return '{"components": []}', ""

    def fake_popen(cmd: list[str], *args, **kwargs):
        captured_cmd.extend(cmd)
        return FakeProcess()

    monkeypatch.setattr(syft_scanner.subprocess, "Popen", fake_popen)

    results = SyftScanner().scan(config)

    assert results[0].success
    assert captured_cmd[2] == str(extracted_root)


def test_syft_scan_rejects_file_output_format(tmp_path, scan_config) -> None:
    config = scan_config(tmp_path)

    results = SyftScanner(output_format="cyclonedx-json=sbom.json").scan(config)

    assert not results[0].success
    assert "must not include a file path" in results[0].error_message

from pathlib import Path

import pytest

from adapters.scanners.common import syft_scanner
from adapters.scanners.common.syft_scanner import SyftScanner
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


@pytest.mark.parametrize("original_path", ["", "/workspace/Original App"])
@pytest.mark.parametrize("source_name", [None, "org/custom-app"])
def test_syft_scan_success_loads_raw_output(monkeypatch, tmp_path: Path, scan_config, original_path, source_name) -> None:
    config = scan_config(tmp_path)
    config.display_project_path = original_path
    if source_name is None:
        monkeypatch.delenv("SYFT_SOURCE_NAME", raising=False)
    else:
        monkeypatch.setenv("SYFT_SOURCE_NAME", source_name)
    captured_cmd = []

    class FakeProcess:
        def __init__(self, cmd: list[str]):
            captured_cmd.extend(cmd)
            self.cmd = cmd
            self.returncode = 0

        stdout = '{"artifacts": []}'
        stderr = ""

    monkeypatch.setattr(syft_scanner.subprocess, "run", lambda cmd, *args, **kwargs: FakeProcess(cmd))

    results = SyftScanner().scan(config)

    assert len(results) == 1
    assert results[0].success
    assert results[0].raw_output == '{"artifacts": []}'
    assert results[0].relative_target_path == "sbom.json"
    assert captured_cmd[captured_cmd.index("-o") + 1] == "syft-json"
    assert captured_cmd[2] == str(config.project_path)
    assert captured_cmd[captured_cmd.index("--source-name") + 1] == (
        source_name or ("Original App" if original_path else "project")
    )
    assert "--source-version" not in captured_cmd


def test_syft_scan_uses_configured_stdout_format(monkeypatch, tmp_path, scan_config) -> None:
    config = scan_config(tmp_path)
    captured_cmd = []

    class FakeProcess:
        def __init__(self, cmd: list[str]):
            captured_cmd.extend(cmd)
            self.returncode = 0

        stdout = '{"spdxVersion": "SPDX-2.3"}'
        stderr = ""

    monkeypatch.setattr(syft_scanner.subprocess, "run", lambda cmd, *args, **kwargs: FakeProcess(cmd))

    results = SyftScanner(output_format="spdx-json").scan(config)

    assert not results[0].success
    assert "requires syft-json" in results[0].error_message
    assert captured_cmd == []


def test_syft_scans_shared_extracted_binary_root(monkeypatch, tmp_path: Path, scan_config) -> None:
    config = scan_config(tmp_path)
    config.project_path = tmp_path / "Example.apk"
    monkeypatch.delenv("SYFT_SOURCE_NAME", raising=False)
    extracted_root = tmp_path / "extracted"
    extracted_root.mkdir()
    config.extracted_binary = ExtractedAPK(temp_dir=extracted_root)
    captured_cmd = []

    class FakeProcess:
        returncode = 0

        stdout = '{"artifacts": []}'
        stderr = ""

    def fake_run(cmd: list[str], *args, **kwargs):
        captured_cmd.extend(cmd)
        return FakeProcess()

    monkeypatch.setattr(syft_scanner.subprocess, "run", fake_run)

    results = SyftScanner().scan(config)

    assert results[0].success
    assert captured_cmd[2] == str(extracted_root)
    assert captured_cmd[captured_cmd.index("--source-name") + 1] == "Example.apk"


def test_syft_scan_rejects_file_output_format(tmp_path, scan_config) -> None:
    config = scan_config(tmp_path)

    results = SyftScanner(output_format="syft-json=sbom.json").scan(config)

    assert not results[0].success
    assert "requires syft-json" in results[0].error_message

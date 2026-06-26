from pathlib import Path

from adapters.output import ConsoleScanOutput, FileScanOutput, MultiScanOutput
from adapters.storage import StoreToFile
from domain.models import ScanConfig, ScanResult, ScanType
from ports.scan_output_port import ScanOutputPort
from ports.storage_port import ArtifactStorePort

SCAN_METADATA_FILE_NAME = "scan_metadata.json"


class RecordingOutput(ScanOutputPort):
    def __init__(self) -> None:
        self.results: list[ScanResult] = []

    def write_result(self, result: ScanResult) -> None:
        self.results.append(result)


class RecordingArtifactStore(ArtifactStorePort):
    def __init__(self) -> None:
        self.calls: list[tuple[ScanResult, Path]] = []

    def create_work_dir(self, prefix: str) -> Path:
        return Path(prefix)

    def persist(self, result: ScanResult, storage_path: Path) -> Path:
        self.calls.append((result, storage_path))
        return storage_path / f"{result.scan_type.value}.txt"

    def persist_scan_metadata(
        self,
        config: ScanConfig,
        report_context: dict[str, str],
        storage_path: Path,
    ) -> Path:
        return storage_path / SCAN_METADATA_FILE_NAME


def test_multi_scan_output_writes_result_to_each_output(tmp_path: Path) -> None:
    result = ScanResult(
        scanner_name="Gitleaks",
        scan_type=ScanType.GITLEAKS,
        raw_output='{"ok": true}',
    )
    first = RecordingOutput()
    second = RecordingOutput()

    MultiScanOutput([first, second]).write_result(result)

    assert first.results == [result]
    assert second.results == [result]


def test_console_scan_output_prints_skipped_status(capsys) -> None:
    result = ScanResult(
        scanner_name="Gitleaks",
        scan_type=ScanType.GITLEAKS,
        success=False,
        skipped=True,
        error_message="Gitleaks is not available.",
    )

    ConsoleScanOutput().write_result(result)

    output = capsys.readouterr().out
    assert "Gitleaks: Skipped" in output
    assert "Gitleaks is not available." in output


def test_console_scan_output_prints_skipped_binary_status(capsys) -> None:
    result = ScanResult(
        scanner_name="MobSF Scanner",
        scan_type=ScanType.MOBSF_SCANNER,
        success=False,
        skipped=True,
        error_message="MobSF Scanner is not available on this system.",
    )

    ConsoleScanOutput().write_result(result)

    output = capsys.readouterr().out
    assert "MobSF Scanner: Skipped" in output
    assert "MobSF Scanner is not available on this system." in output


def test_file_scan_output_delegates_to_artifact_store(tmp_path: Path) -> None:
    result = ScanResult(
        scanner_name="Gitleaks",
        scan_type=ScanType.GITLEAKS,
        raw_output='{"ok": true}',
    )
    storage_path = tmp_path / "scan-results"
    artifact_store = RecordingArtifactStore()

    FileScanOutput(storage_path, artifact_store=artifact_store).write_result(result)

    assert artifact_store.calls == [(result, storage_path)]


def test_file_scan_output_writes_scan_metadata(tmp_path: Path) -> None:
    storage_path = tmp_path / "scan-results"
    config = ScanConfig(
        project_path=tmp_path / "Example.ipa",
        output_path=storage_path,
        mode="binary",
        scan_label="iOS binary",
    )
    report_context = {
        "platform": "IOS",
        "target_type": "BINARY",
        "stack": "ANY",
    }

    metadata_path = FileScanOutput(storage_path).write_scan_metadata(
        config,
        report_context,
    )

    assert metadata_path == storage_path / SCAN_METADATA_FILE_NAME
    assert '"platform": "IOS"' in metadata_path.read_text(encoding="utf-8")
    assert '"target_type": "BINARY"' in metadata_path.read_text(encoding="utf-8")


def test_store_to_file_persists_raw_output(tmp_path: Path) -> None:
    result = ScanResult(
        scanner_name="Gitleaks",
        scan_type=ScanType.GITLEAKS,
        raw_output='{"ok": true}',
    )

    stored_path = StoreToFile(tmp_path / "artifacts").persist(
        result,
        tmp_path / "scan-results",
    )

    assert stored_path == tmp_path / "scan-results" / "gitleaks.txt"
    assert stored_path.read_text(encoding="utf-8") == '{"ok": true}'


def test_store_to_file_writes_error_message_when_raw_output_is_empty(
    tmp_path: Path,
) -> None:
    result = ScanResult(
        scanner_name="Gitleaks",
        scan_type=ScanType.GITLEAKS,
        success=False,
        skipped=True,
        error_message="Gitleaks is not available.",
    )

    stored_path = StoreToFile(tmp_path / "artifacts").persist(
        result,
        tmp_path / "scan-results",
    )

    assert stored_path == tmp_path / "scan-results" / "gitleaks.txt"
    assert stored_path.read_text(encoding="utf-8") == "Gitleaks is not available."


def test_store_to_file_preserves_relative_target_extension(tmp_path: Path) -> None:
    result = ScanResult(
        scanner_name="Androguard",
        scan_type=ScanType.STRINGS,
        raw_output='{"ok": true}',
        relative_target_path="metadata.json",
    )

    stored_path = StoreToFile(tmp_path / "artifacts").persist(
        result,
        tmp_path / "scan-results",
    )

    assert stored_path == tmp_path / "scan-results" / "strings" / "metadata.json"
    assert stored_path.read_text(encoding="utf-8") == '{"ok": true}'


def test_store_to_file_adds_txt_for_extensionless_relative_target(
    tmp_path: Path,
) -> None:
    result = ScanResult(
        scanner_name="Strings Extractor",
        scan_type=ScanType.STRINGS,
        raw_output="HELLO",
        relative_target_path="Frameworks/Foo.framework/Foo",
    )

    stored_path = StoreToFile(tmp_path / "artifacts").persist(
        result,
        tmp_path / "scan-results",
    )

    assert (
        stored_path
        == tmp_path
        / "scan-results"
        / "strings"
        / "Frameworks"
        / "Foo.framework"
        / "Foo.txt"
    )
    assert stored_path.read_text(encoding="utf-8") == "HELLO"

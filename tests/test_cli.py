import argparse
import json
import plistlib
import zipfile
from pathlib import Path

import pytest

from application import mobile_analysis_workflow_service as workflow
from domain.models import ScanConfig, ScanResult, ScanType
from entrypoints import cli


@pytest.fixture(autouse=True)
def clear_rules_root_environment(monkeypatch):
    monkeypatch.delenv("PHOENIX_RULES_ROOT", raising=False)


class FakeScanner:
    def __init__(self, scan_type: ScanType, name: str):
        self.scan_type = scan_type
        self.name = name

    def is_available(self) -> bool:
        return False

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        return []


def _fake_scanner(scan_type: ScanType, name: str):
    return lambda *args, **kwargs: FakeScanner(scan_type, name)


def _patch_core_scanners(monkeypatch) -> None:
    monkeypatch.setattr(
        workflow,
        "MobSFScanner",
        _fake_scanner(ScanType.MOBSF_SCANNER, "MobSF Scanner"),
    )
    monkeypatch.setattr(
        workflow,
        "OpenGrepScanner",
        _fake_scanner(ScanType.OPENGREP_SOURCE, "OpenGrep"),
    )
    monkeypatch.setattr(
        workflow,
        "TrufflehogScanner",
        _fake_scanner(ScanType.TRUFFLEHOG, "Trufflehog"),
    )
    monkeypatch.setattr(
        workflow,
        "GitleaksScanner",
        _fake_scanner(ScanType.GITLEAKS, "Gitleaks"),
    )
    monkeypatch.setattr(
        workflow,
        "PlistSourceScanner",
        _fake_scanner(ScanType.PLIST_SOURCE, "Plist Source Saver"),
    )
    monkeypatch.setattr(
        workflow,
        "PlistBinaryScanner",
        _fake_scanner(ScanType.PLIST_BINARY, "Plist Binary Saver"),
    )
    monkeypatch.setattr(
        workflow,
        "LIEFScanner",
        _fake_scanner(ScanType.LIEF, "LIEF Binary Analyzer"),
    )
    monkeypatch.setattr(
        workflow,
        "IpswScanner",
        _fake_scanner(ScanType.IPSW, "ipsw Mach-O Analyzer"),
    )
    monkeypatch.setattr(
        workflow,
        "AndroguardScanner",
        _fake_scanner(ScanType.ANDROGUARD, "Androguard"),
    )
    monkeypatch.setattr(
        workflow,
        "Aapt2Scanner",
        _fake_scanner(ScanType.AAPT2, "aapt2 Evidence Extractor"),
    )
    monkeypatch.setattr(
        workflow,
        "ApktoolScanner",
        _fake_scanner(ScanType.APKTOOL, "Apktool Evidence Extractor"),
    )
    monkeypatch.setattr(
        workflow,
        "ApksignerScanner",
        _fake_scanner(ScanType.APKSIGNER, "Apksigner Evidence Extractor"),
    )
    monkeypatch.setattr(
        workflow,
        "ApkidScanner",
        _fake_scanner(ScanType.APKID, "APKiD Intelligence Extractor"),
    )
    monkeypatch.setattr(
        workflow,
        "StringsScanner",
        _fake_scanner(ScanType.STRINGS, "Strings"),
    )
    monkeypatch.setattr(
        workflow,
        "SyftScanner",
        _fake_scanner(ScanType.SYFT, "Syft"),
    )


def _scan_args(tmp_path: Path, flag_name: str, extra_args: list[str] | None = None) -> argparse.Namespace:
    parser = cli._build_parser()
    return parser.parse_args(
        [
            "scan",
            flag_name,
            str(tmp_path),
            "--output",
            str(tmp_path / "results"),
            *(extra_args or []),
        ]
    )


def _build_scanners(config: ScanConfig) -> list[FakeScanner]:
    return workflow.MobileScannerFactory().build_scanner_list(config)


def _assert_scanner_types(config: ScanConfig, expected_scan_types: set[ScanType]) -> None:
    scanner_types = {scanner.scan_type for scanner in _build_scanners(config)}
    assert scanner_types == expected_scan_types


def test_create_scan_config_for_android_binary(tmp_path: Path, monkeypatch) -> None:
    rules_path = tmp_path / "rules" / "android"
    rules_path.mkdir(parents=True)
    monkeypatch.delenv("MOBSF_URL", raising=False)
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: rules_path)
    args = _scan_args(tmp_path, "--android-binary")

    config = cli._create_scan_config(args)

    assert config.project_path == tmp_path.resolve()
    assert config.mode == "binary"
    assert config.target_type == "BINARY"
    assert config.platform == "ANDROID"
    assert config.stack == "ANY"
    assert config.opengrep_rules_path == rules_path
    assert config.output_path.parent == (tmp_path / "results").resolve()
    assert config.output_path.name.startswith("SAST_android_binary_")
    _assert_scanner_types(
        config,
        {
            ScanType.ANDROGUARD,
            ScanType.AAPT2,
            ScanType.APKTOOL,
            ScanType.APKSIGNER,
            ScanType.APKID,
            ScanType.STRINGS,
        },
    )


def test_create_scan_config_for_android_binary_includes_opengrep_when_rules_path_is_configured(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("MOBSF_URL", raising=False)
    rules_path = tmp_path / "android-opengrep-rules"
    rules_path.mkdir()
    args = _scan_args(
        tmp_path,
        "--android-binary",
        ["--android-binary-opengrep-rules", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    assert config.opengrep_rules_path == rules_path.resolve()
    assert {scanner.scan_type for scanner in _build_scanners(config)} == {
        ScanType.ANDROGUARD,
        ScanType.AAPT2,
        ScanType.APKTOOL,
        ScanType.APKSIGNER,
        ScanType.APKID,
        ScanType.STRINGS,
    }


def test_create_scan_config_for_android_binary_includes_mobsf_when_url_is_configured(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("MOBSF_URL", "http://localhost:8000")
    args = _scan_args(tmp_path, "--android-binary")

    config = cli._create_scan_config(args)

    _assert_scanner_types(
        config,
        {
            ScanType.MOBSF_SCANNER,
            ScanType.ANDROGUARD,
            ScanType.AAPT2,
            ScanType.APKTOOL,
            ScanType.APKSIGNER,
            ScanType.APKID,
            ScanType.STRINGS,
        },
    )


def test_create_scan_config_for_ios_binary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("MOBSF_URL", raising=False)
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: None)
    args = _scan_args(tmp_path, "--ios-binary")

    config = cli._create_scan_config(args)

    assert config.mode == "binary"
    assert config.target_type == "BINARY"
    assert config.platform == "IOS"
    assert config.stack == "ANY"
    assert config.opengrep_rules_path is None
    assert config.output_path.name.startswith("SAST_ios_binary_")
    _assert_scanner_types(
        config,
        {
            ScanType.IPSW,
            ScanType.LIEF,
            ScanType.STRINGS,
            ScanType.PLIST_BINARY,
            ScanType.TRUFFLEHOG,
            ScanType.GITLEAKS,
            ScanType.SYFT,
        },
    )


def test_create_scan_config_for_ios_binary_includes_opengrep_when_rules_path_is_configured(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("MOBSF_URL", raising=False)
    rules_path = tmp_path / "ios-opengrep-rules"
    rules_path.mkdir()
    args = _scan_args(
        tmp_path,
        "--ios-binary",
        ["--ios-binary-opengrep-rules", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    assert config.opengrep_rules_path == rules_path.resolve()
    assert {scanner.scan_type for scanner in _build_scanners(config)} == {
        ScanType.IPSW,
        ScanType.LIEF,
        ScanType.TRUFFLEHOG,
        ScanType.GITLEAKS,
        ScanType.STRINGS,
        ScanType.PLIST_BINARY,
        ScanType.SYFT,
    }


def test_ios_workflow_shares_and_cleans_extracted_binary(tmp_path: Path, monkeypatch) -> None:
    ipa_path = tmp_path / "Example.ipa"
    with zipfile.ZipFile(ipa_path, "w") as archive:
        archive.writestr(
            "Payload/Example.app/Info.plist",
            plistlib.dumps({"CFBundleExecutable": "Example"}),
        )
        archive.writestr("Payload/Example.app/Example", b"binary")

    config = ScanConfig(
        project_path=ipa_path,
        output_path=tmp_path / "results",
        mode="binary",
        platform="IOS",
    )
    captured = []

    class RecordingScannerService:
        def __init__(self, scanners):
            _ = scanners

        def scan_project(self, scan_config, output=None):
            captured.append(scan_config.extracted_binary)
            assert scan_config.project_path == ipa_path
            assert scan_config.extracted_binary is not None
            assert scan_config.extracted_binary.scan_root_path.name == "Example.app"
            return []

    monkeypatch.setattr(workflow.MobileScannerFactory, "build_scanner_list", lambda self, scan_config: [])
    monkeypatch.setattr(workflow, "ScannerService", RecordingScannerService)
    monkeypatch.setattr(
        workflow.MobileAnalysisWorkflowService,
        "_perform_opengrep_scan",
        lambda self, scan_config, scan_output_method: [],
    )
    monkeypatch.setattr(
        workflow.MobileAnalysisWorkflowService,
        "_run_post_scan_processing",
        lambda self, output_path, scan_config: {},
    )
    monkeypatch.setattr(workflow.PdfReportGenerator, "generate", lambda self, data, path: path)

    workflow.MobileAnalysisWorkflowService().run(config)

    assert len(captured) == 1
    assert not captured[0].temp_dir.exists()
    assert config.extracted_binary is None


def test_create_scan_config_for_ios_binary_uses_default_opengrep_rules_path_when_present(
    tmp_path: Path,
    monkeypatch,
) -> None:
    rules_path = tmp_path / "ios"
    rules_path.mkdir()

    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: rules_path)
    monkeypatch.delenv("MOBSF_URL", raising=False)

    config = cli._create_scan_config(_scan_args(tmp_path, "--ios-binary"))

    assert config.opengrep_rules_path == rules_path


def test_create_scan_config_for_ios_binary_includes_mobsf_when_url_is_configured(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MOBSF_URL", "http://localhost:8000")
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: None)
    args = _scan_args(tmp_path, "--ios-binary")

    config = cli._create_scan_config(args)

    _assert_scanner_types(
        config,
        {
            ScanType.MOBSF_SCANNER,
            ScanType.IPSW,
            ScanType.LIEF,
            ScanType.TRUFFLEHOG,
            ScanType.GITLEAKS,
            ScanType.STRINGS,
            ScanType.PLIST_BINARY,
            ScanType.SYFT,
        },
    )


def test_create_scan_config_for_flutter_source(tmp_path: Path) -> None:
    args = _scan_args(tmp_path, "--flutter-source")

    config = cli._create_scan_config(args)

    assert config.mode == "source"
    assert config.target_type == "SOURCE"
    assert config.platform == "ANY"
    assert config.stack == "FLUTTER"
    assert config.opengrep_rules_path == (Path(__file__).parent.parent / "rules" / "flutter" / "source").resolve()
    assert config.syft_output_format == "syft-json"
    assert config.output_path.name.startswith("SAST_flutter_source_")
    _assert_scanner_types(
        config,
        {
            ScanType.FLUTTER_SOURCE_METADATA,
            ScanType.TRUFFLEHOG,
            ScanType.GITLEAKS,
            ScanType.SYFT,
        },
    )


def test_create_scan_config_for_flutter_source_includes_opengrep_when_rules_path_is_configured(
    tmp_path: Path,
) -> None:
    rules_path = tmp_path / "flutter-opengrep-rules"
    rules_path.mkdir()
    args = _scan_args(
        tmp_path,
        "--flutter-source",
        ["--flutter-source-opengrep-rules", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    (config.project_path / "ios").mkdir()
    assert config.opengrep_rules_path == rules_path.resolve()
    assert {scanner.scan_type for scanner in _build_scanners(config)} == {
        ScanType.FLUTTER_SOURCE_METADATA,
        ScanType.TRUFFLEHOG,
        ScanType.GITLEAKS,
        ScanType.PLIST_SOURCE,
        ScanType.SYFT,
    }


def test_create_scan_config_for_flutter_source_uses_default_opengrep_rules_path_when_present(
    tmp_path: Path,
    monkeypatch,
) -> None:
    rules_path = tmp_path / "flutter"
    rules_path.mkdir()
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: rules_path)

    config = cli._create_scan_config(_scan_args(tmp_path, "--flutter-source"))

    assert config.opengrep_rules_path == rules_path


def test_resolve_opengrep_rules_path_uses_app_rules_fallback(monkeypatch) -> None:
    app_rules_path = Path("/app/rules/ios/binary")

    monkeypatch.setattr(
        cli.Path,
        "exists",
        lambda self: self == app_rules_path,
    )

    resolved = cli._resolve_opengrep_rules_path(None, "ios_binary")

    assert resolved == app_rules_path


def test_create_scan_config_for_react_native_source(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: None)
    args = _scan_args(tmp_path, "--react-native-source")

    config = cli._create_scan_config(args)

    assert config.mode == "source"
    assert config.target_type == "SOURCE"
    assert config.platform == "ANY"
    assert config.stack == "REACT_NATIVE"
    assert config.opengrep_rules_path is None
    assert config.output_path.name.startswith("SAST_react_native_source_")
    _assert_scanner_types(
        config,
        {
            ScanType.REACT_NATIVE_SOURCE_METADATA,
            ScanType.TRUFFLEHOG,
            ScanType.GITLEAKS,
            ScanType.SYFT,
        },
    )


def test_create_scan_config_for_react_native_source_includes_opengrep_when_rules_path_is_configured(
    tmp_path: Path,
) -> None:
    rules_path = tmp_path / "react-native-opengrep-rules"
    rules_path.mkdir()
    args = _scan_args(
        tmp_path,
        "--react-native-source",
        ["--react-native-source-opengrep-rules", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    (config.project_path / "ios").mkdir()
    assert config.opengrep_rules_path == rules_path.resolve()
    assert {scanner.scan_type for scanner in _build_scanners(config)} == {
        ScanType.REACT_NATIVE_SOURCE_METADATA,
        ScanType.TRUFFLEHOG,
        ScanType.GITLEAKS,
        ScanType.PLIST_SOURCE,
        ScanType.SYFT,
    }


def test_create_scan_config_for_native_android_source(tmp_path: Path, monkeypatch) -> None:
    rules_path = tmp_path / "rules" / "android"
    rules_path.mkdir(parents=True)
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: rules_path)
    args = _scan_args(tmp_path, "--android-source")

    config = cli._create_scan_config(args)

    assert config.mode == "source"
    assert config.target_type == "SOURCE"
    assert config.platform == "ANDROID"
    assert config.stack == "NATIVE_ANDROID"
    assert config.opengrep_rules_path == rules_path
    assert config.output_path.name.startswith("SAST_native_android_source_")
    _assert_scanner_types(
        config,
        {
            ScanType.NATIVE_ANDROID_SOURCE_METADATA,
            ScanType.TRUFFLEHOG,
            ScanType.GITLEAKS,
            ScanType.SYFT,
        },
    )


def test_create_scan_config_for_native_android_source_includes_opengrep_when_rules_path_is_configured(
    tmp_path: Path,
) -> None:
    rules_path = tmp_path / "native-android-opengrep-rules"
    rules_path.mkdir()
    args = _scan_args(
        tmp_path,
        "--android-source",
        ["--android-source-opengrep-rules", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    assert config.opengrep_rules_path == rules_path.resolve()
    assert {scanner.scan_type for scanner in _build_scanners(config)} == {
        ScanType.NATIVE_ANDROID_SOURCE_METADATA,
        ScanType.TRUFFLEHOG,
        ScanType.GITLEAKS,
        ScanType.SYFT,
    }


def test_create_scan_config_for_native_ios_source(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: None)
    monkeypatch.setenv("MOBSF_URL", "http://localhost:8000")
    args = _scan_args(tmp_path, "--ios-source")

    config = cli._create_scan_config(args)

    assert config.mode == "source"
    assert config.target_type == "SOURCE"
    assert config.platform == "IOS"
    assert config.stack == "NATIVE_IOS"
    assert config.opengrep_rules_path is None
    assert config.output_path.name.startswith("SAST_native_ios_source_")
    _assert_scanner_types(
        config,
        {
            ScanType.TRUFFLEHOG,
            ScanType.GITLEAKS,
            ScanType.PLIST_SOURCE,
            ScanType.SYFT,
        },
    )


def test_create_scan_config_for_native_ios_source_includes_opengrep_when_rules_path_is_configured(
    tmp_path: Path,
) -> None:
    rules_path = tmp_path / "native-ios-opengrep-rules"
    rules_path.mkdir()
    args = _scan_args(
        tmp_path,
        "--ios-source",
        ["--ios-source-opengrep-rules", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    assert config.opengrep_rules_path == rules_path.resolve()
    assert {scanner.scan_type for scanner in _build_scanners(config)} == {
        ScanType.TRUFFLEHOG,
        ScanType.GITLEAKS,
        ScanType.PLIST_SOURCE,
        ScanType.SYFT,
    }


def test_scan_command_prints_selected_scan_details(tmp_path: Path, capsys, monkeypatch) -> None:
    _patch_core_scanners(monkeypatch)

    exit_code = cli.main(
        [
            "scan",
            "--android-binary",
            str(tmp_path),
            "--output",
            str(tmp_path / "results"),
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "Phoenix scan" in output
    assert f"Project: {tmp_path.resolve()}" in output
    assert "Scan type: Android binary" in output
    assert "Proceeding with Android binary scan" in output


def test_scan_command_writes_scan_metadata(tmp_path: Path, monkeypatch) -> None:
    _patch_core_scanners(monkeypatch)

    exit_code = cli.main(
        [
            "scan",
            "--ios-source",
            str(tmp_path),
            "--output",
            str(tmp_path / "results"),
        ]
    )

    scan_dirs = list((tmp_path / "results").iterdir())
    assert exit_code == 1
    assert len(scan_dirs) == 1
    metadata_path = scan_dirs[0] / "scan_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["scan_label"] == "Native iOS source"
    assert metadata["platform"] == "IOS"
    assert metadata["target_type"] == "SOURCE"
    assert metadata["stack"] == "NATIVE_IOS"


def test_scan_command_passes_scan_config_to_mobile_analysis_workflow_service(
    tmp_path: Path,
    monkeypatch,
) -> None:
    rules_path = tmp_path / "rules" / "android"
    rules_path.mkdir(parents=True)
    monkeypatch.delenv("MOBSF_URL", raising=False)
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: rules_path)
    captured = {}

    class RecordingMobileAnalysisWorkflowService:
        def run(self, config: ScanConfig):
            captured["config"] = config
            return []

    monkeypatch.setattr(
        cli,
        "MobileAnalysisWorkflowService",
        lambda: RecordingMobileAnalysisWorkflowService(),
    )

    exit_code = cli.main(
        [
            "scan",
            "--android-binary",
            str(tmp_path),
            "--output",
            str(tmp_path / "results"),
        ]
    )

    assert exit_code == 0
    assert captured["config"].platform == "ANDROID"
    assert captured["config"].stack == "ANY"
    assert captured["config"].opengrep_rules_path == rules_path
    assert not hasattr(captured["config"], "scanners")
    assert not hasattr(captured["config"], "enabled_scans")


def test_scan_command_passes_syft_output_format(tmp_path: Path, monkeypatch) -> None:
    captured = {}

    def recording_syft_scanner(*args, **kwargs):
        captured["output_format"] = kwargs.get("output_format")
        return FakeScanner(ScanType.SYFT, "Syft")

    monkeypatch.setattr(workflow, "SyftScanner", recording_syft_scanner)

    config = cli._create_scan_config(
        _scan_args(
            tmp_path,
            "--flutter-source",
            ["--syft-output-format", "spdx-json"],
        )
    )
    scanners = _build_scanners(config)

    assert scanners
    assert captured["output_format"] == "spdx-json"


@pytest.mark.parametrize("stack", ["FLUTTER", "REACT_NATIVE", "NATIVE_ANDROID", "NATIVE_IOS"])
def test_get_opengrep_scan_paths_for_source_includes_only_native_ios_xml_artifacts(tmp_path: Path, stack: str) -> None:
    config = ScanConfig(
        project_path=tmp_path / "project",
        output_path=tmp_path / "scan-results",
        mode="source",
        platform="ANY",
        stack=stack,
    )

    paths = workflow.MobileScannerFactory()._get_opengrep_scan_paths(config)

    assert paths == [config.project_path]
    plist_output = config.output_path / "plist_source"
    plist_output.mkdir(parents=True)
    (plist_output / "Info.json").write_text('{"plist": {}}')
    assert workflow.MobileScannerFactory()._get_opengrep_scan_paths(config) == [config.project_path]
    xml_output = plist_output / "xml"
    xml_output.mkdir()
    expected = [config.project_path, xml_output] if stack == "NATIVE_IOS" else [config.project_path]
    assert workflow.MobileScannerFactory()._get_opengrep_scan_paths(config) == expected


def test_get_opengrep_scan_paths_for_binary_returns_strings_artifact_directory_only(tmp_path: Path) -> None:
    config = ScanConfig(
        project_path=tmp_path / "app.apk",
        output_path=tmp_path / "scan-results",
        mode="binary",
        platform="ANDROID",
        stack="ANY",
    )
    strings_path = config.output_path / ScanType.STRINGS.value
    strings_path.mkdir(parents=True)
    paths = workflow.MobileScannerFactory()._get_opengrep_scan_paths(config)

    assert paths == [strings_path]


def test_get_opengrep_scan_paths_for_binary_without_strings_returns_empty(tmp_path: Path) -> None:
    config = ScanConfig(
        project_path=tmp_path / "app.apk",
        output_path=tmp_path / "scan-results",
        mode="binary",
        platform="ANDROID",
        stack="ANY",
    )

    assert workflow.MobileScannerFactory()._get_opengrep_scan_paths(config) == []


def test_cli_version_exits_successfully(capsys) -> None:
    try:
        cli.main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0

    output = capsys.readouterr().out
    assert output.startswith("phoenix ")


def test_cli_help_mentions_scan_target_flags(capsys) -> None:
    try:
        cli.main(["scan", "--help"])
    except SystemExit as exc:
        assert exc.code == 0

    output = capsys.readouterr().out
    assert "--ios-binary" in output
    assert "--android-binary" in output
    assert "--flutter-source" in output
    assert "--react-native-source" in output
    assert "--android-source" in output
    assert "--ios-source" in output
    assert "--ios-binary-opengrep-rules" in output
    assert "--android-binary-opengrep-rules" in output
    assert "--flutter-source-opengrep-rules" in output
    assert "--react-native-source-opengrep-rules" in output
    assert "--android-source-opengrep-rules" in output
    assert "--ios-source-opengrep-rules" in output
    assert "-path" not in output
    assert "--native-" not in output
    assert "--syft-output-format" in output


@pytest.mark.parametrize("option", ["--ios-source", "--ios-source-opengrep-rules"])
def test_cli_rejects_removed_path_suffix(tmp_path, capsys, option):
    with pytest.raises(SystemExit) as exc:
        cli._build_parser().parse_args(["scan", "--ios-source", str(tmp_path), f"{option}-path", str(tmp_path)])

    assert exc.value.code == 2
    assert f"unrecognized arguments: {option}-path" in capsys.readouterr().err


@pytest.mark.parametrize("platform", ["ios", "android"])
@pytest.mark.parametrize("suffix", ["", "-opengrep-rules"])
def test_cli_rejects_removed_native_prefix(tmp_path, capsys, platform, suffix):
    option = f"--native-{platform}-source{suffix}"
    with pytest.raises(SystemExit) as exc:
        cli._build_parser().parse_args(["scan", f"--{platform}-source", str(tmp_path), option, str(tmp_path)])

    assert exc.value.code == 2
    assert f"unrecognized arguments: {option}" in capsys.readouterr().err


def test_rules_root_combines_execution_platform_and_mode(tmp_path):
    for flag, relative in (
        ("--ios-source", "ios/source"),
        ("--ios-binary", "ios/binary"),
        ("--android-source", "android/source"),
        ("--android-binary", "android/binary"),
        ("--flutter-source", "flutter/source"),
        ("--react-native-source", "react_native/source"),
    ):
        args = _scan_args(tmp_path, flag, ["--rules-root", str(tmp_path / "private-rules")])
        config = cli._create_scan_config(args)
        assert config.opengrep_rules_path == tmp_path / "private-rules" / relative
        assert config.opengrep_rules_root == tmp_path / "private-rules"


def test_target_override_takes_precedence_over_rules_root(tmp_path):
    args = _scan_args(
        tmp_path,
        "--ios-source",
        ["--rules-root", str(tmp_path / "rules"), "--ios-source-opengrep-rules", str(tmp_path / "custom")],
    )
    assert cli._create_scan_config(args).opengrep_rules_path == tmp_path / "custom"


@pytest.mark.parametrize(
    "flag,relative",
    [
        ("--ios-source", "ios/source"),
        ("--ios-binary", "ios/binary"),
        ("--android-source", "android/source"),
        ("--android-binary", "android/binary"),
        ("--flutter-source", "flutter/source"),
        ("--react-native-source", "react_native/source"),
    ],
)
def test_container_rules_root_needs_no_flag_or_existing_tree(tmp_path, monkeypatch, flag, relative):
    monkeypatch.setenv("PHOENIX_RULES_ROOT", "/app/rules")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.Path, "exists", lambda self: False)

    config = cli._create_scan_config(_scan_args(tmp_path, flag))

    assert config.opengrep_rules_root == Path("/app/rules")
    assert config.opengrep_rules_path == Path("/app/rules") / relative


def test_explicit_rules_root_overrides_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PHOENIX_RULES_ROOT", "/app/rules")
    selected = tmp_path / "selected-rules"
    config = cli._create_scan_config(_scan_args(tmp_path, "--flutter-source", ["--rules-root", str(selected)]))
    assert config.opengrep_rules_root == selected
    assert config.opengrep_rules_path == selected / "flutter/source"


@pytest.mark.parametrize(
    "flag,relative",
    [
        ("--ios-source", "ios/source"),
        ("--ios-binary", "ios/binary"),
        ("--android-source", "android/source"),
        ("--android-binary", "android/binary"),
        ("--flutter-source", "flutter/source"),
        ("--react-native-source", "react_native/source"),
    ],
)
def test_whole_rules_tree_override_selects_execution_scope(tmp_path, monkeypatch, flag, relative):
    monkeypatch.setenv("PHOENIX_RULES_ROOT", "/app/rules")
    root = tmp_path / "PhoenixRules" / "rules"
    (root / relative).mkdir(parents=True)

    config = cli._create_scan_config(_scan_args(tmp_path, flag, [f"{flag}-opengrep-rules", str(root)]))

    assert config.opengrep_rules_path == root / relative
    assert config.opengrep_rules_root == root


@pytest.mark.parametrize("platform", ["ios", "android"])
def test_rules_tree_with_only_source_rules_does_not_supply_binary_rules(tmp_path, platform):
    root = tmp_path / "rules"
    (root / platform / "source").mkdir(parents=True)
    flag = f"--{platform}-binary"

    config = cli._create_scan_config(_scan_args(tmp_path, flag, [f"{flag}-opengrep-rules", str(root)]))

    assert config.opengrep_rules_path == root / platform / "binary"
    assert not config.opengrep_rules_path.exists()


def test_opengrep_rule_loading_failure_is_visible_in_terminal(tmp_path, capsys, monkeypatch):
    rules = tmp_path / "rules" / "ios" / "source"
    rules.mkdir(parents=True)
    config = cli._create_scan_config(_scan_args(tmp_path, "--ios-source", ["--ios-source-opengrep-rules", str(rules)]))

    monkeypatch.setattr(workflow.CategoryOpenGrepScanner, "is_available", lambda self: True)
    monkeypatch.setattr(workflow.MobileScannerFactory, "build_scanner_list", lambda self, config: [])

    exit_code = cli.main(
        [
            "scan",
            "--ios-source",
            str(tmp_path),
            "--output",
            str(config.output_path),
            "--ios-source-opengrep-rules",
            str(rules),
        ]
    )

    assert exit_code == 1
    error = capsys.readouterr().err
    assert "Phoenix scan failed: iOS Category OpenGrep Scanner failed:" in error
    assert f"No YAML rule files found in: {rules}" in error
    assert not list(config.output_path.rglob("post_scan_processing.json"))
    assert not list(config.output_path.rglob("*.pdf"))

import argparse
import json
from pathlib import Path

from domain.models import ScanConfig, ScanResult, ScanType
from entrypoints import cli


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
        cli,
        "MobSFScanner",
        _fake_scanner(ScanType.MOBSF_SCANNER, "MobSF Scanner"),
    )
    monkeypatch.setattr(
        cli,
        "OpenGrepScanner",
        _fake_scanner(ScanType.OPENGREP_SOURCE, "OpenGrep"),
    )
    monkeypatch.setattr(
        cli,
        "BinaryOpenGrepScanner",
        _fake_scanner(ScanType.OPENGREP_BINARY, "OpenGrep Binary"),
    )
    monkeypatch.setattr(
        cli,
        "TrufflehogScanner",
        _fake_scanner(ScanType.TRUFFLEHOG, "Trufflehog"),
    )
    monkeypatch.setattr(
        cli,
        "GitleaksScanner",
        _fake_scanner(ScanType.GITLEAKS, "Gitleaks"),
    )
    monkeypatch.setattr(
        cli,
        "PlistSourceScanner",
        _fake_scanner(ScanType.PLIST_SOURCE, "Plist Source Saver"),
    )
    monkeypatch.setattr(
        cli,
        "PlistBinaryScanner",
        _fake_scanner(ScanType.PLIST_BINARY, "Plist Binary Saver"),
    )
    monkeypatch.setattr(
        cli,
        "LIEFScanner",
        _fake_scanner(ScanType.LIEF, "LIEF Binary Analyzer"),
    )
    monkeypatch.setattr(
        cli,
        "IpswScanner",
        _fake_scanner(ScanType.IPSW, "ipsw Mach-O Analyzer"),
    )
    monkeypatch.setattr(
        cli,
        "AndroguardScanner",
        _fake_scanner(ScanType.ANDROGUARD, "Androguard"),
    )
    monkeypatch.setattr(
        cli,
        "Aapt2Scanner",
        _fake_scanner(ScanType.AAPT2, "aapt2 Evidence Extractor"),
    )
    monkeypatch.setattr(
        cli,
        "ApktoolScanner",
        _fake_scanner(ScanType.APKTOOL, "Apktool Evidence Extractor"),
    )
    monkeypatch.setattr(
        cli,
        "ApksignerScanner",
        _fake_scanner(ScanType.APKSIGNER, "Apksigner Evidence Extractor"),
    )
    monkeypatch.setattr(
        cli,
        "ApkidScanner",
        _fake_scanner(ScanType.APKID, "APKiD Intelligence Extractor"),
    )
    monkeypatch.setattr(
        cli,
        "StringsScanner",
        _fake_scanner(ScanType.STRINGS, "Strings"),
    )
    monkeypatch.setattr(
        cli,
        "DependencyCheckScanner",
        _fake_scanner(ScanType.DEPENDENCY_CHECK, "Dependency Check"),
    )
    monkeypatch.setattr(
        cli,
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


def _assert_scanner_types(config: ScanConfig, expected_scan_types: set[ScanType]) -> None:
    scanner_types = {scanner.scan_type for scanner in config.scanners}

    assert scanner_types == expected_scan_types
    assert set(config.enabled_scans) == expected_scan_types


def test_create_scan_config_for_android_binary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("MOBSF_URL", raising=False)
    args = _scan_args(tmp_path, "--android-binary-path")

    config = cli._create_scan_config(args)

    assert config.project_path == tmp_path.resolve()
    assert config.mode == "binary"
    assert config.target_type == "BINARY"
    assert config.platform == "ANDROID"
    assert config.stack == "ANY"
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
        "--android-binary-path",
        ["--android-binary-opengrep-rules-path", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    assert {scanner.scan_type for scanner in config.scanners} == {
        ScanType.ANDROGUARD,
        ScanType.AAPT2,
        ScanType.APKTOOL,
        ScanType.APKSIGNER,
        ScanType.APKID,
        ScanType.STRINGS,
        ScanType.OPENGREP_BINARY,
    }


def test_create_scan_config_for_android_binary_includes_mobsf_when_url_is_configured(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("MOBSF_URL", "http://localhost:8000")
    args = _scan_args(tmp_path, "--android-binary-path")

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
    args = _scan_args(tmp_path, "--ios-binary-path")

    config = cli._create_scan_config(args)

    assert config.mode == "binary"
    assert config.target_type == "BINARY"
    assert config.platform == "IOS"
    assert config.stack == "ANY"
    assert config.output_path.name.startswith("SAST_ios_binary_")
    _assert_scanner_types(
        config,
        {
            ScanType.IPSW,
            ScanType.LIEF,
            ScanType.STRINGS,
            ScanType.PLIST_BINARY,
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
        "--ios-binary-path",
        ["--ios-binary-opengrep-rules-path", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    assert {scanner.scan_type for scanner in config.scanners} == {
        ScanType.IPSW,
        ScanType.LIEF,
        ScanType.STRINGS,
        ScanType.PLIST_BINARY,
        ScanType.OPENGREP_BINARY,
    }


def test_create_scan_config_for_ios_binary_uses_default_opengrep_rules_path_when_present(
    tmp_path: Path,
    monkeypatch,
) -> None:
    captured = {}
    rules_path = tmp_path / "ios"
    rules_path.mkdir()

    def recording_binary_opengrep_scanner(*args, **kwargs):
        captured["rules_path"] = kwargs.get("rules_path")
        return FakeScanner(ScanType.OPENGREP_BINARY, "OpenGrep Binary")

    monkeypatch.setattr(cli, "BinaryOpenGrepScanner", recording_binary_opengrep_scanner)
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: rules_path)
    monkeypatch.delenv("MOBSF_URL", raising=False)

    config = cli._create_scan_config(_scan_args(tmp_path, "--ios-binary-path"))

    assert captured["rules_path"] == rules_path
    assert ScanType.OPENGREP_BINARY in {scanner.scan_type for scanner in config.scanners}


def test_create_scan_config_for_ios_binary_includes_mobsf_when_url_is_configured(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MOBSF_URL", "http://localhost:8000")
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: None)
    args = _scan_args(tmp_path, "--ios-binary-path")

    config = cli._create_scan_config(args)

    _assert_scanner_types(
        config,
        {
            ScanType.MOBSF_SCANNER,
            ScanType.IPSW,
            ScanType.LIEF,
            ScanType.STRINGS,
            ScanType.PLIST_BINARY,
        },
    )


def test_create_scan_config_for_flutter_source(tmp_path: Path) -> None:
    args = _scan_args(tmp_path, "--flutter-source-path")

    config = cli._create_scan_config(args)

    assert config.mode == "source"
    assert config.target_type == "SOURCE"
    assert config.platform == "ANY"
    assert config.stack == "FLUTTER"
    assert config.output_path.name.startswith("SAST_flutter_source_")
    _assert_scanner_types(
        config,
        {
            ScanType.TRUFFLEHOG,
            ScanType.GITLEAKS,
            ScanType.PLIST_SOURCE,
            ScanType.DEPENDENCY_CHECK,
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
        "--flutter-source-path",
        ["--flutter-source-opengrep-rules-path", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    assert {scanner.scan_type for scanner in config.scanners} == {
        ScanType.OPENGREP_SOURCE,
        ScanType.TRUFFLEHOG,
        ScanType.GITLEAKS,
        ScanType.PLIST_SOURCE,
        ScanType.DEPENDENCY_CHECK,
        ScanType.SYFT,
    }


def test_create_scan_config_for_flutter_source_uses_default_opengrep_rules_path_when_present(
    tmp_path: Path,
    monkeypatch,
) -> None:
    captured = {}
    rules_path = tmp_path / "flutter"
    rules_path.mkdir()

    def recording_opengrep_scanner(*args, **kwargs):
        captured["rules_path"] = kwargs.get("rules_path")
        return FakeScanner(ScanType.OPENGREP_SOURCE, "OpenGrep")

    monkeypatch.setattr(cli, "OpenGrepScanner", recording_opengrep_scanner)
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: rules_path)

    config = cli._create_scan_config(_scan_args(tmp_path, "--flutter-source-path"))

    assert captured["rules_path"] == rules_path
    assert ScanType.OPENGREP_SOURCE in {scanner.scan_type for scanner in config.scanners}


def test_resolve_opengrep_rules_path_uses_app_rules_fallback(monkeypatch) -> None:
    app_rules_path = Path("/app/rules/ios")

    monkeypatch.setattr(
        cli.Path,
        "exists",
        lambda self: self == app_rules_path,
    )

    resolved = cli._resolve_opengrep_rules_path(None, "ios_binary")

    assert resolved == app_rules_path


def test_create_scan_config_for_react_native_source(tmp_path: Path) -> None:
    args = _scan_args(tmp_path, "--react-native-source-path")

    config = cli._create_scan_config(args)

    assert config.mode == "source"
    assert config.target_type == "SOURCE"
    assert config.platform == "ANY"
    assert config.stack == "REACT_NATIVE"
    assert config.output_path.name.startswith("SAST_react_native_source_")
    _assert_scanner_types(
        config,
        {
            ScanType.TRUFFLEHOG,
            ScanType.GITLEAKS,
            ScanType.PLIST_SOURCE,
            ScanType.DEPENDENCY_CHECK,
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
        "--react-native-source-path",
        ["--react-native-source-opengrep-rules-path", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    assert {scanner.scan_type for scanner in config.scanners} == {
        ScanType.OPENGREP_SOURCE,
        ScanType.TRUFFLEHOG,
        ScanType.GITLEAKS,
        ScanType.PLIST_SOURCE,
        ScanType.DEPENDENCY_CHECK,
        ScanType.SYFT,
    }


def test_create_scan_config_for_native_android_source(tmp_path: Path) -> None:
    args = _scan_args(tmp_path, "--native-android-source-path")

    config = cli._create_scan_config(args)

    assert config.mode == "source"
    assert config.target_type == "SOURCE"
    assert config.platform == "ANDROID"
    assert config.stack == "NATIVE_ANDROID"
    assert config.output_path.name.startswith("SAST_native_android_source_")
    _assert_scanner_types(
        config,
        {
            ScanType.TRUFFLEHOG,
            ScanType.GITLEAKS,
            ScanType.DEPENDENCY_CHECK,
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
        "--native-android-source-path",
        ["--native-android-source-opengrep-rules-path", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    assert {scanner.scan_type for scanner in config.scanners} == {
        ScanType.OPENGREP_SOURCE,
        ScanType.TRUFFLEHOG,
        ScanType.GITLEAKS,
        ScanType.DEPENDENCY_CHECK,
        ScanType.SYFT,
    }


def test_create_scan_config_for_native_ios_source(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cli, "_resolve_opengrep_rules_path", lambda override, slug: None)
    args = _scan_args(tmp_path, "--native-ios-source-path")

    config = cli._create_scan_config(args)

    assert config.mode == "source"
    assert config.target_type == "SOURCE"
    assert config.platform == "IOS"
    assert config.stack == "NATIVE_IOS"
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
        "--native-ios-source-path",
        ["--native-ios-source-opengrep-rules-path", str(rules_path)],
    )

    config = cli._create_scan_config(args)

    assert {scanner.scan_type for scanner in config.scanners} == {
        ScanType.OPENGREP_SOURCE,
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
            "--android-binary-path",
            str(tmp_path),
            "--output",
            str(tmp_path / "results"),
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "AppcritIQ scan" in output
    assert f"Project: {tmp_path.resolve()}" in output
    assert "Scan type: Android binary" in output
    assert "Proceeding with Android binary scan" in output


def test_scan_command_writes_scan_metadata(tmp_path: Path, monkeypatch) -> None:
    _patch_core_scanners(monkeypatch)

    exit_code = cli.main(
        [
            "scan",
            "--native-ios-source-path",
            str(tmp_path),
            "--output",
            str(tmp_path / "results"),
        ]
    )

    scan_dirs = list((tmp_path / "results").iterdir())
    assert exit_code == 0
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
    _patch_core_scanners(monkeypatch)
    monkeypatch.delenv("MOBSF_URL", raising=False)
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
            "--android-binary-path",
            str(tmp_path),
            "--output",
            str(tmp_path / "results"),
        ]
    )

    expected_scan_types = {
        ScanType.ANDROGUARD,
        ScanType.AAPT2,
        ScanType.APKTOOL,
        ScanType.APKSIGNER,
        ScanType.APKID,
        ScanType.STRINGS,
    }
    scanner_types = {scanner.scan_type for scanner in captured["config"].scanners}
    assert exit_code == 0
    assert scanner_types == expected_scan_types
    assert set(captured["config"].enabled_scans) == expected_scan_types


def test_scan_command_passes_syft_output_format(tmp_path: Path, monkeypatch) -> None:
    _patch_core_scanners(monkeypatch)
    captured = {}

    def recording_syft_scanner(*args, **kwargs):
        captured["output_format"] = kwargs.get("output_format")
        return FakeScanner(ScanType.SYFT, "Syft")

    monkeypatch.setattr(cli, "SyftScanner", recording_syft_scanner)

    exit_code = cli.main(
        [
            "scan",
            "--flutter-source-path",
            str(tmp_path),
            "--output",
            str(tmp_path / "results"),
            "--syft-output-format",
            "spdx-json",
        ]
    )

    assert exit_code == 0
    assert captured["output_format"] == "spdx-json"


def test_cli_version_exits_successfully(capsys) -> None:
    try:
        cli.main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0

    output = capsys.readouterr().out
    assert output.startswith("appcritiq ")


def test_cli_help_mentions_scan_path_flags(capsys) -> None:
    try:
        cli.main(["scan", "--help"])
    except SystemExit as exc:
        assert exc.code == 0

    output = capsys.readouterr().out
    assert "--ios-binary-path" in output
    assert "--android-binary-path" in output
    assert "--flutter-source-path" in output
    assert "--react-native-source-path" in output
    assert "--native-android-source-path" in output
    assert "--native-ios-source-path" in output
    assert "--ios-binary-opengrep-rules-path" in output
    assert "--android-binary-opengrep-rules-path" in output
    assert "--flutter-source-opengrep-rules-path" in output
    assert "--react-native-source-opengrep-rules-path" in output
    assert "--native-android-source-opengrep-rules-path" in output
    assert "--native-ios-source-opengrep-rules-path" in output
    assert "--sourcecode-path" not in output
    assert "--binary-path" not in output
    assert "--syft-output-format" in output

"""Regression coverage for tool ownership, exclusions, and optional reports."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from adapters.output.file_output import FileScanOutput
from adapters.output.phoenix_report.common.badges import result_badge, risk_badge
from adapters.post_scan.android_binary_scan_detail_extractor import AndroidBinaryScanDetailExtractor
from adapters.post_scan.artifact_loader import ArtifactLoader
from adapters.post_scan.ios.binary.scan_detail_extractor import IOSBinaryScanDetailExtractor
from adapters.post_scan.ios.native.scan_detail_extractor import NativeIOSScanDetailExtractor
from adapters.scanners.android.apktool_scanner import ApktoolDecodeResult, ApktoolScanner
from adapters.scanners.ios.lief_scanner import LIEFScanner
from application.mobile_analysis_workflow_service import MobileAnalysisWorkflowService, MobileScannerFactory
from application.scanner_service import ScannerService
from domain.models import ScanConfig, ScanResult, ScanType
from domain.post_scan.ios.binary.ipa_binary_evidence import IOSIPABinaryEvidence
from domain.post_scan.rule_assessment import rule_assessments
from domain.post_scan.utilities import coerce_bool_like
from entrypoints.cli import _build_parser, _create_scan_config, main
from tests.rule_fixtures import assessment_payload, rule
from utilities.exclusions import PathExclusions, prune_excluded, source_scan_workspace
from utilities.ipa_utils import ExtractedIPA


@pytest.mark.parametrize("severity", [None, "info", "LOW", "Medium", "HIGH", "CRITICAL"])
@pytest.mark.parametrize("json_flag,pdf_flag", [(False, False), (True, False), (False, True), (True, True)])
def test_reports_are_independently_opt_in(tmp_path, monkeypatch, capsys, json_flag, pdf_flag, severity):
    from adapters.output.phoenix_report.pdf_report import PdfReportGenerator

    monkeypatch.setenv("NO_COLOR", "1")
    project = tmp_path / "project"
    project.mkdir()
    args = ["scan", "--ios-source", str(project), "--output", str(tmp_path / "out")]
    args += ["--json"] if json_flag else []
    args += ["--pdf"] if pdf_flag else []
    args += ["--severity", severity] if severity else []
    config = _create_scan_config(_build_parser().parse_args(args))
    assert config.stdout_severity == (severity.lower() if severity else None)
    assert (config.json_report, config.pdf_report) == (json_flag, pdf_flag)
    monkeypatch.setattr(MobileScannerFactory, "build_scanner_list", lambda self, config: [])

    def opengrep(self, config, output):
        result = ScanResult(
            "OpenGrep",
            ScanType.OPENGREP_SOURCE,
            raw_output=json.dumps(
                assessment_payload(
                    *(
                        rule(f"test.{level}", severity=level.upper())
                        for level in ("info", "low", "medium", "high", "critical")
                    ),
                    results=[{"check_id": f"test.{level}"} for level in ("info", "low", "medium", "high", "critical")],
                )
            ),
            relative_target_path="opengrep_results.json",
        )
        output.write_result(result)
        return [result]

    monkeypatch.setattr(MobileAnalysisWorkflowService, "_perform_opengrep_scan", opengrep)
    rendered = []

    def render(self, data, path):
        rendered.append(data)
        path.write_bytes(b"%PDF-fixture")
        return path

    monkeypatch.setattr(PdfReportGenerator, "generate", render)
    MobileAnalysisWorkflowService().run(config)
    assert (config.output_path / "post_scan_processing.json").is_file() == json_flag
    assert bool(list(config.output_path.glob("*.pdf"))) == pdf_flag
    assert bool(rendered) == pdf_flag
    assert (config.output_path / "opengrep_source/opengrep_results.json").is_file()
    stdout = capsys.readouterr().out
    levels = ["info", "low", "medium", "high", "critical"]
    expected = levels[levels.index(severity.lower()) :] if severity else levels
    counts = stdout.split("Weakness counts", 1)[1].split("Findings", 1)[0]
    for level in levels:
        assert (f"test.{level}" in stdout) == (level in expected)
        assert (level.upper() in counts) == (level in expected)
    if rendered:
        assert sum(len(section.checks) for section in rendered[0].vulnerability_sections) == 5
    assert "OpenGrep coverage: success" in stdout
    if json_flag:
        original = json.loads((config.output_path / "post_scan_processing.json").read_text())
        assert sum(len(section["checks"]) for section in original["vulnerability_sections"]) == 5
        monkeypatch.setattr(
            MobileAnalysisWorkflowService, "run", lambda *_: pytest.fail("Saved reports must not run tools")
        )
        assert main(["report", str(config.output_path / "post_scan_processing.json"), "--pdf"]) == 0
        assert json.loads(json.dumps(rendered[-1].to_dict())) == original
        assert config.output_path.joinpath("post_scan_processing.pdf").is_file()


def test_exclusion_list_and_globs_use_one_filtered_tree(tmp_path):
    project = tmp_path / "app"
    for name in [
        "src/keep.py",
        "src/drop.generated.py",
        "vendor/lib/a.py",
        "nested/vendor/b.py",
        "scan-results/old/report.json",
    ]:
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name)
    args = _build_parser().parse_args(
        [
            "scan",
            "--ios-source",
            str(project),
            "--exclude",
            "**/vendor,**/*.generated.py",
            "--output",
            str(project / "scan-results"),
        ]
    )
    config = _create_scan_config(args)
    assert config.exclude_patterns == ["**/vendor", "**/*.generated.py"]
    with source_scan_workspace(config) as filtered:
        staged = filtered.project_path
        assert staged != project
        assert {p.relative_to(staged).as_posix() for p in staged.rglob("*") if p.is_file()} == {"src/keep.py"}
        assert filtered.display_project_path == str(project)
        assert (project / "vendor/lib/a.py").is_file()
    assert not staged.exists()


def test_exclusions_do_not_follow_symlinks_back_into_excluded_paths(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "private.txt").write_text("excluded")
    (root / "alias.txt").symlink_to(root / "private.txt")
    (root / "public.txt").write_text("public")
    (root / "allowed.txt").symlink_to(root / "public.txt")
    config = ScanConfig(root, tmp_path / "out", exclude_patterns=[str(root / "private.txt")])
    with source_scan_workspace(config) as filtered:
        assert not (filtered.project_path / "alias.txt").exists()
        assert (filtered.project_path / "allowed.txt").read_text() == "public"


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("**/*.py", "main.py", True),
        ("**/build", "a/build/out", True),
        ("src/*.py", "src/nested/a.py", False),
        ("a?b", "a/b", False),
        ("lib/[ab].so", "lib/a.so", True),
        ("dir", "directory/a", False),
    ],
)
def test_glob_semantics(tmp_path, pattern, path, expected):
    assert PathExclusions(tmp_path, [pattern]).matches(Path(path)) is expected


def test_extracted_input_exclusions_preserve_other_members(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets/secret.txt").write_text("excluded")
    (tmp_path / "classes.dex").write_bytes(b"dex")
    prune_excluded(tmp_path, ["assets/**"])
    assert not (tmp_path / "assets/secret.txt").exists()
    assert (tmp_path / "classes.dex").is_file()


def test_failed_decode_with_index_is_still_a_failure(tmp_path):
    decoder = ApktoolScanner()
    result = ApktoolDecodeResult(tmp_path, 1, "", "decode failed", "test")
    artifacts = {"evidence_index.json": {"artifacts": [{"name": "manifest_summary.json"}]}}
    results = decoder._scan_results(artifacts, result, [])
    assert results and all(not item.success for item in results)
    assert results[0].raw_output


def test_lief_parse_failure_is_not_a_successful_artifact(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from adapters.scanners.ios import lief_scanner

    binary = tmp_path / "App"
    binary.write_bytes(b"invalid macho")
    extracted = ExtractedIPA(tmp_path, tmp_path, binary, {})
    config = ScanConfig(
        tmp_path / "App.ipa", tmp_path / "out", mode="binary", platform="IOS", extracted_binary=extracted
    )
    monkeypatch.setattr(lief_scanner, "lief", SimpleNamespace(MachO=SimpleNamespace(parse=lambda path: None)))
    results = LIEFScanner().scan(config)
    assert results and not results[0].success
    assert "no Mach-O slices" in results[0].error_message
    assert json.loads(results[0].raw_output)["binary"]["slices"] == []


def test_python_does_not_infer_binary_findings_or_capabilities():
    markers = {"strings_outputs": {"App.txt": "description\nDES\nNSLog password\n"}}
    for extractor in (AndroidBinaryScanDetailExtractor(), IOSBinaryScanDetailExtractor()):
        result = extractor.extract_sections(markers)
        assert result["functionality"] == {}
        assert result["hardcoded_values"]["secrets"] == []
        assert not {"code_evidence", "network_evidence", "data_storage_evidence", "resilience_evidence"} & result.keys()
    assert all(value is None for value in asdict(IOSIPABinaryEvidence({})).values())
    assert coerce_bool_like(False) is False
    assert coerce_bool_like(0) is False


def test_native_ios_functionality_uses_catalog_metadata():
    definition = rule("test.new-capability", finding_type="observation")
    definition["metadata"]["functionality"] = "HomeKit"
    loaded = {
        "opengrep": assessment_payload(
            definition, category="functionality", results=[{"check_id": "test.new-capability"}]
        )
    }
    details = NativeIOSScanDetailExtractor().extract_sections(loaded)
    assert details["functionality"]["HomeKit"]["present"] is True
    assert details["third_party_sdks"] == []


@pytest.mark.parametrize("project_name", ["source", 'source "quoted"'])
def test_persisted_artifacts_release_raw_output_and_restore_original_paths(tmp_path, project_name):
    class Reader:
        name = "Fixture"

        def is_available(self):
            return True

        def scan(self, config):
            return [
                ScanResult(
                    self.name,
                    ScanType.SYFT,
                    raw_output=json.dumps({"path": str(config.project_path / "app.py")}),
                    relative_target_path="sbom.json",
                    artifact_files={"details.json": json.dumps({"path": str(config.project_path / "app.py")})},
                )
            ]

    root = tmp_path / project_name
    root.mkdir()
    (root / "app.py").write_text("pass")
    config = ScanConfig(root, tmp_path / "out", exclude_patterns=["ignored"])
    with source_scan_workspace(config) as filtered:
        assert filtered.project_path == filtered.project_path.resolve()
        results = ScannerService([Reader()]).scan_project(
            filtered, FileScanOutput(config.output_path), retain_output=False
        )
    assert results[0].raw_output == ""
    assert json.loads((config.output_path / "syft/sbom.json").read_text())["path"] == str(root / "app.py")
    assert json.loads((config.output_path / "syft/details.json").read_text())["path"] == str(root / "app.py")


@pytest.mark.parametrize("empty_directory", [False, True])
def test_missing_binary_rules_record_unassessed_coverage(tmp_path, empty_directory):
    config = ScanConfig(
        tmp_path / "app.apk",
        tmp_path / "out",
        mode="binary",
        platform="ANDROID",
        opengrep_rules_path=tmp_path / "rules/android/binary",
    )
    if empty_directory:
        config.opengrep_rules_path.mkdir(parents=True)
        (config.opengrep_rules_path / ".gitkeep").touch()
    output = FileScanOutput(config.output_path)
    result = MobileAnalysisWorkflowService()._perform_opengrep_scan(config, output)[0]
    payload = json.loads((config.output_path / "opengrep_source/opengrep_results.json").read_text())
    assert result.skipped
    assert payload["scan_metadata"]["status"] == "not_evaluated"
    coverage = rule_assessments(payload)["coverage"]
    assert coverage[0]["platform"] == "android"
    assert coverage[0]["mode"] == "binary"
    assert coverage[0]["status"] == "not_evaluated"


def test_artifact_loader_retains_nested_names_and_diagnoses_corruption(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib/a.txt").write_text("evidence")
    assert ArtifactLoader._load_text_outputs(tmp_path) == {"lib/a.txt": "evidence"}
    bad = tmp_path / "bad.json"
    bad.write_text("{broken")
    with pytest.warns(UserWarning, match="Unreadable tool artifact"):
        assert ArtifactLoader._load_json(bad) is None


def test_html_badges_escape_external_labels():
    assert "<img" not in risk_badge("high", '<img src="file:///etc/passwd">')
    assert "<script" not in result_badge("<script>alert(1)</script>")


def test_android_component_inventory_prefers_known_empty_aapt2_data():
    from domain.post_scan.android.app_component import AppComponent

    inventory = AppComponent(
        {
            "aapt2_components": {"activities": []},
            "androguard_components": {"activities": [{"exported": True}]},
        }
    )
    assert inventory.activities == inventory.exported_activities == 0
    assert AppComponent.count_exported([{"exported": None, "intent_filters": ["launcher"]}]) == 0


def test_binary_file_metadata_does_not_require_original_input(tmp_path):
    from adapters.storage.store_to_file import StoreToFile
    from domain.post_scan.android.file_info import FileInfo
    from domain.post_scan.ios.binary.file_info import IOSFileInfo

    binary = tmp_path / "app.ipa"
    binary.write_bytes(b"original application archive")
    output = tmp_path / "out"
    StoreToFile(output).persist_scan_metadata(ScanConfig(binary, output, mode="binary"), output)
    saved = json.loads((output / "scan_metadata.json").read_text())
    binary.unlink()
    assert saved["file_info"]["size"] == str(len(b"original application archive"))
    for model in (FileInfo, IOSFileInfo):
        assert asdict(model({"scan_metadata": saved})) == saved["file_info"]


def test_invalid_saved_report_fails_without_running_tools(tmp_path, monkeypatch, capsys):
    source = tmp_path / "invalid.json"
    source.write_text("{}")
    monkeypatch.setattr(MobileAnalysisWorkflowService, "run", lambda *_: pytest.fail("Unexpected tool execution"))
    assert main(["report", str(source), "--pdf"]) == 1
    assert "Phoenix report failed:" in capsys.readouterr().err
    assert not source.with_suffix(".pdf").exists()

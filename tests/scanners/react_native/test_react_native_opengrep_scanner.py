import json
from pathlib import Path

from adapters.scanners.react_native import react_native_opengrep_scanner as scanner_module
from adapters.scanners.react_native.react_native_opengrep_scanner import ReactNativeOpenGrepScanner
from application import mobile_analysis_workflow_service as workflow
from domain.models import ScanConfig, ScanResult, ScanType


class FakeOpenGrepScanner:
    calls: list[tuple[Path, list[Path], ScanConfig]] = []

    def __init__(self, rules_path: Path | None = None, scan_paths: list[Path] | None = None) -> None:
        self.rules_path = rules_path or Path()
        self.scan_paths = scan_paths or []

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        self.calls.append((self.rules_path, self.scan_paths, config))
        rule_id = f"{self.rules_path.name}.rule"
        return [
            ScanResult(
                scanner_name="Fake OpenGrep",
                scan_type=ScanType.OPENGREP_SOURCE,
                raw_output=json.dumps(
                    {
                        "results": [{"check_id": rule_id, "path": str(self.scan_paths[0])}],
                        "errors": [],
                        "scan_metadata": {
                            "configured_rule_ids": [rule_id],
                            "tool_version": "test",
                        },
                    }
                ),
            )
        ]


def test_scopes_mobile_source_and_excludes_web(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    rules = tmp_path / "rules"
    for path in (project / "src", project / "web", project / "node_modules", project / "android", project / "ios"):
        path.mkdir(parents=True)
    for scope in ("react_native", "android", "ios"):
        (rules / scope).mkdir(parents=True)

    (project / "src" / "App.tsx").write_text("export default App", encoding="utf-8")
    (project / "src" / "Device.ios.ts").write_text("export default Device", encoding="utf-8")
    (project / "src" / "Browser.web.tsx").write_text("export default Browser", encoding="utf-8")
    (project / "web" / "page.tsx").write_text("export default Page", encoding="utf-8")
    (project / "node_modules" / "dependency.js").write_text("module.exports = {}", encoding="utf-8")

    FakeOpenGrepScanner.calls = []
    monkeypatch.setattr(scanner_module, "OpenGrepScanner", FakeOpenGrepScanner)
    scanner = ReactNativeOpenGrepScanner(
        rules / "react_native",
        android_rules_path=rules / "android",
        ios_rules_path=rules / "ios",
    )
    config = ScanConfig(project_path=project, output_path=tmp_path / "output", stack="REACT_NATIVE")

    result = scanner.scan(config)[0]
    report = json.loads(result.raw_output)

    assert result.success
    assert report["scan_metadata"]["status"] == "complete"
    assert {finding["phoenix_scope"] for finding in report["results"]} == {"react_native", "android", "ios"}
    assert [paths for _, paths, _ in FakeOpenGrepScanner.calls] == [
        [project.resolve()],
        [(project / "android").resolve()],
        [(project / "ios").resolve()],
    ]
    react_native_config = FakeOpenGrepScanner.calls[0][2]
    assert "android/**" in react_native_config.ignore_patterns
    assert "ios/**" in react_native_config.ignore_patterns
    assert "web/**" in react_native_config.ignore_patterns
    assert "**/*.web.tsx" in react_native_config.ignore_patterns


def test_web_only_project_does_not_run_opengrep(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    web = project / "web"
    web.mkdir(parents=True)
    (web / "App.tsx").write_text("export default App", encoding="utf-8")
    rules = tmp_path / "rules" / "react_native"
    rules.mkdir(parents=True)

    FakeOpenGrepScanner.calls = []
    monkeypatch.setattr(scanner_module, "OpenGrepScanner", FakeOpenGrepScanner)
    result = ReactNativeOpenGrepScanner(rules).scan(
        ScanConfig(project_path=project, output_path=tmp_path / "output", stack="REACT_NATIVE")
    )[0]
    report = json.loads(result.raw_output)

    assert not result.success
    assert report["scan_metadata"]["status"] == "failed"
    assert report["scan_metadata"]["scopes"]["react_native"]["status"] == "skipped"
    assert FakeOpenGrepScanner.calls == []


def test_applicable_native_scope_without_rules_makes_report_partial(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "App.tsx").write_text("export default App", encoding="utf-8")
    (project / "android").mkdir()
    react_native_rules = tmp_path / "rules" / "react_native"
    react_native_rules.mkdir(parents=True)

    FakeOpenGrepScanner.calls = []
    monkeypatch.setattr(scanner_module, "OpenGrepScanner", FakeOpenGrepScanner)
    scanner = ReactNativeOpenGrepScanner(
        react_native_rules,
        android_rules_path=tmp_path / "missing-android-rules",
    )

    result = scanner.scan(ScanConfig(project_path=project, output_path=tmp_path / "output"))[0]
    report = json.loads(result.raw_output)

    assert result.success
    assert report["scan_metadata"]["status"] == "partial"
    assert report["scan_metadata"]["scopes"]["react_native"]["status"] == "success"
    assert report["scan_metadata"]["scopes"]["android"]["status"] == "skipped"


def test_mobile_source_discovery_keeps_platform_files_and_drops_web_files(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source = project / "src"
    source.mkdir(parents=True)
    included = [source / "shared.ts", source / "screen.android.tsx", source / "screen.ios.tsx"]
    excluded = [source / "screen.web.tsx", source / "screen.test.tsx"]
    for path in [*included, *excluded]:
        path.write_text("export default {}", encoding="utf-8")

    discovered = ReactNativeOpenGrepScanner._mobile_source_files(project)

    assert discovered == sorted(included)


def test_workflow_selects_react_native_scoped_scanner(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    rules = tmp_path / "rules" / "react_native"
    rules.mkdir(parents=True)
    captured: dict[str, Path] = {}

    class RecordingScanner:
        def __init__(self, react_native_rules_path: Path) -> None:
            captured["rules_path"] = react_native_rules_path

        def scan(self, config: ScanConfig) -> list[ScanResult]:
            captured["project_path"] = config.project_path
            return []

    monkeypatch.setattr(workflow, "ReactNativeOpenGrepScanner", RecordingScanner)
    config = ScanConfig(
        project_path=project,
        output_path=tmp_path / "output",
        stack="REACT_NATIVE",
        opengrep_rules_path=rules,
    )

    results = workflow.MobileAnalysisWorkflowService()._perform_opengrep_scan(config, object())

    assert results == []
    assert captured == {"rules_path": rules, "project_path": project}

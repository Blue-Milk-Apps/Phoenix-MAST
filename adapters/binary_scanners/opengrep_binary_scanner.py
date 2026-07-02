"""OpenGrep scanner adapter for binary strings artifacts."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from adapters.source_code_scanners.opengrep_scanner import OpenGrepScanner
from domain.models import ScanConfig, ScanResult, ScanType
from utilities.apk_utils import extract_apk, is_apk_file, iter_apk_analysis_targets
from utilities.ipa_utils import extract_ipa, get_scanable_binary_paths, is_ipa_file
from utilities.path_utils import relative_result_path


class BinaryOpenGrepScanner(OpenGrepScanner):
    """Run OpenGrep over generated strings artifacts for binary scans."""

    REPORT_PATH = "opengrep_results.json"
    DEFAULT_MIN_LENGTH = 10

    @property
    def scan_type(self) -> ScanType:
        return ScanType.OPENGREP_BINARY

    @property
    def name(self) -> str:
        return "OpenGrep Binary Strings Scanner"

    @property
    def description(self) -> str:
        return "OpenGrep analysis over generated strings artifacts for binary targets."

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        rules_path = self._get_rules_path(config)
        if not rules_path:
            return [self._failure("No rules path found. Please configure rules_path in config.")]
        if not self._has_rule_files(rules_path):
            return [self._failure(f"No OpenGrep rule files found in: {rules_path}")]

        strings_executable = shutil.which("strings")
        if not strings_executable:
            return [self._failure("The 'strings' command is not installed on this system.")]

        scan_root = Path(tempfile.mkdtemp(prefix="appcritiq_opengrep_binary_"))
        cleanup_targets: list[object] = []
        try:
            targets, cleanup_targets, report_root = self._resolve_targets(config)
            generated = 0
            for file_path in targets:
                relative_target_path = self._strings_result_path(
                    relative_result_path(report_root or config.project_path, file_path)
                )
                result = subprocess.run(
                    [
                        strings_executable,
                        "-n",
                        str(self.DEFAULT_MIN_LENGTH),
                        "-a",
                        str(file_path),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != 0:
                    error_text = result.stderr.strip() if result.stderr else ""
                    return [self._failure(error_text or f"strings failed for {file_path}", result.stdout)]
                output = result.stdout.strip()
                if not output:
                    continue
                target = scan_root / relative_target_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(output, encoding="utf-8")
                generated += 1

            if generated == 0:
                return [self._failure("No strings artifacts were generated for binary OpenGrep input.")]

            opengrep_config = ScanConfig(
                project_path=scan_root,
                output_path=config.output_path,
                mode=config.mode,
                scan_label=config.scan_label,
                platform=config.platform,
                stack=config.stack,
                scanners=config.scanners,
                enabled_scans=config.enabled_scans,
                rules_path=rules_path,
                ignore_patterns=config.ignore_patterns,
                ignore_file=config.ignore_file,
                display_project_path=config.display_project_path,
            )
            results = super().scan(opengrep_config)
            for result in results:
                result.scan_type = self.scan_type
                result.scanner_name = self.name
                result.description = self.description
            return results
        finally:
            shutil.rmtree(scan_root, ignore_errors=True)
            for cleanup_target in cleanup_targets:
                cleanup_target.cleanup()

    def _resolve_targets(
        self, config: ScanConfig
    ) -> tuple[list[Path], list[object], Path | None]:
        target = config.project_path
        cleanup_targets: list[object] = []

        if target.is_file():
            if is_ipa_file(target):
                extracted = extract_ipa(target)
                cleanup_targets.append(extracted)
                return (
                    get_scanable_binary_paths(extracted),
                    cleanup_targets,
                    extracted.app_bundle,
                )
            if is_apk_file(target):
                extracted = extract_apk(target)
                cleanup_targets.append(extracted)
                return (
                    iter_apk_analysis_targets(extracted),
                    cleanup_targets,
                    extracted.temp_dir,
                )
            return [target], cleanup_targets, None

        for path in sorted(target.rglob("*")):
            if not path.is_file():
                continue
            if is_ipa_file(path):
                extracted = extract_ipa(path)
                cleanup_targets.append(extracted)
                return (
                    get_scanable_binary_paths(extracted),
                    cleanup_targets,
                    extracted.app_bundle,
                )
            if is_apk_file(path):
                extracted = extract_apk(path)
                cleanup_targets.append(extracted)
                return (
                    iter_apk_analysis_targets(extracted),
                    cleanup_targets,
                    extracted.temp_dir,
                )

        raise ValueError("Binary path did not contain an IPA or APK file.")

    def _strings_result_path(self, relative_path: str) -> str:
        return Path(relative_path).with_suffix(".txt").as_posix()

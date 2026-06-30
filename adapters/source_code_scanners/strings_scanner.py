"""Strings scanner adapter for extracting strings from binary targets."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.apk_utils import extract_apk, is_apk_file, iter_apk_analysis_targets
from utilities.ipa_utils import extract_ipa, get_scanable_binary_paths, is_ipa_file
from utilities.path_utils import relative_result_path


class StringsScanner(ScannerPort):
    """Scanner for extracting strings from binary files."""

    DEFAULT_MIN_LENGTH = 10

    @property
    def scan_type(self) -> ScanType:
        return ScanType.STRINGS

    @property
    def name(self) -> str:
        return "Strings Extractor"

    @property
    def description(self) -> str:
        return "Raw strings extracted from files in the target project."

    def is_available(self) -> bool:
        return shutil.which("strings") is not None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        cleanup_targets: list[object] = []

        strings_executable = shutil.which("strings")
        if not strings_executable:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message="The 'strings' command is not installed on this system.",
                )
            ]

        try:
            targets, cleanup_targets, report_root = self._resolve_targets(config)
            scan_results: list[ScanResult] = []
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
                    return [
                        ScanResult(
                            scanner_name=self.name,
                            scan_type=self.scan_type,
                            success=False,
                            error_message=error_text
                            or f"strings failed for {file_path}",
                            raw_output=result.stdout,
                            relative_target_path=relative_target_path,
                        )
                    ]

                output = result.stdout.strip()
                if output:
                    scan_results.append(
                        ScanResult(
                            scanner_name=self.name,
                            scan_type=self.scan_type,
                            success=True,
                            raw_output=output,
                            description=self.description,
                            relative_target_path=relative_target_path,
                        )
                    )

            return scan_results
        except Exception as exc:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=str(exc),
                )
            ]
        finally:
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

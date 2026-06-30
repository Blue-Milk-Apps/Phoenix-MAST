"""OWASP Dependency Check scanner adapter."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort

REPORT_PATH = "dependency-check-report.json"


class DependencyCheckScanner(ScannerPort):
    """Scanner for vulnerable dependencies using OWASP Dependency Check."""

    PROJECT_ENV_FILE_NAME = ".env"
    DEFAULT_CONTAINER_DATA_DIR = Path("/opt/dependency-check/data")
    DATA_DIR_ENV_NAME = "DEPENDENCY_CHECK_DATA_DIR"

    @property
    def scan_type(self) -> ScanType:
        return ScanType.DEPENDENCY_CHECK

    @property
    def name(self) -> str:
        return "OWASP Dependency Check Scanner"

    @property
    def description(self) -> str:
        return (
            "Known vulnerabilities in third-party dependencies identified by cross-referencing "
            "the National Vulnerability Database (NVD). The native report includes CVE identifiers "
            "and CVSS severity scores."
        )

    def is_available(self) -> bool:
        return shutil.which("dependency-check") is not None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        output_dir = Path(tempfile.mkdtemp(prefix="phoenix_dependency_check_"))
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "dependency-check-report.json"

        cmd = [
            "dependency-check",
            "--scan",
            str(config.project_path),
            "--format",
            "JSON",
            "--format",
            "HTML",
            "--out",
            str(output_dir),
            "--project",
            config.project_path.name,
            "--disableBundleAudit",  # no ruby scan
            "--disableYarnAudit",
            "--disableNodeAudit",
            "--disableAssembly",
            "--enableExperimental",
            "--noupdate",
        ]

        data_dir = self._resolve_data_directory(config)
        if data_dir:
            cmd.extend(["--data", str(data_dir)])

        try:
            process = subprocess.Popen(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            for line in process.stdout:
                clean_line = line.replace("\r", "").strip()
                # Skip per-file "Analyzing: /path/to/file" lines; they are too verbose.
                if not clean_line or "Analyzing: " in clean_line:
                    continue
                print(f"{ScannerPort.format_stdout_prefix(self.scan_type)}{clean_line}")

            process.wait()

            if process.returncode != 0:
                error_message = f"Dependency Check error: {process.returncode}"
                return [
                    ScanResult(
                        scanner_name=self.name,
                        scan_type=self.scan_type,
                        success=False,
                        error_message=error_message,
                        raw_output=self._error_report(
                            error_message, self._read_report(output_file)
                        ),
                        relative_target_path=REPORT_PATH,
                    )
                ]

            # Find the actual JSON report file (name may vary by version)
            actual_file = self._find_report_file(output_dir, output_file)

            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=True,
                    raw_output=self._json_report(self._read_report(actual_file)),
                    relative_target_path=REPORT_PATH,
                    description=self.description,
                )
            ]
        except Exception as e:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=str(e),
                    raw_output=self._error_report(
                        str(e), self._read_report(output_file)
                    ),
                    relative_target_path=REPORT_PATH,
                )
            ]
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)

    @staticmethod
    def _find_report_file(output_dir: Path, default: Path) -> Path:
        """Locate the JSON report file in the output directory."""
        if default.exists():
            return default
        # Search for any JSON file the tool may have written
        json_files = sorted(output_dir.glob("*.json"))
        if json_files:
            return json_files[0]
        return default

    @staticmethod
    def _read_report(report_file: Path) -> str:
        if report_file.exists():
            return report_file.read_text(encoding="utf-8")
        return ""

    @staticmethod
    def _json_report(raw_output: str) -> str:
        if not raw_output.strip():
            return "{}"
        return json.dumps(json.loads(raw_output), sort_keys=True)

    def _error_report(self, error_message: str, raw_output: str = "") -> str:
        report: dict[str, object] = {
            "error": error_message,
            "success": False,
        }
        if raw_output.strip():
            try:
                report["raw_output"] = json.loads(raw_output)
            except json.JSONDecodeError:
                report["raw_output"] = raw_output
        return json.dumps(report, indent=2, sort_keys=True)

    def _resolve_data_directory(self, config: ScanConfig) -> Path | None:
        # 1. System Environment Variable (Highest Priority)
        env_data_dir = os.environ.get(self.DATA_DIR_ENV_NAME, "").strip()
        if env_data_dir:
            return Path(env_data_dir).expanduser().resolve()

        # 2. Check for .env in the CURRENT WORKING DIRECTORY (The Calling Dir)
        cwd = Path.cwd()
        cwd_env_val = self._env_file_value(cwd, self.DATA_DIR_ENV_NAME)
        if cwd_env_val:
            return self._env_file_path(cwd, cwd_env_val).resolve()

        # 3. Check for .env in the PROJECT PATH (The Scanned Dir)
        project_env_val = self._env_file_value(
            config.project_path, self.DATA_DIR_ENV_NAME
        )
        if project_env_val:
            return self._env_file_path(config.project_path, project_env_val).resolve()

        # 4. Fallback: If 'owasp-data' exists in CWD, just use it!
        # This fixes the issue without needing an .env at all
        cwd_fallback = cwd / "nvd-owasp-data"
        if cwd_fallback.exists() and cwd_fallback.is_dir():
            return cwd_fallback.resolve()

        # 5. Docker Fallback
        if os.environ.get("DC_NO_UPDATE", "").strip() == "1":
            return self.DEFAULT_CONTAINER_DATA_DIR

        return None

    def _env_file_value(self, project_path: Path, key: str) -> str:
        env_file = project_path / self.PROJECT_ENV_FILE_NAME
        if not env_file.is_file():
            return ""

        for raw_line in env_file.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line.removeprefix("export ").strip()
            name, separator, value = line.partition("=")
            if separator and name.strip() == key:
                return self._normalize_env_value(value)

        return ""

    @staticmethod
    def _normalize_env_value(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1]
        return value

    @staticmethod
    def _env_file_path(project_path: Path, value: str) -> Path:
        path = Path(value).expanduser()
        if path.is_absolute():
            return path.resolve()
        # Adding .resolve() here is critical for matching OS strings
        return (project_path / path).resolve()

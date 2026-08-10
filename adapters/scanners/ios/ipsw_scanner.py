"""iOS ipsw scanner adapter for IPA Mach-O metadata extraction."""

from __future__ import annotations

import json
import plistlib
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.ipa_utils import (
    ExtractedIPA,
    classify_ipa_binary,
    extract_ipa,
    find_ipa_in_directory,
    get_scanable_binary_paths,
    is_ipa_file,
)
from utilities.json_utils import json_safe
from utilities.path_utils import relative_result_path


@dataclass(frozen=True)
class IpswCommandResult:
    purpose: str
    argv: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    execution_status: str
    duration_seconds: float
    error_message: str = ""


class IpswScanner(ScannerPort):
    """Scanner for Mach-O metadata extracted from IPA binaries using ipsw."""

    COMMAND_PROFILE = "IPSW_MACHO_INFO_V1"
    DEFAULT_TIMEOUT_SECONDS = 120
    MAX_COMMAND_OUTPUT_EXCERPT_CHARS = 4000
    SCANNER_VERSION = "1.0"
    SCHEMA_VERSION = "1.0"

    @property
    def scan_type(self) -> ScanType:
        return ScanType.IPSW

    @property
    def name(self) -> str:
        return "ipsw Mach-O Analyzer"

    @property
    def description(self) -> str:
        return "Mach-O metadata extracted from IPA binaries using ipsw."

    def is_available(self) -> bool:
        return shutil.which("ipsw") is not None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        extracted = config.extracted_binary if isinstance(config.extracted_binary, ExtractedIPA) else None
        owns_extraction = extracted is None
        target_path = self._resolve_ipa_path(config.project_path) if extracted is None else None
        if extracted is None and target_path is None:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="ipsw only runs on IPA files.",
                )
            ]

        ipsw_executable = shutil.which("ipsw")
        if not ipsw_executable:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="The 'ipsw' command is not installed on this system.",
                )
            ]

        try:
            if extracted is None:
                extracted = extract_ipa(target_path)
            app_info = self._build_app_info(extracted)
            ipsw_version = self._ipsw_version(ipsw_executable)
            scan_results: list[ScanResult] = []

            for binary_path in get_scanable_binary_paths(extracted):
                binary_relative_path = relative_result_path(
                    extracted.app_bundle,
                    binary_path,
                )
                scan_document = self._build_scan_document(
                    ipsw_executable=ipsw_executable,
                    extracted=extracted,
                    binary_path=binary_path,
                    app_info=app_info,
                    ipsw_version=ipsw_version,
                )
                scan_results.append(
                    ScanResult(
                        scanner_name=self.name,
                        scan_type=self.scan_type,
                        success=self._scan_document_succeeded(scan_document),
                        error_message=self._error_message(scan_document),
                        raw_output=json.dumps(
                            json_safe(scan_document),
                            indent=2,
                            sort_keys=True,
                        )
                        + "\n",
                        description=self.description,
                        relative_target_path=Path(binary_relative_path).with_suffix(".json").as_posix(),
                    )
                )

            return scan_results
        except ValueError as exc:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=str(exc),
                )
            ]
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
            if owns_extraction and extracted is not None:
                extracted.cleanup()

    def _resolve_ipa_path(self, project_path: Path) -> Path | None:
        if project_path.is_file():
            if project_path.suffix.lower() == ".apk":
                return None
            return project_path if is_ipa_file(project_path) else None
        return find_ipa_in_directory(project_path)

    def _build_scan_document(
        self,
        ipsw_executable: str,
        extracted: ExtractedIPA,
        binary_path: Path,
        app_info: dict[str, Any],
        ipsw_version: str,
    ) -> dict[str, Any]:
        command_results = [
            self._run_ipsw(
                ipsw_executable,
                "macho_info_json",
                ["macho", "info", str(binary_path), "--json"],
            ),
            self._run_ipsw(
                ipsw_executable,
                "code_signature",
                ["macho", "info", str(binary_path), "--sig"],
            ),
            self._run_ipsw(
                ipsw_executable,
                "entitlements",
                ["macho", "info", str(binary_path), "--ent"],
            ),
        ]
        binary_relative_path = relative_result_path(extracted.app_bundle, binary_path)

        return {
            "schema_version": self.SCHEMA_VERSION,
            "scanner": {
                "name": "phoenix-ipsw",
                "version": self.SCANNER_VERSION,
            },
            "app_info": app_info,
            "binary": {
                "kind": classify_ipa_binary(extracted, binary_path),
                "name": binary_path.name,
                "path": binary_relative_path,
            },
            "scan_metadata": {
                "execution_status": self._execution_status(command_results),
                "duration_seconds": round(
                    sum(result.duration_seconds for result in command_results),
                    6,
                ),
                "ipsw_version": ipsw_version,
                "command_profile": self.COMMAND_PROFILE,
                "tool_exit_codes": {result.purpose: result.exit_code for result in command_results},
            },
            "analysis": self._analysis_document(command_results),
            "commands": [self._command_document(result) for result in command_results],
        }

    def _run_ipsw(
        self,
        ipsw_executable: str,
        purpose: str,
        args: list[str],
    ) -> IpswCommandResult:
        argv = [ipsw_executable, *args]
        started = time.perf_counter()
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.DEFAULT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            return IpswCommandResult(
                purpose=purpose,
                argv=self._display_argv(args),
                exit_code=None,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                execution_status="TIMEOUT",
                duration_seconds=time.perf_counter() - started,
                error_message="ipsw timed out.",
            )
        except KeyboardInterrupt:
            return IpswCommandResult(
                purpose=purpose,
                argv=self._display_argv(args),
                exit_code=None,
                stdout="",
                stderr="",
                execution_status="INTERRUPTED",
                duration_seconds=time.perf_counter() - started,
                error_message="ipsw was interrupted.",
            )
        except Exception as exc:
            return IpswCommandResult(
                purpose=purpose,
                argv=self._display_argv(args),
                exit_code=None,
                stdout="",
                stderr=str(exc),
                execution_status="TOOL_ERROR",
                duration_seconds=time.perf_counter() - started,
                error_message=str(exc),
            )

        if result.returncode == 0:
            execution_status = "SUCCESS"
        elif result.stdout or result.stderr:
            execution_status = "PARTIAL_SUCCESS"
        else:
            execution_status = "TOOL_ERROR"

        return IpswCommandResult(
            purpose=purpose,
            argv=self._display_argv(args),
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            execution_status=execution_status,
            duration_seconds=time.perf_counter() - started,
        )

    @staticmethod
    def _display_argv(args: list[str]) -> list[str]:
        return [
            "ipsw",
            *["<binary>" if Path(arg).is_absolute() else arg for arg in args],
        ]

    def _command_document(self, command_result: IpswCommandResult) -> dict[str, Any]:
        document: dict[str, Any] = {
            "purpose": command_result.purpose,
            "argv": command_result.argv,
            "exit_code": command_result.exit_code,
            "execution_status": command_result.execution_status,
            "duration_seconds": round(command_result.duration_seconds, 6),
            "error_message": command_result.error_message,
        }
        if command_result.execution_status != "SUCCESS" and command_result.stdout:
            document["stdout_excerpt"] = self._excerpt(command_result.stdout)
        if command_result.stderr:
            document["stderr_excerpt"] = self._excerpt(command_result.stderr)
        return document

    def _analysis_document(self, command_results: list[IpswCommandResult]) -> dict[str, Any]:
        commands_by_purpose = {result.purpose: result for result in command_results}
        return {
            "macho": self._macho_summary(commands_by_purpose.get("macho_info_json")),
            "code_signature": self._code_signature_summary(commands_by_purpose.get("code_signature")),
            "entitlements": self._entitlements_summary(commands_by_purpose.get("entitlements")),
        }

    def _macho_summary(self, command_result: IpswCommandResult | None) -> dict[str, Any]:
        if command_result is None or not command_result.stdout.strip():
            return {}
        data = self._json_object(command_result.stdout)
        if not isinstance(data, dict):
            return {"parse_status": "UNPARSED"}

        header = data.get("header")
        summary: dict[str, Any] = {
            "parse_status": "PARSED",
            "header": self._selected_mapping(
                header if isinstance(header, dict) else {},
                {
                    "type",
                    "filetype",
                    "cpu",
                    "cputype",
                    "subcpu",
                    "cpusubtype",
                    "flags",
                },
            ),
            "load_commands": self._unique_limited(
                value
                for value in self._collect_values(data, {"cmd", "command", "name"})
                if str(value).startswith("LC_")
            ),
            "linked_dylibs": self._unique_limited(
                value
                for value in self._collect_values(data, {"name", "path", "dylib"})
                if ".dylib" in str(value) or str(value).startswith(("@rpath/", "/usr/lib/"))
            ),
            "rpaths": self._unique_limited(
                value
                for value in self._collect_values(data, {"path"})
                if str(value).startswith(("@rpath", "@loader_path", "@executable_path"))
            ),
            "platform": self._selected_mapping(
                self._flatten_first_mapping(data, {"platform", "build_version", "version_min"}),
                {"platform", "minos", "sdk", "ntools"},
            ),
        }
        return {key: value for key, value in summary.items() if value not in ({}, [])}

    def _code_signature_summary(self, command_result: IpswCommandResult | None) -> dict[str, Any]:
        if command_result is None or not command_result.stdout.strip():
            return {}

        lines = [line.strip() for line in command_result.stdout.splitlines() if line.strip()]
        team_identifier = self._first_regex_match(
            lines,
            (
                r"\bTeamIdentifier\s*=\s*([A-Z0-9]+)",
                r"\bTeam\s*Identifier\s*:\s*([A-Z0-9]+)",
                r"\bTeamID\s*[:=]\s*([A-Z0-9]+)",
            ),
        )
        signing_identifier = self._first_regex_match(
            lines,
            (
                r"\bIdentifier\s*=\s*([^\s]+)",
                r"\bSigning Identifier\s*:\s*([^\s]+)",
            ),
        )
        cdhashes = self._unique_limited(
            match for line in lines for match in re.findall(r"\bCDHash\s*=\s*([A-Fa-f0-9]+)", line)
        )
        authorities = self._unique_limited(
            line.split("=", 1)[1].strip() if "=" in line else line
            for line in lines
            if "Authority=" in line or line.lower().startswith(("authority:", "certificate"))
        )

        return {
            "present": True,
            "team_identifier": team_identifier,
            "signing_identifier": signing_identifier,
            "cdhashes": cdhashes,
            "authorities": authorities,
            "line_count": len(lines),
            "raw_output_omitted": True,
        }

    def _entitlements_summary(self, command_result: IpswCommandResult | None) -> dict[str, Any]:
        if command_result is None or not command_result.stdout.strip():
            return {}

        entitlements = self._plist_object(command_result.stdout)
        if isinstance(entitlements, dict):
            keys = sorted(str(key) for key in entitlements)
            return {
                "parse_status": "PARSED",
                "keys": keys,
                "values": json_safe(entitlements),
                "has_private_entitlements": any(self._is_private_entitlement(key) for key in keys),
                "raw_output_omitted": True,
            }

        keys = sorted(set(re.findall(r"<key>([^<]+)</key>", command_result.stdout)))
        return {
            "parse_status": "KEYS_ONLY" if keys else "UNPARSED",
            "keys": keys,
            "has_private_entitlements": any(self._is_private_entitlement(key) for key in keys),
            "raw_output_omitted": True,
        }

    @classmethod
    def _excerpt(cls, value: str) -> str:
        return value[: cls.MAX_COMMAND_OUTPUT_EXCERPT_CHARS]

    @staticmethod
    def _json_object(value: str) -> Any:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _plist_object(value: str) -> Any:
        try:
            return plistlib.loads(value.encode("utf-8"))
        except Exception:
            return None

    @staticmethod
    def _selected_mapping(mapping: dict[str, Any], keys: set[str]) -> dict[str, Any]:
        return {key: json_safe(mapping[key]) for key in sorted(keys) if key in mapping}

    @classmethod
    def _flatten_first_mapping(cls, value: Any, keys: set[str]) -> dict[str, Any]:
        if isinstance(value, dict):
            if any(key in value for key in keys):
                return value
            for item in value.values():
                found = cls._flatten_first_mapping(item, keys)
                if found:
                    return found
        if isinstance(value, list):
            for item in value:
                found = cls._flatten_first_mapping(item, keys)
                if found:
                    return found
        return {}

    @classmethod
    def _collect_values(cls, value: Any, keys: set[str]) -> list[str]:
        values: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                if key in keys and isinstance(item, str):
                    values.append(item)
                values.extend(cls._collect_values(item, keys))
        elif isinstance(value, list):
            for item in value:
                values.extend(cls._collect_values(item, keys))
        return values

    @staticmethod
    def _unique_limited(values: Any, limit: int = 25) -> list[str]:
        unique: list[str] = []
        for value in values:
            clean_value = str(value).strip()
            if not clean_value or clean_value in unique:
                continue
            unique.append(clean_value)
            if len(unique) >= limit:
                break
        return unique

    @staticmethod
    def _first_regex_match(lines: list[str], patterns: tuple[str, ...]) -> str:
        for line in lines:
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    return match.group(1)
        return ""

    @staticmethod
    def _is_private_entitlement(key: str) -> bool:
        return key.startswith("com.apple.private.") or key.startswith("com.apple.rootless.")

    def _ipsw_version(self, ipsw_executable: str) -> str:
        try:
            result = subprocess.run(
                [ipsw_executable, "version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except Exception:
            return ""
        return result.stdout.strip() or result.stderr.strip()

    @staticmethod
    def _build_app_info(extracted: ExtractedIPA) -> dict[str, Any]:
        if not extracted.info_plist:
            return {}

        return {
            "bundle_id": extracted.info_plist.get("CFBundleIdentifier", ""),
            "bundle_name": extracted.info_plist.get("CFBundleName", ""),
            "bundle_version": extracted.info_plist.get("CFBundleVersion", ""),
            "short_version": extracted.info_plist.get("CFBundleShortVersionString", ""),
            "minimum_os": extracted.info_plist.get("MinimumOSVersion", ""),
            "executable_name": extracted.info_plist.get("CFBundleExecutable", ""),
        }

    @staticmethod
    def _execution_status(command_results: list[IpswCommandResult]) -> str:
        statuses = {result.execution_status for result in command_results}
        if statuses & {"TIMEOUT", "TOOL_ERROR", "INTERRUPTED"}:
            return "TOOL_ERROR"
        if statuses == {"SUCCESS"}:
            return "SUCCESS"
        return "PARTIAL_SUCCESS"

    @staticmethod
    def _scan_document_succeeded(scan_document: dict[str, Any]) -> bool:
        return scan_document["scan_metadata"]["execution_status"] != "TOOL_ERROR"

    @staticmethod
    def _error_message(scan_document: dict[str, Any]) -> str:
        execution_status = scan_document["scan_metadata"]["execution_status"]
        if execution_status != "TOOL_ERROR":
            return ""

        command_errors = [
            command.get("error_message") or command.get("stderr") or f"{command.get('purpose', 'ipsw')} failed."
            for command in scan_document["commands"]
            if command.get("execution_status") in {"TIMEOUT", "TOOL_ERROR", "INTERRUPTED"}
        ]
        if command_errors:
            return "; ".join(str(error).strip() for error in command_errors if error)
        return "ipsw metadata extraction failed."

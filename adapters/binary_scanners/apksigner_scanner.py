"""Apksigner scanner adapter for APK signing evidence extraction."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.apk_utils import find_apk_in_directory, is_apk_file


@dataclass(frozen=True)
class ApksignerCommandResult:
    exit_code: int | None
    stdout: str
    stderr: str
    execution_status: str
    duration_seconds: float
    error_message: str = ""


class ApksignerScanner(ScannerPort):
    """Scanner for normalized APK signing and signer identity evidence."""

    COMMAND_PROFILE = "VERIFY_VERBOSE_CERTS_V1"
    EXTRACTOR_VERSION = "1.0"
    SCHEMA_VERSION = "1.0"
    DEFAULT_TIMEOUT_SECONDS = 120

    SCHEME_PATTERN = re.compile(
        r"Verified using v(?P<version>[1-4]) scheme.*:\s*(?P<value>true|false)",
        re.IGNORECASE,
    )
    SIGNER_FIELD_PATTERN = re.compile(r"Signer #(?P<index>\d+) (?P<field>.+?):\s*(?P<value>.*)")

    @property
    def scan_type(self) -> ScanType:
        return ScanType.APKSIGNER

    @property
    def name(self) -> str:
        return "Apksigner Evidence Extractor"

    @property
    def description(self) -> str:
        return "Normalized APK signing integrity and signer identity evidence."

    def is_available(self) -> bool:
        return shutil.which("apksigner") is not None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        apk_path = self._resolve_apk_path(config.project_path)
        if apk_path is None:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="Apksigner only runs on APK files.",
                )
            ]

        apksigner_executable = shutil.which("apksigner")
        if not apksigner_executable:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="The 'apksigner' command is not installed on this system.",
                )
            ]

        command_result = self._run_verify(apksigner_executable, apk_path)
        version = self._apksigner_version(apksigner_executable)
        evidence = self._build_evidence(apk_path, version, command_result)
        return self._scan_results(evidence, command_result)

    def _resolve_apk_path(self, project_path: Path) -> Path | None:
        if project_path.is_file():
            return project_path if is_apk_file(project_path) else None
        return find_apk_in_directory(project_path)

    def _run_verify(
        self,
        apksigner_executable: str,
        apk_path: Path,
    ) -> ApksignerCommandResult:
        started = time.perf_counter()
        try:
            result = subprocess.run(
                [
                    apksigner_executable,
                    "verify",
                    "--verbose",
                    "--print-certs",
                    str(apk_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=self.DEFAULT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            return ApksignerCommandResult(
                exit_code=None,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                execution_status="TIMEOUT",
                duration_seconds=time.perf_counter() - started,
                error_message="apksigner timed out.",
            )
        except KeyboardInterrupt:
            return ApksignerCommandResult(
                exit_code=None,
                stdout="",
                stderr="",
                execution_status="INTERRUPTED",
                duration_seconds=time.perf_counter() - started,
                error_message="apksigner was interrupted.",
            )
        except Exception as exc:
            return ApksignerCommandResult(
                exit_code=None,
                stdout="",
                stderr=str(exc),
                execution_status="TOOL_ERROR",
                duration_seconds=time.perf_counter() - started,
                error_message=str(exc),
            )

        status = "SUCCESS"
        if result.returncode != 0 and (result.stdout or result.stderr):
            status = "PARTIAL_SUCCESS"
        elif result.returncode != 0:
            status = "TOOL_ERROR"

        return ApksignerCommandResult(
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            execution_status=status,
            duration_seconds=time.perf_counter() - started,
        )

    def _apksigner_version(self, apksigner_executable: str) -> str:
        for command in (
            [apksigner_executable, "version"],
            [apksigner_executable, "--version"],
        ):
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
            except Exception:
                continue
            output = result.stdout.strip() or result.stderr.strip()
            if output:
                return output
        return ""

    def _build_evidence(
        self,
        apk_path: Path,
        apksigner_version: str,
        command_result: ApksignerCommandResult,
    ) -> dict[str, Any]:
        output = self._combined_output(command_result)
        parser_errors: list[str] = []
        schemes = self._signature_schemes(output)
        signers = self._signers(output, parser_errors)
        overall_status = self._overall_status(command_result, output, schemes)
        structural_integrity = self._structural_integrity(command_result, output)

        if command_result.execution_status == "SUCCESS" and output and not schemes and not signers:
            parser_errors.append("No signature schemes or signer certificates parsed.")
            execution_status = "PARSING_ERROR"
        else:
            execution_status = command_result.execution_status

        return {
            "schema_version": self.SCHEMA_VERSION,
            "extractor": {
                "name": "appcritiq-apksigner",
                "version": self.EXTRACTOR_VERSION,
            },
            "apk": self._apk_identity(apk_path),
            "extraction_metadata": {
                "execution_status": execution_status,
                "duration_seconds": round(command_result.duration_seconds, 6),
                "apksigner_version": apksigner_version,
                "command_profile": self.COMMAND_PROFILE,
                "tool_exit_code": command_result.exit_code,
                "parser_errors": parser_errors,
            },
            "command_profile": {
                "name": self.COMMAND_PROFILE,
                "commands": [
                    {
                        "purpose": "verify_signatures",
                        "argv": [
                            "apksigner",
                            "verify",
                            "--verbose",
                            "--print-certs",
                            "<apk>",
                        ],
                    }
                ],
            },
            "verification": {
                "overall_status": overall_status,
                "structural_integrity": structural_integrity,
                "verified_using_v1_scheme": self._scheme_verified(schemes, "v1"),
                "verified_using_v2_scheme": self._scheme_verified(schemes, "v2"),
                "verified_using_v3_scheme": self._scheme_verified(schemes, "v3"),
                "verified_using_v4_scheme": self._scheme_verified(schemes, "v4"),
            },
            "signature_schemes": self._signature_scheme_document(schemes),
            "signers": signers,
            "lineage": {
                "lineage_state": "UNKNOWN",
                "signing_certificate_rotation_detected": None,
                "nodes": [],
                "raw_references": {},
            },
            "trust_relationships": self._trust_relationships(signers),
            "enrichment": {
                "signer_classification": "UNKNOWN",
                "known_signer_id": None,
                "expected_signer_match": None,
                "source": None,
            },
            "raw_evidence": {
                "stdout": "raw/apksigner_verify_stdout.txt" if command_result.stdout else None,
                "stderr": "raw/apksigner_verify_stderr.txt" if command_result.stderr else None,
                "certificates": [],
                "signing_block": None,
            },
        }

    def _apk_identity(self, apk_path: Path) -> dict[str, Any]:
        return {
            "file_name": apk_path.name,
            "sha256": self._sha256(apk_path),
            "size_bytes": apk_path.stat().st_size,
            "package_name": None,
            "version_code": None,
            "version_name": None,
        }

    def _signature_schemes(
        self,
        output: str,
    ) -> dict[str, str]:
        schemes: dict[str, str] = {}
        for match in self.SCHEME_PATTERN.finditer(output):
            scheme = f"v{match.group('version')}"
            verified = match.group("value").lower() == "true"
            schemes[scheme] = "VERIFIED" if verified else "MISSING"
        return schemes

    def _signature_scheme_document(
        self,
        schemes: dict[str, str],
    ) -> dict[str, dict[str, str]]:
        return {
            scheme: {
                "state": schemes.get(scheme, "UNKNOWN"),
                "source": "apksigner_verbose",
            }
            for scheme in ("v1", "v2", "v3", "v4")
        }

    def _scheme_verified(
        self,
        schemes: dict[str, str],
        scheme: str,
    ) -> bool | None:
        state = schemes.get(scheme)
        if state is None:
            return None
        return state == "VERIFIED"

    def _signers(
        self,
        output: str,
        parser_errors: list[str],
    ) -> list[dict[str, Any]]:
        by_index: dict[int, dict[str, Any]] = {}
        for line in output.splitlines():
            match = self.SIGNER_FIELD_PATTERN.search(line.strip())
            if not match:
                continue

            index = int(match.group("index"))
            field = self._normalize_label(match.group("field"))
            value = match.group("value").strip()
            signer = by_index.setdefault(index, self._empty_signer(index))
            self._apply_signer_field(signer, field, value)

        signers = [by_index[index] for index in sorted(by_index)]
        if "Number of signers:" in output and not signers:
            parser_errors.append("Signer count was present but no signer fields parsed.")
        return signers

    def _empty_signer(self, index: int) -> dict[str, Any]:
        return {
            "signer_index": index,
            "certificate": {
                "subject_dn": None,
                "issuer_dn": None,
                "serial_number": None,
                "not_before": None,
                "not_after": None,
                "sha256": None,
                "sha1": None,
                "md5": None,
                "public_key_algorithm": "UNKNOWN",
                "public_key_size_bits": None,
                "signature_algorithm": "UNKNOWN",
            },
            "public_key": {
                "algorithm": "UNKNOWN",
                "size_bits": None,
                "sha256": None,
            },
            "raw_references": {
                "certificate_der": None,
            },
        }

    def _apply_signer_field(
        self,
        signer: dict[str, Any],
        field: str,
        value: str,
    ) -> None:
        certificate = signer["certificate"]
        public_key = signer["public_key"]

        if field == "certificate_dn":
            certificate["subject_dn"] = value
        elif field == "certificate_sha_256_digest":
            certificate["sha256"] = self._normalize_fingerprint(value)
        elif field == "certificate_sha_1_digest":
            certificate["sha1"] = self._normalize_fingerprint(value)
        elif field == "certificate_md5_digest":
            certificate["md5"] = self._normalize_fingerprint(value)
        elif field == "key_algorithm":
            algorithm = self._public_key_algorithm(value)
            certificate["public_key_algorithm"] = algorithm
            public_key["algorithm"] = algorithm
        elif field == "key_size_bits":
            size = self._parse_int(value)
            certificate["public_key_size_bits"] = size
            public_key["size_bits"] = size
        elif field == "public_key_sha_256_digest":
            public_key["sha256"] = self._normalize_fingerprint(value)
        elif field in {"certificate_signature_algorithm", "signature_algorithm"}:
            certificate["signature_algorithm"] = self._signature_algorithm(value)
        elif field == "certificate_subject":
            certificate["subject_dn"] = value
        elif field == "certificate_issuer":
            certificate["issuer_dn"] = value
        elif field == "certificate_serial_number":
            certificate["serial_number"] = value

    def _overall_status(
        self,
        command_result: ApksignerCommandResult,
        output: str,
        schemes: dict[str, str],
    ) -> str:
        if command_result.execution_status in {
            "TIMEOUT",
            "TOOL_ERROR",
            "INTERRUPTED",
        }:
            return "TOOL_ERROR"
        if command_result.exit_code == 0:
            return "VERIFIED"
        lowered = output.lower()
        if any(phrase in lowered for phrase in ("does not verify", "failed to verify")):
            return "FAILED"
        if schemes:
            return "PARTIAL"
        return "INCONCLUSIVE"

    def _structural_integrity(
        self,
        command_result: ApksignerCommandResult,
        output: str,
    ) -> str:
        if command_result.exit_code == 0:
            return "VALID"
        lowered = output.lower()
        if "truncated" in lowered:
            return "TRUNCATED"
        if "malformed" in lowered:
            return "MALFORMED"
        if "corrupt" in lowered:
            return "CORRUPTED"
        if any(phrase in lowered for phrase in ("failed to parse", "not a valid apk", "zip end of central")):
            return "UNPARSEABLE"
        return "UNKNOWN"

    def _trust_relationships(self, signers: list[dict[str, Any]]) -> dict[str, Any]:
        if not signers:
            return {
                "certificate_chain_length": None,
                "self_signed": None,
                "issuer_subject_match": None,
            }

        certificate = signers[0]["certificate"]
        issuer = certificate.get("issuer_dn")
        subject = certificate.get("subject_dn")
        issuer_subject_match = issuer == subject if issuer is not None and subject is not None else None
        return {
            "certificate_chain_length": len(signers),
            "self_signed": issuer_subject_match,
            "issuer_subject_match": issuer_subject_match,
        }

    def _scan_results(
        self,
        evidence: dict[str, Any],
        command_result: ApksignerCommandResult,
    ) -> list[ScanResult]:
        execution_status = evidence["extraction_metadata"]["execution_status"]
        extractor_success = execution_status not in {
            "TIMEOUT",
            "TOOL_ERROR",
            "PARSING_ERROR",
            "INTERRUPTED",
        }
        error_message = (
            ""
            if extractor_success
            else (
                command_result.error_message or command_result.stderr.strip() or "apksigner evidence extraction failed."
            )
        )
        results = [
            ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                success=extractor_success,
                error_message=error_message,
                raw_output=json.dumps(evidence, indent=2, sort_keys=True),
                relative_target_path="signing_evidence.json",
                description=self.description,
            )
        ]

        if command_result.stdout:
            results.append(
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=extractor_success,
                    raw_output=command_result.stdout,
                    relative_target_path="raw/apksigner_verify_stdout.txt",
                    description="Raw apksigner verify stdout.",
                )
            )
        if command_result.stderr:
            results.append(
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=extractor_success,
                    raw_output=command_result.stderr,
                    relative_target_path="raw/apksigner_verify_stderr.txt",
                    description="Raw apksigner verify stderr.",
                )
            )
        return results

    def _combined_output(self, command_result: ApksignerCommandResult) -> str:
        return "\n".join(part for part in (command_result.stdout, command_result.stderr) if part)

    def _normalize_label(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")

    def _normalize_fingerprint(self, value: str) -> str:
        return value.replace(":", "").replace(" ", "").upper()

    def _public_key_algorithm(self, value: str) -> str:
        normalized = value.strip().upper()
        if normalized.startswith("RSA"):
            return "RSA"
        if normalized.startswith(("EC", "ECDSA")):
            return "EC"
        if normalized.startswith("DSA"):
            return "DSA"
        return "UNKNOWN"

    def _signature_algorithm(self, value: str) -> str:
        normalized = value.replace("-", "").replace(" ", "_").upper()
        if "SHA1" in normalized and "RSA" in normalized:
            return "SHA1_WITH_RSA"
        if "SHA256" in normalized and "RSA" in normalized:
            return "SHA256_WITH_RSA"
        if "SHA512" in normalized and "RSA" in normalized:
            return "SHA512_WITH_RSA"
        if "SHA256" in normalized and ("ECDSA" in normalized or "EC" in normalized):
            return "SHA256_WITH_ECDSA"
        if "SHA512" in normalized and ("ECDSA" in normalized or "EC" in normalized):
            return "SHA512_WITH_ECDSA"
        return "UNKNOWN"

    def _parse_int(self, value: str) -> int | None:
        match = re.search(r"\d+", value)
        return int(match.group(0)) if match else None

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

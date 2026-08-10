"""Platform-neutral MobSF scanner adapter."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort


class MobSFScannerError(Exception):
    """Raised when a MobSF API call fails."""


@dataclass(frozen=True)
class _HttpResponse:
    status_code: int
    text: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> dict:
        return json.loads(self.text)


class MobSFScanner(ScannerPort):
    """Scanner for IPA/APK binaries using a MobSF API container."""

    DEFAULT_BASE_URL = "http://mobsf-scanner:8000"
    DEFAULT_API_KEY = "phoenix-local-mobsf-api-key"  # pragma: allowlist secret
    DEFAULT_TIMEOUT_SECONDS = 120
    REPORT_PATH = "mobsf_report.json"
    SUPPORTED_EXTENSIONS = (".ipa", ".apk", ".zip", ".appx")

    def __init__(self) -> None:
        base_url = os.environ.get("MOBSF_URL", self.DEFAULT_BASE_URL)
        self.api_key = os.environ.get("MOBSF_API_KEY", self.DEFAULT_API_KEY)
        self._base_url = base_url.rstrip("/")

    @property
    def scan_type(self) -> ScanType:
        return ScanType.MOBSF_SCANNER

    @property
    def name(self) -> str:
        return "MobSF Scanner"

    @property
    def description(self) -> str:
        return (
            "Static binary analysis for IPA and APK artifacts using MobSF. "
            "The raw MobSF report includes application metadata, binary hardening checks, "
            "permissions, manifest findings, embedded endpoints, certificates, and secrets."
        )

    def is_available(self) -> bool:
        try:
            response = self._request("GET", f"{self._base_url}/", timeout=5)
        except (OSError, urllib.error.URLError):
            return False
        return response.ok

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        try:
            target_path, filename = self._resolve_target(config)
            upload_data = self._upload(target_path, filename)
            file_hash = upload_data.get("hash", "")
            if not file_hash:
                raise MobSFScannerError("MobSF upload response did not include a file hash.")

            scan_data = self._run_scan(file_hash)
            self._print_logs(file_hash)
            print(f"{ScannerPort.format_stdout_prefix(self.name)}Scan complete.")

            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=True,
                    raw_output=json.dumps(scan_data, indent=2, sort_keys=True),
                    relative_target_path=self.REPORT_PATH,
                    description=self.description,
                )
            ]
        except MobSFScannerError as e:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=str(e),
                    raw_output=self._error_report(str(e)),
                    relative_target_path=self.REPORT_PATH,
                )
            ]
        except Exception as e:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=str(e),
                    raw_output=self._error_report(str(e)),
                    relative_target_path=self.REPORT_PATH,
                )
            ]

    def _resolve_target(self, config: ScanConfig) -> tuple[Path, str]:
        target_path = config.project_path
        if target_path.is_dir():
            matches = sorted(target_path.rglob("*.ipa")) or sorted(target_path.rglob("*.apk"))
            if not matches:
                raise MobSFScannerError("No IPA or APK file found in the provided directory.")
            target_path = matches[0]

        if not target_path.is_file():
            raise MobSFScannerError(f"Binary target does not exist: {target_path}")

        display_name = Path(config.display_project_path).name if config.display_project_path else target_path.name
        if display_name.lower().endswith(self.SUPPORTED_EXTENSIONS):
            return target_path, display_name

        try:
            with zipfile.ZipFile(target_path) as archive:
                suffix = ".ipa" if any(name.startswith("Payload/") for name in archive.namelist()) else ".apk"
        except zipfile.BadZipFile:
            suffix = ".apk"

        return target_path, f"upload{suffix}"

    def _upload(self, target_path: Path, filename: str) -> dict:
        print(f"{ScannerPort.format_stdout_prefix(self.name)}Uploading {filename}...")
        response = self._post_file(
            f"{self._base_url}/api/v1/upload",
            field_name="file",
            filename=filename,
            file_path=target_path,
        )
        if not response.ok:
            raise MobSFScannerError(
                f"Upload failed with status {response.status_code}: {response.text}",
            )

        upload_data = response.json()
        print(
            f"{ScannerPort.format_stdout_prefix(self.name)}Upload complete. Hash: {upload_data.get('hash', 'unknown')}"
        )
        return upload_data

    def _run_scan(self, file_hash: str) -> dict:
        response = self._post_form(
            f"{self._base_url}/api/v1/scan",
            data={"hash": file_hash},
        )
        if not response.ok:
            raise MobSFScannerError(
                f"Scan failed with status {response.status_code}: {response.text}",
            )
        return response.json()

    def _print_logs(self, file_hash: str) -> None:
        try:
            response = self._post_form(
                f"{self._base_url}/api/v1/scan_logs",
                data={"hash": file_hash},
            )
        except urllib.error.URLError:
            return

        if not response.ok:
            return

        try:
            logs = response.json().get("logs", [])
        except json.JSONDecodeError:
            return

        for log in logs:
            status = log.get("status", "")
            if status and "Saving to Database" not in status:
                print(f"{ScannerPort.format_stdout_prefix(self.name)}{status}")

    def _post_form(self, url: str, data: dict[str, str]) -> _HttpResponse:
        body = urllib.parse.urlencode(data).encode()
        headers = self._api_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        return self._request("POST", url, data=body, headers=headers)

    def _post_file(self, url: str, field_name: str, filename: str, file_path: Path) -> _HttpResponse:
        boundary = uuid.uuid4().hex
        body = self._multipart_body(boundary, field_name, filename, file_path)
        headers = self._api_headers()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        headers["Content-Length"] = str(len(body))
        return self._request("POST", url, data=body, headers=headers)

    def _request(
        self,
        method: str,
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> _HttpResponse:
        request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout or self._timeout_seconds()) as response:
                body = response.read().decode("utf-8", errors="replace")
                return _HttpResponse(status_code=response.status, text=body)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return _HttpResponse(status_code=e.code, text=body)

    def _api_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = self.api_key
        return headers

    @staticmethod
    def _error_report(error_message: str) -> str:
        return json.dumps(
            {
                "error": error_message,
                "success": False,
            },
            indent=2,
            sort_keys=True,
        )

    @classmethod
    def _multipart_body(cls, boundary: str, field_name: str, filename: str, file_path: Path) -> bytes:
        prefix = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        suffix = f"\r\n--{boundary}--\r\n".encode()
        return prefix + file_path.read_bytes() + suffix

    @classmethod
    def _timeout_seconds(cls) -> int:
        value = os.environ.get("PHOENIX_MOBSF_SCANNER_TIMEOUT", str(cls.DEFAULT_TIMEOUT_SECONDS))
        try:
            return max(1, int(value))
        except ValueError:
            return cls.DEFAULT_TIMEOUT_SECONDS

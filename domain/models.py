"""Domain models for AppcritIQ security scanning platform."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ports.scanner_port import ScannerPort


class ScanType(str, Enum):
    """Available scan types."""

    MOBSF_SCANNER = "mobsf_scanner"
    LIEF = "lief"
    ANDROGUARD = "androguard"
    AAPT2 = "aapt2"
    APKTOOL = "apktool"
    APKSIGNER = "apksigner"
    APKID = "apkid"
    IPSW = "ipsw"
    OPENGREP_SOURCE = "opengrep_source"
    OPENGREP_BINARY = "opengrep_binary"
    TRUFFLEHOG = "trufflehog"
    GITLEAKS = "gitleaks"
    STRINGS = "strings"
    PLIST_SOURCE = "plist_source"
    PLIST_BINARY = "plist_binary"
    DEPENDENCY_CHECK = "dependency_check"
    SYFT = "syft"


@dataclass
class ScanResult:
    """Result from a single scanner execution."""

    scanner_name: str
    scan_type: ScanType
    success: bool = True
    skipped: bool = False
    error_message: str = ""
    raw_output: str = ""
    artifact_files: dict[str, str] = field(default_factory=dict)
    duration_seconds: float = 0.0
    description: str = ""
    relative_target_path: str = ""


@dataclass
class ScanConfig:
    """Configuration for a scanning session."""

    project_path: Path
    output_path: Path
    mode: str = "source"
    scan_label: str = ""
    scanners: list["ScannerPort"] = field(default_factory=list)
    enabled_scans: list[ScanType] = field(default_factory=lambda: list(ScanType))
    rules_path: Path | None = None
    ignore_patterns: list[str] = field(default_factory=list)
    ignore_file: Path | None = None
    display_project_path: str = ""
    platform: str = "ANY"
    stack: str = "ANY"

    @property
    def target_type(self) -> str:
        return self.mode.upper()

"""Domain models for Phoenix security scanning platform."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol


class ExtractedBinary(Protocol):
    """Shared extracted-binary workspace for a scan."""

    temp_dir: Path

    @property
    def scan_root_path(self) -> Path: ...

    @property
    def analysis_targets(self) -> list[Path]: ...

    def cleanup(self) -> None: ...


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
    TRUFFLEHOG = "trufflehog"
    GITLEAKS = "gitleaks"
    STRINGS = "strings"
    PLIST_SOURCE = "plist_source"
    PLIST_BINARY = "plist_binary"
    NATIVE_ANDROID_SOURCE_METADATA = "native_android_source_metadata"
    FLUTTER_SOURCE_METADATA = "flutter_source_metadata"
    REACT_NATIVE_METADATA = "react_native_metadata"
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
    opengrep_rules_path: Path | None = None
    ignore_patterns: list[str] = field(default_factory=list)
    ignore_file: Path | None = None
    display_project_path: str = ""
    platform: str = "ANY"
    stack: str = "ANY"
    syft_output_format: str = "syft-json"
    extracted_binary: ExtractedBinary | None = None

    @property
    def target_type(self) -> str:
        return self.mode.upper()

"""iOS LIEF scanner adapter for IPA binaries."""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.ipa_utils import (
    ExtractedIPA,
    classify_ipa_binary,
    extract_ipa,
    get_scanable_binary_paths,
    is_ipa_file,
)
from utilities.json_utils import json_safe
from utilities.path_utils import relative_result_path

try:
    import lief
except ImportError:  # pragma: no cover - handled by is_available()
    lief = None


class LIEFScanner(ScannerPort):
    """Scanner for Mach-O analysis of IPA files using LIEF."""

    @property
    def scan_type(self) -> ScanType:
        return ScanType.LIEF

    @property
    def name(self) -> str:
        return "LIEF Binary Analyzer"

    @property
    def description(self) -> str:
        return "Mach-O metadata extracted from IPA binaries using LIEF."

    def is_available(self) -> bool:
        return lief is not None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        extracted = config.extracted_binary if isinstance(config.extracted_binary, ExtractedIPA) else None
        target_path = config.project_path
        owns_extraction = extracted is None

        if extracted is None and not target_path.exists():
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=f"Binary target does not exist: {target_path}",
                )
            ]

        if extracted is None and (not target_path.is_file() or not is_ipa_file(target_path)):
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="LIEF only runs on IPA files.",
                )
            ]

        try:
            if extracted is None:
                extracted = extract_ipa(target_path)
            app_info = self._build_app_info(extracted)
            scan_results: list[ScanResult] = []

            for binary_path in get_scanable_binary_paths(extracted):
                binary_record = self._analyze_binary(lief, extracted, binary_path)
                raw_output = (
                    json.dumps(
                        json_safe(
                            {
                                "target": str(binary_path),
                                "app_info": app_info,
                                "binary": binary_record,
                            }
                        ),
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n"
                )
                scan_results.append(
                    ScanResult(
                        scanner_name=self.name,
                        scan_type=self.scan_type,
                        success=True,
                        raw_output=raw_output,
                        description=self.description,
                        relative_target_path=Path(relative_result_path(extracted.app_bundle, binary_path))
                        .with_suffix(".json")
                        .as_posix(),
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

    def _analyze_binary(self, lief_module: Any, extracted: ExtractedIPA, binary_path: Path) -> dict[str, Any]:
        try:
            binary = lief_module.MachO.parse(str(binary_path))
            slices = self._collect_slices(binary)
        except Exception as exc:
            return {
                "name": binary_path.name,
                "kind": classify_ipa_binary(extracted, binary_path),
                "path": relative_result_path(extracted.app_bundle, binary_path),
                "slices": [],
                "error": str(exc),
            }

        return {
            "name": binary_path.name,
            "kind": classify_ipa_binary(extracted, binary_path),
            "path": relative_result_path(extracted.app_bundle, binary_path),
            "slices": slices,
        }

    def _collect_slices(self, binary: Any) -> list[dict[str, Any]]:
        macho_items = self._collect_macho_objects(binary)
        return [self._build_macho_slice_analysis(macho) for macho in macho_items if macho is not None]

    def _collect_macho_objects(self, binary: Any) -> list[Any]:
        if binary is None:
            return []

        if hasattr(binary, "header") and hasattr(binary, "segments"):
            return [binary]

        size = None
        for attr in ("size", "__len__"):
            if attr == "size" and isinstance(getattr(binary, "size", None), int):
                size = getattr(binary, "size")
                break
            if attr == "__len__":
                try:
                    size = len(binary)
                    break
                except Exception:
                    pass

        if size is not None:
            slices: list[Any] = []
            for index in range(size):
                try:
                    slices.append(binary.at(index))
                except Exception:
                    break
            if slices:
                return slices

        if hasattr(binary, "at"):
            try:
                first = binary.at(0)
                if first is not None:
                    return [first]
            except Exception:
                pass

        if isinstance(binary, (list, tuple)):
            return list(binary)

        try:
            first = binary[0]
            return [first] if first is not None else []
        except Exception:
            return [binary]

    def _build_macho_slice_analysis(self, macho: Any) -> dict[str, Any]:
        header = getattr(macho, "header", None)
        flags = [self._enum_text(flag) for flag in getattr(header, "flags_list", [])] if header else []
        libraries = [self._enum_text(getattr(lib, "name", lib)) for lib in getattr(macho, "libraries", [])]
        interesting_sections = self._collect_interesting_sections(macho)

        architecture = self._enum_text(getattr(header, "cpu_type", "unknown")) if header else "unknown"

        return {
            "architecture": architecture,
            "cpu_type": architecture,
            "file_type": self._enum_text(getattr(header, "file_type", "unknown")) if header else "unknown",
            "has_nx": self._bool_property(macho, "has_nx"),
            "has_nx_heap": self._bool_property(macho, "has_nx_heap"),
            "has_nx_stack": self._bool_property(macho, "has_nx_stack"),
            "has_rpath": self._bool_property(macho, "has_rpath"),
            "imported_functions": self._imported_function_names(macho),
            "flags": flags,
            "libraries": libraries,
            "interesting_sections": interesting_sections,
        }

    @staticmethod
    def _collect_interesting_sections(macho: Any) -> list[dict[str, Any]]:
        interesting: list[dict[str, Any]] = []
        for segment in getattr(macho, "segments", []):
            segment_name = getattr(segment, "name", "")
            for section in getattr(segment, "sections", []):
                section_name = getattr(section, "name", "")
                if not any(token in section_name.lower() for token in ("objc", "swift", "cstring")):
                    continue
                interesting.append(
                    {
                        "segment": segment_name,
                        "section": section_name,
                        "size": getattr(section, "size", 0),
                    }
                )
        return interesting

    @staticmethod
    def _enum_text(value: Any) -> str:
        if isinstance(value, Enum):
            return value.name or str(value)
        name = getattr(value, "name", None)
        if isinstance(name, str) and name:
            return name
        if value is None:
            return "unknown"
        return str(value)

    @staticmethod
    def _bool_property(value: Any, attribute: str) -> bool | None:
        candidate = getattr(value, attribute, None)
        if candidate is None:
            return None
        try:
            resolved = candidate() if callable(candidate) else candidate
        except Exception:
            return None
        if isinstance(resolved, bool):
            return resolved
        return None

    @staticmethod
    def _imported_function_names(macho: Any) -> list[str]:
        imported_functions = getattr(macho, "imported_functions", None)
        if imported_functions is None:
            return []

        names: list[str] = []
        for item in imported_functions:
            name = getattr(item, "name", item)
            text = str(name).strip()
            if text:
                names.append(text)
        return names

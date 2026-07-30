"""APK extraction utilities for binary analysis."""

import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# Magic bytes for ZIP archives (APK files are ZIP archives)
_ZIP_MAGIC = b"PK\x03\x04"


@dataclass
class ExtractedAPK:
    """Result of APK extraction."""

    temp_dir: Path
    native_libs: list[Path] = field(default_factory=list)
    analysis_targets: list[Path] = field(default_factory=list)

    def cleanup(self) -> None:
        """Remove temporary extraction directory."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    @property
    def scan_root_path(self) -> Path:
        """Return the extracted APK directory for filesystem scanners."""
        return self.temp_dir


def iter_apk_analysis_targets(extracted: ExtractedAPK) -> list[Path]:
    """Return the APK binary targets that should be scanned by analysis tools."""
    if extracted.analysis_targets:
        return list(extracted.analysis_targets)
    return list(extracted.native_libs)


def find_apk_in_directory(directory: Path) -> Path | None:
    """Return the first .apk file found at the top level of a directory, or None."""
    try:
        for item in directory.iterdir():
            if item.is_file() and item.suffix.lower() == ".apk":
                return item
    except OSError:
        pass
    return None


def is_apk_file(path: Path) -> bool:
    """
    Check if a file is an APK archive.

    Validates ZIP magic bytes plus either a .apk extension or the presence of
    AndroidManifest.xml / classes.dex inside the archive (the two files that
    every valid APK must contain).
    """
    if not path.is_file():
        return False
    try:
        with open(path, "rb") as f:
            if f.read(4) != _ZIP_MAGIC:
                return False
    except OSError:
        return False
    if path.suffix.lower() == ".apk":
        return True
    # No .apk extension — verify by inspecting contents.
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = set(zf.namelist())
            return "AndroidManifest.xml" in names or "classes.dex" in names
    except Exception:
        return False


def extract_apk(apk_path: Path) -> ExtractedAPK:
    """
    Extract native libraries from an APK file.

    APK structure:
        MyApp.apk (ZIP)
        ├── AndroidManifest.xml
        ├── classes.dex
        └── lib/
            ├── arm64-v8a/
            │   └── libfoo.so   (ELF native library)
            ├── armeabi-v7a/
            └── x86_64/

    Only the analysis-relevant members are extracted to keep temp storage minimal.
    If the APK contains no native libraries the returned native_libs list
    will be empty — callers should handle this gracefully.

    Args:
        apk_path: Path to the .apk file.

    Returns:
        ExtractedAPK containing the temp dir and a list of .so paths.

    Raises:
        ValueError: If the path does not exist or is not a valid APK.
    """
    if not apk_path.exists():
        raise ValueError(f"APK file does not exist: {apk_path}")

    if not is_apk_file(apk_path):
        raise ValueError(f"Not a valid APK file: {apk_path}")

    temp_dir = Path(tempfile.mkdtemp(prefix="phoenix_apk_"))

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            target_entries = [n for n in zf.namelist() if _should_extract_for_analysis(n)]
            for entry in target_entries:
                if entry.endswith("/"):
                    continue
                zf.extract(entry, temp_dir)

        lib_dir = temp_dir / "lib"
        native_libs = sorted(lib_dir.rglob("*.so")) if lib_dir.exists() else []
        analysis_targets = sorted(
            path
            for path in temp_dir.rglob("*")
            if path.is_file() and _should_scan_for_analysis(path.relative_to(temp_dir).as_posix())
        )

        return ExtractedAPK(
            temp_dir=temp_dir,
            native_libs=native_libs,
            analysis_targets=analysis_targets,
        )

    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def _should_extract_for_analysis(archive_name: str) -> bool:
    if archive_name.endswith("/"):
        return False

    normalized = archive_name.replace("\\", "/")
    base_name = Path(normalized).name

    if normalized == "AndroidManifest.xml":
        return True
    if normalized == "resources.arsc":
        return True
    if base_name.startswith("classes") and base_name.endswith(".dex"):
        return True
    if normalized.startswith("lib/") and normalized.endswith(".so"):
        return True
    if normalized.startswith("assets/"):
        return True
    return base_name.lower().endswith((".json", ".xml", ".txt", ".pem"))


def _should_scan_for_analysis(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    base_name = Path(normalized).name

    if normalized == "AndroidManifest.xml":
        return True
    if normalized == "resources.arsc":
        return True
    if base_name.startswith("classes") and base_name.endswith(".dex"):
        return True
    if normalized.startswith("lib/") and normalized.endswith(".so"):
        return True
    if normalized.startswith("assets/"):
        return True
    return base_name.lower().endswith((".json", ".xml", ".txt", ".pem"))

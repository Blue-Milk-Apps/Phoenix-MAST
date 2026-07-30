"""IPA extraction utilities for binary analysis."""

import plistlib
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

# Magic bytes for ZIP archives (IPA files are ZIP archives)
_ZIP_MAGIC = b"PK\x03\x04"


@dataclass
class ExtractedIPA:
    """Result of IPA extraction."""

    temp_dir: Path
    app_bundle: Path
    binary_path: Path
    info_plist: dict | None = None

    def cleanup(self) -> None:
        """Remove temporary extraction directory."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    @property
    def scan_root_path(self) -> Path:
        """Return the extracted app bundle for filesystem scanners."""
        return self.app_bundle

    @property
    def analysis_targets(self) -> list[Path]:
        """Return the Mach-O binaries relevant to binary analysis."""
        return get_scanable_binary_paths(self)


def get_scanable_binary_paths(extracted: ExtractedIPA) -> list[Path]:
    """Return the IPA binary targets that should be scanned by analysis tools."""
    targets = [extracted.binary_path]
    frameworks_dir = extracted.app_bundle / "Frameworks"
    if not frameworks_dir.exists():
        return targets

    for framework_dir in sorted(frameworks_dir.glob("*.framework")):
        binary = framework_dir / framework_dir.stem
        if binary.is_file():
            targets.append(binary)

        for dylib in sorted(framework_dir.glob("*.dylib")):
            if dylib.is_file():
                targets.append(dylib)

    return targets


def relative_ipa_binary_path(extracted: ExtractedIPA, binary_path: Path) -> Path:
    """Return a stable path for a binary within the extracted IPA bundle."""
    try:
        return binary_path.relative_to(extracted.app_bundle)
    except ValueError:
        return Path(binary_path.name)


def classify_ipa_binary(extracted: ExtractedIPA, binary_path: Path) -> str:
    """Classify an IPA binary as the main app binary, a framework, or another embedded file."""
    if binary_path == extracted.binary_path:
        return "main"
    if "Frameworks" in binary_path.parts:
        return "framework"
    if binary_path.suffix == ".dylib":
        return "dylib"
    return "embedded"


def find_ipa_in_directory(directory: Path) -> Path | None:
    """Return the first .ipa file found at the top level of a directory, or None."""
    try:
        for item in directory.iterdir():
            if item.is_file() and item.suffix.lower() == ".ipa":
                return item
    except OSError:
        pass
    return None


def is_ipa_file(path: Path) -> bool:
    """
    Check if a file is an IPA archive.

    Validates ZIP magic bytes plus either a .ipa extension or an internal
    Payload/*.app structure. The content-based check handles cases where the
    file is mounted without its original name (e.g. Docker volume as /scan).
    """
    if not path.is_file():
        return False
    try:
        with open(path, "rb") as f:
            if f.read(4) != _ZIP_MAGIC:
                return False
    except OSError:
        return False
    if path.suffix.lower() == ".ipa":
        return True
    # No .ipa extension — verify IPA structure by inspecting the ZIP contents.
    # IPA ZIPs typically don't include explicit directory entries, so check for
    # any file path that lives inside a Payload/*.app/ bundle instead.
    try:
        with zipfile.ZipFile(path, "r") as zf:
            return any(name.startswith("Payload/") and ".app/" in name for name in zf.namelist())
    except Exception:
        return False


def extract_ipa(ipa_path: Path) -> ExtractedIPA:
    """
    Extract an IPA file and locate the main Mach-O binary.

    IPA structure:
        MyApp.ipa (ZIP)
        └── Payload/
            └── MyApp.app/
                ├── MyApp (Mach-O binary - name from CFBundleExecutable)
                ├── Info.plist
                └── ... other resources

    Args:
        ipa_path: Path to the .ipa file.

    Returns:
        ExtractedIPA containing paths to extracted content.

    Raises:
        ValueError: If IPA structure is invalid or binary not found.
    """
    if not ipa_path.exists():
        raise ValueError(f"IPA file does not exist: {ipa_path}")

    if not is_ipa_file(ipa_path):
        raise ValueError(f"Not a valid IPA file: {ipa_path}")

    temp_dir = Path(tempfile.mkdtemp(prefix="phoenix_ipa_"))

    try:
        with zipfile.ZipFile(ipa_path, "r") as zf:
            zf.extractall(temp_dir)

        payload_dir = temp_dir / "Payload"
        if not payload_dir.exists():
            raise ValueError("Invalid IPA: No Payload directory found")

        app_bundles = list(payload_dir.glob("*.app"))
        if not app_bundles:
            raise ValueError("Invalid IPA: No .app bundle found in Payload")

        app_bundle = app_bundles[0]

        info_plist_path = app_bundle / "Info.plist"
        info_plist = None
        executable_name = None

        if info_plist_path.exists():
            with info_plist_path.open("rb") as handle:
                info_plist = plistlib.load(handle)
                executable_name = info_plist.get("CFBundleExecutable")

        binary_path = app_bundle / (executable_name or app_bundle.stem)
        if not binary_path.exists():
            for item in app_bundle.iterdir():
                if item.is_file() and not item.suffix:
                    binary_path = item
                    break

        if not binary_path.exists():
            raise ValueError(f"Could not find Mach-O binary in app bundle: {app_bundle}")

        return ExtractedIPA(
            temp_dir=temp_dir,
            app_bundle=app_bundle,
            binary_path=binary_path,
            info_plist=info_plist,
        )

    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

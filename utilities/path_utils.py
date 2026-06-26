"""Path helpers shared by scanner adapters."""

from __future__ import annotations

from pathlib import Path


def relative_result_path(base_path: Path, target_path: Path) -> str:
    """Return a stable relative path for a per-target scan result."""
    try:
        relative = target_path.relative_to(base_path)
    except ValueError:
        relative = Path(target_path.name)

    if relative == Path(".") or not relative.parts:
        relative = Path(target_path.name)

    return relative.as_posix()

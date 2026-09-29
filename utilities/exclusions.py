"""Apply the same path exclusions before filesystem tools execute."""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import replace
from glob import escape
from pathlib import Path
from typing import Iterator

from domain.models import ScanConfig


class PathExclusions:
    """Root-relative globs; matching a directory also excludes its descendants."""

    def __init__(self, root: Path, patterns: list[str]) -> None:
        self.root = root.absolute()
        self.patterns = []
        for pattern in patterns:
            if Path(pattern).is_absolute():
                try:
                    pattern = Path(pattern).relative_to(self.root).as_posix()
                except ValueError:
                    continue
            pattern = pattern.removeprefix("./").strip("/")
            if not pattern:
                continue
            self.patterns.append(() if pattern == "." else tuple(pattern.split("/")))

    def matches(self, path: Path) -> bool:
        parts = path.relative_to(self.root).parts if path.is_absolute() else path.parts
        return any(self._matches_parts(parts, pattern) for pattern in self.patterns)

    @classmethod
    def _matches_parts(cls, parts: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
        if not pattern:
            return True  # A matched directory includes descendants.
        if pattern[0] == "**":
            return any(cls._matches_parts(parts[index:], pattern[1:]) for index in range(len(parts) + 1))
        return bool(parts) and fnmatch.fnmatchcase(parts[0], pattern[0]) and cls._matches_parts(parts[1:], pattern[1:])


def prune_excluded(root: Path, patterns: list[str]) -> None:
    """Remove excluded inputs from a disposable extracted/decoded workspace."""
    root = root.absolute()
    matcher = PathExclusions(root, patterns)
    for directory, dirs, files in os.walk(root):
        for name in [*dirs, *files]:
            path = Path(directory) / name
            if matcher.matches(path):
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                    dirs.remove(name)
                else:
                    path.unlink()


def _is_scan_output(path: Path) -> bool:
    """Identify Phoenix results by their metadata, regardless of directory name."""
    try:
        metadata = json.loads((path / "scan_metadata.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(metadata, dict) and {"scan_label", "target_type", "project_path", "output_path"}.issubset(metadata)


@contextmanager
def source_scan_workspace(config: ScanConfig) -> Iterator[ScanConfig]:
    """Use a shared filtered tree only when exclusions are needed.

    Tools read hard-linked files where possible, avoiding duplicate file contents.
    Source paths in artifacts are restored by ScannerService before persistence.
    """
    if config.target_type != "SOURCE":
        yield config
        return
    root = config.project_path.resolve()
    patterns = list(config.exclude_patterns)
    # Exclude this and previous runs when the output directory is inside the target.
    output_parent = config.output_path.resolve().parent
    if output_parent != root and output_parent.is_relative_to(root):
        patterns.append(escape(output_parent.relative_to(root).as_posix()))
    elif config.output_path.resolve().is_relative_to(root):
        patterns.append(escape(config.output_path.resolve().relative_to(root).as_posix()))
    if _is_scan_output(root):
        raise ValueError("Source target is a Phoenix scan results directory; select the original source project.")
    matcher = PathExclusions(root, patterns)
    for directory, dirs, _ in os.walk(root):
        for name in dirs[:]:
            path = Path(directory) / name
            if matcher.matches(path):
                dirs.remove(name)
            elif _is_scan_output(path):
                relative = path.relative_to(root).as_posix()
                patterns.append(escape(relative))
                dirs.remove(name)
                print(f"Input skipped: {relative} (previous Phoenix scan results)")
    if not patterns:
        yield config
        return
    matcher = PathExclusions(root, patterns)
    with tempfile.TemporaryDirectory(prefix="phoenix_source_") as work:
        staged = Path(work).resolve() / root.name
        staged.mkdir()

        def copy_tree(source_dir: Path, target_dir: Path, ancestors: frozenset[Path]) -> None:
            target_dir.mkdir(parents=True, exist_ok=True)
            for source in sorted(source_dir.iterdir()):
                if matcher.matches(source):
                    continue
                resolved = source.resolve()
                if not resolved.is_relative_to(root):
                    print(f"Input skipped: {source.relative_to(root)} (symlink outside scan target)")
                    continue
                if matcher.matches(resolved):
                    continue
                target = target_dir / source.name
                if source.is_dir():
                    if resolved in ancestors:
                        continue
                    copy_tree(source, target, ancestors | {resolved})
                elif source.is_file():
                    try:
                        os.link(resolved, target)
                    except OSError:
                        shutil.copy2(resolved, target)

        copy_tree(root, staged, frozenset({root}))
        yield replace(config, project_path=staged, display_project_path=str(root))

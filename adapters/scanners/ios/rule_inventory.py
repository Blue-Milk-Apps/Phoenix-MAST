"""Validate the section-based iOS OpenGrep rule catalog."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Collection

import yaml


class IOSRuleInventoryError(ValueError):
    """Raised when the iOS rule files do not match the Phoenix registry."""


class IOSRuleSection(StrEnum):
    CODE = "Code"
    FUNCTIONALITY = "Functionality"
    NETWORK = "Network"
    PERMISSIONS = "Permissions"
    STORAGE = "Data Evidence"

    @classmethod
    def from_file_name(cls, file_name: str) -> "IOSRuleSection":
        sections = {
            "code": cls.CODE,
            "crypto": cls.CODE,
            "functionality": cls.FUNCTIONALITY,
            "network": cls.NETWORK,
            "networking": cls.NETWORK,
            "permissions": cls.PERMISSIONS,
            "storage": cls.STORAGE,
        }
        try:
            return sections[file_name]
        except KeyError as exc:
            raise IOSRuleInventoryError(
                f"Unsupported iOS rule file '{file_name}.yml'. "
                "Expected code, crypto, functionality, network, networking, permissions, or storage."
            ) from exc


@dataclass(frozen=True)
class IOSRuleFile:
    """A parsed iOS rule file and the section it declares."""

    path: Path
    section: IOSRuleSection
    rule_ids: tuple[str, ...]
    rule_documents: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class IOSRuleInventory:
    """The complete section-based iOS OpenGrep rule inventory."""

    files: tuple[IOSRuleFile, ...]

    @classmethod
    def from_directory(cls, rules_directory: Path) -> "IOSRuleInventory":
        if not rules_directory.is_dir():
            raise IOSRuleInventoryError(f"iOS rules directory does not exist: {rules_directory}")

        rule_paths = tuple(sorted(path for path in rules_directory.glob("*.yml") if path.is_file()))
        rule_paths += tuple(sorted(path for path in rules_directory.glob("*.yaml") if path.is_file()))
        if not rule_paths:
            raise IOSRuleInventoryError(f"No iOS YAML rule files found in: {rules_directory}")

        files = tuple(cls._parse_file(path) for path in rule_paths)
        return cls(files=files)

    def validate(self, expected_rule_ids: Collection[str] | None = None) -> None:
        """Validate duplicate IDs and optional expected-rule coverage."""

        errors: list[str] = []
        all_rule_ids = [rule_id for rule_file in self.files for rule_id in rule_file.rule_ids]
        duplicates = sorted(rule_id for rule_id, count in Counter(all_rule_ids).items() if count > 1)
        if duplicates:
            errors.append(f"duplicate rule IDs: {', '.join(duplicates)}")

        if expected_rule_ids is not None:
            expected = set(expected_rule_ids)
            actual = set(all_rule_ids)
            missing = sorted(expected - actual)
            unexpected = sorted(actual - expected)
            if missing:
                errors.append(f"missing rule IDs: {', '.join(missing)}")
            if unexpected:
                errors.append(f"unexpected rule IDs: {', '.join(unexpected)}")

        if errors:
            raise IOSRuleInventoryError("Invalid iOS OpenGrep rule inventory: " + "; ".join(errors))

    def write_single_rule(self, rule_id: str, output_directory: Path) -> Path:
        """Write one catalog rule to a temporary OpenGrep configuration file."""

        for rule_file in self.files:
            for rule in rule_file.rule_documents:
                if rule.get("id") != rule_id:
                    continue
                output_directory.mkdir(parents=True, exist_ok=True)
                output_path = output_directory / f"{rule_id.replace('/', '_')}.yml"
                output_path.write_text(
                    yaml.safe_dump({"rules": [rule]}, sort_keys=False),
                    encoding="utf-8",
                )
                return output_path
        raise IOSRuleInventoryError(f"Rule ID is not present in the iOS inventory: {rule_id}")

    @staticmethod
    def _parse_file(path: Path) -> IOSRuleFile:
        section = IOSRuleSection.from_file_name(path.stem)
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise IOSRuleInventoryError(f"Could not parse iOS rule file {path}: {exc}") from exc

        if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
            raise IOSRuleInventoryError(f"iOS rule file {path} must contain a top-level rules list.")

        rule_ids: list[str] = []
        rule_documents: list[dict[str, Any]] = []
        rule_errors: list[str] = []
        for index, rule in enumerate(document["rules"], start=1):
            rule_id = rule.get("id") if isinstance(rule, dict) else None
            if not isinstance(rule_id, str) or not rule_id.strip():
                rule_errors.append(f"{path.name} rule {index} has no non-empty id")
                continue
            rule_ids.append(rule_id.strip())
            rule_documents.append(rule)

        if rule_errors:
            raise IOSRuleInventoryError("Invalid iOS rules: " + "; ".join(rule_errors))
        return IOSRuleFile(
            path=path,
            section=section,
            rule_ids=tuple(rule_ids),
            rule_documents=tuple(rule_documents),
        )


def validate_ios_rule_inventory(rules_directory: Path) -> IOSRuleInventory:
    """Parse and validate the default iOS OpenGrep rule directory."""

    inventory = IOSRuleInventory.from_directory(rules_directory)
    inventory.validate()
    return inventory

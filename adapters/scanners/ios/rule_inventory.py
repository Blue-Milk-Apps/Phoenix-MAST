"""Load iOS rule definitions and reporting metadata from category files."""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from domain.post_scan.rule_assessment import RuleDefinition


class IOSRuleInventoryError(ValueError):
    """The configured ruleset cannot be interpreted reliably."""


@dataclass(frozen=True)
class IOSRuleFile:
    path: Path
    category: str
    rule_ids: tuple[str, ...]
    definitions: tuple[RuleDefinition, ...]


@dataclass(frozen=True)
class IOSRuleInventory:
    files: tuple[IOSRuleFile, ...]

    @classmethod
    def from_directory(cls, rules_directory: Path) -> IOSRuleInventory:
        if not rules_directory.is_dir():
            raise IOSRuleInventoryError(f"iOS rules directory does not exist: {rules_directory}")
        paths = sorted(p for p in rules_directory.iterdir() if p.is_file() and p.suffix in {".yml", ".yaml"})
        if not paths:
            raise IOSRuleInventoryError(f"No iOS YAML rule files found in: {rules_directory}")
        return cls(tuple(cls._parse_file(path) for path in paths))

    @property
    def fingerprint(self) -> str:
        parts = [f"{item.path.name}:{item.definitions[0].fingerprint}" for item in self.files]
        return hashlib.sha256("\n".join(parts).encode()).hexdigest()

    @property
    def catalog(self) -> list[dict[str, Any]]:
        return [definition.snapshot() for item in self.files for definition in item.definitions]

    def validate(self) -> None:
        counts = Counter(rule_id for item in self.files for rule_id in item.rule_ids)
        duplicates = sorted(key for key, count in counts.items() if count > 1)
        if duplicates:
            raise IOSRuleInventoryError(f"duplicate rule IDs: {', '.join(duplicates)}")

    @staticmethod
    def _parse_file(path: Path) -> IOSRuleFile:
        try:
            contents = path.read_bytes()
            document = yaml.safe_load(contents)
            if not isinstance(document, dict) or not isinstance(document.get("rules"), list) or not document["rules"]:
                raise ValueError("Expected a non-empty top-level rules list.")
            fingerprint = hashlib.sha256(contents).hexdigest()
            rules = tuple(document["rules"])
            definitions = tuple(
                RuleDefinition.from_rule(
                    rule,
                    category=path.stem,
                    rule_file=path.name,
                    fingerprint=fingerprint,
                )
                for rule in rules
            )
            return IOSRuleFile(path, path.stem, tuple(rule.rule_id for rule in definitions), definitions)
        except (OSError, ValueError, TypeError, AttributeError, yaml.YAMLError) as exc:
            raise IOSRuleInventoryError(f"Invalid iOS rule file {path}: {exc}") from exc


def validate_ios_rule_inventory(rules_directory: Path) -> IOSRuleInventory:
    inventory = IOSRuleInventory.from_directory(rules_directory)
    inventory.validate()
    return inventory

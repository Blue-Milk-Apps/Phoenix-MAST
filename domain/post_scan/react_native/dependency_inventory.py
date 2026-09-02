"""Build typed React Native dependency and SBOM inventory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass(frozen=True)
class ReactNativeDeclaredDependency:
    name: str
    constraint: str
    source: str
    scope: str


@dataclass(frozen=True)
class ReactNativeSbomPackage:
    name: str
    version: str
    output_path: str


@dataclass
class ReactNativeDependencyInventory:
    metadata_assessed: bool
    sbom_assessed: bool
    declared: list[ReactNativeDeclaredDependency]
    sbom_packages: list[ReactNativeSbomPackage]

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        self.metadata_assessed = context.dependencies_assessed
        self.sbom_assessed = context.syft_assessed
        self.declared = self._declared_dependencies(context, context.dependencies)
        self.sbom_packages = [
            ReactNativeSbomPackage(name=name, version=version, output_path=output_path)
            for output_path, name, version in context.syft_packages
        ]

    @staticmethod
    def _declared_dependencies(
        context: ReactNativeScanExtractionContext,
        dependencies: dict[str, list[dict[str, Any]]],
    ) -> list[ReactNativeDeclaredDependency]:
        records: list[ReactNativeDeclaredDependency] = []
        for scope in ("direct", "development"):
            for dependency in dependencies[scope]:
                name = context.first_non_empty(dependency.get("name"))
                if not name:
                    continue
                records.append(
                    ReactNativeDeclaredDependency(
                        name=name,
                        constraint=context.first_non_empty(dependency.get("constraint")),
                        source=context.first_non_empty(dependency.get("source")),
                        scope=scope,
                    )
                )
        return list(dict.fromkeys(records))

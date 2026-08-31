"""Build typed Flutter dependency and SBOM inventory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext


@dataclass(frozen=True)
class FlutterDeclaredDependency:
    name: str
    constraint: str
    source: str
    scope: str


@dataclass(frozen=True)
class FlutterResolvedDependency:
    name: str
    version: str
    source: str
    dependency_kind: str
    hosted_url: str
    vcs_url: str
    path: str


@dataclass(frozen=True)
class FlutterSbomPackage:
    name: str
    version: str
    output_path: str


@dataclass
class FlutterDependencyInventory:
    metadata_assessed: bool
    sbom_assessed: bool
    declared: list[FlutterDeclaredDependency]
    resolved: list[FlutterResolvedDependency]
    sbom_packages: list[FlutterSbomPackage]

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        dependencies = context.dependencies
        self.metadata_assessed = context.dependencies_assessed
        self.sbom_assessed = context.syft_assessed
        self.declared = self._declared_dependencies(context, dependencies)
        self.resolved = self._resolved_dependencies(context, dependencies["resolved"])
        self.sbom_packages = [
            FlutterSbomPackage(name=name, version=version, output_path=output_path)
            for output_path, name, version in context.syft_packages
        ]

    @staticmethod
    def _declared_dependencies(
        context: FlutterScanExtractionContext,
        dependencies: dict[str, list[dict[str, Any]]],
    ) -> list[FlutterDeclaredDependency]:
        records: list[FlutterDeclaredDependency] = []
        for scope in ("direct", "development"):
            for dependency in dependencies[scope]:
                name = context.first_non_empty(dependency.get("name"))
                if not name:
                    continue
                records.append(
                    FlutterDeclaredDependency(
                        name=name,
                        constraint=context.first_non_empty(dependency.get("constraint")),
                        source=context.first_non_empty(dependency.get("source")),
                        scope=scope,
                    )
                )
        return list(dict.fromkeys(records))

    @staticmethod
    def _resolved_dependencies(
        context: FlutterScanExtractionContext,
        dependencies: list[dict[str, Any]],
    ) -> list[FlutterResolvedDependency]:
        records: list[FlutterResolvedDependency] = []
        for dependency in dependencies:
            name = context.first_non_empty(dependency.get("name"))
            if not name:
                continue
            records.append(
                FlutterResolvedDependency(
                    name=name,
                    version=context.first_non_empty(dependency.get("version")),
                    source=context.first_non_empty(dependency.get("source")),
                    dependency_kind=context.first_non_empty(dependency.get("dependency_kind")),
                    hosted_url=context.first_non_empty(dependency.get("hosted_url")),
                    vcs_url=context.first_non_empty(dependency.get("vcs_url")),
                    path=context.first_non_empty(dependency.get("path")),
                )
            )
        return list(dict.fromkeys(records))

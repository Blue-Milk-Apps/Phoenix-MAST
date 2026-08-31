"""Tests for typed Flutter dependency and SBOM inventory."""

from __future__ import annotations

from dataclasses import asdict

from domain.post_scan.flutter import FlutterDependencyInventory, FlutterScanExtractionContext


def test_normalizes_and_deduplicates_dependency_inventory() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "dependencies": {
                    "direct": [
                        {"name": " http ", "constraint": " ^1.2.0 ", "source": " hosted "},
                        {"name": "http", "constraint": "^1.2.0", "source": "hosted"},
                        {"name": "local_package", "constraint": "", "source": "path"},
                        {"name": ""},
                    ],
                    "development": [
                        {"name": "test", "constraint": "^1.25.0", "source": "hosted"},
                        {"name": "http", "constraint": "^1.2.0", "source": "hosted"},
                    ],
                    "resolved": [
                        {
                            "name": "http",
                            "version": "1.2.0",
                            "source": "hosted",
                            "dependency_kind": "direct",
                            "hosted_url": "https://pub.dev",
                            "vcs_url": "",
                            "path": "",
                        },
                        {
                            "name": "http",
                            "version": "1.2.0",
                            "source": "hosted",
                            "dependency_kind": "direct",
                            "hosted_url": "https://pub.dev",
                            "vcs_url": "",
                            "path": "",
                        },
                        {
                            "name": "git_package",
                            "version": "2.0.0",
                            "source": "git",
                            "dependency_kind": "transitive",
                            "vcs_url": "https://example.com/package.git",
                        },
                        {"version": "3.0.0"},
                    ],
                }
            },
            "syft_outputs": {
                "sbom.json": {
                    "artifacts": [
                        {"name": "http", "version": "1.2.0"},
                        {"name": "http", "version": "1.2.0"},
                    ],
                    "components": [{"name": "flutter", "version": "3.22.0"}],
                }
            },
        }
    )

    assert asdict(FlutterDependencyInventory(context)) == {
        "metadata_assessed": True,
        "sbom_assessed": True,
        "declared": [
            {"name": "http", "constraint": "^1.2.0", "source": "hosted", "scope": "direct"},
            {"name": "local_package", "constraint": "", "source": "path", "scope": "direct"},
            {"name": "test", "constraint": "^1.25.0", "source": "hosted", "scope": "development"},
            {"name": "http", "constraint": "^1.2.0", "source": "hosted", "scope": "development"},
        ],
        "resolved": [
            {
                "name": "http",
                "version": "1.2.0",
                "source": "hosted",
                "dependency_kind": "direct",
                "hosted_url": "https://pub.dev",
                "vcs_url": "",
                "path": "",
            },
            {
                "name": "git_package",
                "version": "2.0.0",
                "source": "git",
                "dependency_kind": "transitive",
                "hosted_url": "",
                "vcs_url": "https://example.com/package.git",
                "path": "",
            },
        ],
        "sbom_packages": [
            {"name": "flutter", "version": "3.22.0", "output_path": "sbom.json"},
            {"name": "http", "version": "1.2.0", "output_path": "sbom.json"},
        ],
    }


def test_empty_successful_inventories_remain_assessed() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "dependencies": {"direct": [], "development": [], "resolved": []},
            },
            "syft_outputs": {"sbom.json": {"artifacts": []}},
        }
    )

    inventory = FlutterDependencyInventory(context)

    assert inventory.metadata_assessed is True
    assert inventory.sbom_assessed is True
    assert inventory.declared == []
    assert inventory.resolved == []
    assert inventory.sbom_packages == []


def test_missing_or_partial_inventories_remain_unassessed() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "dependencies": {"direct": [], "development": []},
            },
            "syft_outputs": {"sbom.json": None},
        }
    )

    inventory = FlutterDependencyInventory(context)

    assert inventory.metadata_assessed is False
    assert inventory.sbom_assessed is False
    assert inventory.declared == []
    assert inventory.resolved == []
    assert inventory.sbom_packages == []

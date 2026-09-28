"""Syft owns resolved dependencies; source metadata supplies declarations."""

from domain.post_scan.flutter import FlutterDependencyInventory, FlutterScanExtractionContext


def test_syft_is_the_only_source_of_resolved_dependencies():
    loaded = {
        "source_metadata": {
            "dependencies": {
                "direct": [{"name": "http", "constraint": "^1.2.0", "source": "hosted"}],
                "development": [],
                "resolved": [{"name": "legacy_parser", "version": "wrong"}],
            }
        },
        "syft_outputs": {
            "sbom.json": {
                "artifacts": [
                    {"name": "http", "version": "1.2.0", "type": "dart-pub", "metadata": {"hosted_url": "pub.dev"}},
                    {"name": "http", "version": "1.2.0", "type": "dart-pub", "metadata": {"hosted_url": "pub.dev"}},
                    {"name": "native_dependency", "version": "2", "type": "java-archive"},
                ]
            }
        },
    }
    inventory = FlutterDependencyInventory(FlutterScanExtractionContext(loaded))
    assert inventory.metadata_assessed and inventory.sbom_assessed
    assert len(inventory.resolved) == 1
    assert inventory.resolved[0].name == "http"
    assert inventory.resolved[0].version == "1.2.0"
    assert inventory.resolved[0].dependency_kind == "direct"
    assert inventory.resolved[0].hosted_url == "pub.dev"
    assert len(inventory.sbom_packages) == 2


def test_empty_successful_inventory_is_different_from_unavailable_inventory():
    loaded = {"source_metadata": {"dependencies": {"direct": [], "development": []}}}
    missing = FlutterDependencyInventory(FlutterScanExtractionContext(loaded))
    assert missing.metadata_assessed
    assert not missing.sbom_assessed
    assert missing.resolved == []
    loaded["syft_outputs"] = {"sbom.json": {"artifacts": []}}
    empty = FlutterDependencyInventory(FlutterScanExtractionContext(loaded))
    assert empty.sbom_assessed
    assert empty.resolved == []

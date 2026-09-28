"""Read the canonical Syft inventory without reparsing package lockfiles."""

from typing import Any


def syft_assessed(loaded_outputs: dict[str, Any]) -> bool:
    outputs = loaded_outputs.get("syft_outputs") or {}
    report = outputs.get("sbom.json") if isinstance(outputs, dict) else None
    return isinstance(report, dict) and report.get("success") is not False and isinstance(report.get("artifacts"), list)


def syft_packages(loaded_outputs: dict[str, Any], ecosystem: str | None = None) -> list[dict[str, Any]]:
    if not syft_assessed(loaded_outputs):
        return []
    return [
        package
        for package in loaded_outputs["syft_outputs"]["sbom.json"]["artifacts"]
        if isinstance(package, dict) and package.get("name") and (ecosystem is None or package.get("type") == ecosystem)
    ]

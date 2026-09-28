"""Read the canonical Syft inventory without reparsing package lockfiles."""

from typing import Any

from domain.report.models import SbomPackage, SbomSummary


def summarize_sbom(loaded_outputs: dict[str, Any]) -> SbomSummary:
    if not syft_assessed(loaded_outputs):
        outputs = loaded_outputs.get("syft_outputs") or {}
        report = outputs.get("sbom.json") if isinstance(outputs, dict) else None
        if isinstance(report, dict) and report.get("success") is False:
            return SbomSummary(status="Failed", reason=str(report.get("error") or "Syft did not complete."))
        return SbomSummary()
    packages = {}
    for package in syft_packages(loaded_outputs):
        item = SbomPackage(
            name=str(package["name"]),
            version=str(package.get("version") or ""),
            ecosystem=str(package.get("type") or ""),
            purl=str(package.get("purl") or ""),
            locations=tuple(
                sorted(
                    {
                        str(location["path"])
                        for location in package.get("locations", ())
                        if isinstance(location, dict) and location.get("path")
                    }
                )
            ),
        )
        key = (item.name, item.version, item.ecosystem, item.purl)
        if key in packages:
            previous = packages[key]
            item = SbomPackage(
                item.name,
                item.version,
                item.ecosystem,
                item.purl,
                tuple(sorted(set(previous.locations + item.locations))),
            )
        packages[key] = item
    return SbomSummary("Completed", "", tuple(packages[key] for key in sorted(packages)))


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

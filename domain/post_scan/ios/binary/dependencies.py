"""Combine existing tool metadata into an evidence-based iOS dependency inventory."""

from collections.abc import Mapping
from dataclasses import replace
from pathlib import PurePosixPath

from domain.report.models import IOSBinaryReportDetails, IOSDependency, IOSDependencyInventory, ReportData


def ios_dependencies(outputs: Mapping) -> IOSDependencyInventory:
    items: dict[str, IOSDependency] = {}
    notes = []
    libraries: set[str] = set()
    main_names: set[str] = set()
    modules: dict[str, dict] = {}
    macho_complete = False
    swift_complete = False
    for document in (outputs.get("lief_outputs") or {}).values():
        if not isinstance(document, Mapping):
            continue
        binary = document.get("binary") or {}
        if binary.get("kind") != "main":
            continue
        main_names.add(str(binary.get("name", "")))
        slices = binary.get("slices") or []
        macho_complete |= bool(slices) and not binary.get("error")
        for slice_data in slices:
            libraries.update(str(path) for path in slice_data.get("libraries", ()) if path)

    for document in (outputs.get("ipsw_outputs") or {}).values():
        if not isinstance(document, Mapping) or (document.get("binary") or {}).get("kind") != "main":
            continue
        main_names.add(str(document["binary"].get("name", "")))
        swift = (document.get("analysis") or {}).get("swift_modules") or {}
        swift_complete |= swift.get("status") == "SUCCESS"
        for module in swift.get("modules", ()):
            modules[module["name"]] = module

    plists = outputs.get("plist_outputs") or {}
    index = outputs.get("plist_index") or {}
    paths = set(index.get("embedded_paths", ()))
    # Preserve useful metadata when regenerating older scans without the path inventory.
    for source in plists:
        for parent in PurePosixPath(source).parents:
            if parent.suffix in {".bundle", ".framework"}:
                paths.add(str(parent))
    for path in sorted(paths):
        location = PurePosixPath(path)
        kind = {".bundle": "Resource bundle", ".framework": "Framework", ".dylib": "Dynamic library"}.get(
            location.suffix
        )
        if not kind:
            continue
        document = plists.get(f"{path}/Info.json") or {}
        plist = document.get("plist") or {}
        if kind == "Resource bundle" and plist.get("CFBundleExecutable"):
            kind = "Bundle"
        evidence = ["Embedded in the app bundle."]
        if location.suffix != ".dylib":
            evidence.append("Info.plist metadata." if plist else "Info.plist metadata unavailable.")
        items[path] = IOSDependency(
            name=str(plist.get("CFBundleName") or location.stem),
            kind=kind,
            linkage="Not applicable" if kind == "Resource bundle" else "Unknown",
            version=str(plist.get("CFBundleShortVersionString") or ""),
            build=str(plist.get("CFBundleVersion") or ""),
            bundle_id=str(plist.get("CFBundleIdentifier") or ""),
            minimum_os=str(plist.get("MinimumOSVersion") or ""),
            executable=str(plist.get("CFBundleExecutable") or ""),
            paths=(path,),
            evidence=tuple(evidence),
        )

    for library in sorted(libraries):
        location = PurePosixPath(library)
        framework = next((p for p in location.parents if p.suffix == ".framework"), None)
        system = library.startswith(("/System/Library/", "/usr/lib/"))
        name = framework.stem if framework else location.name
        # Match complete framework/executable suffixes, not arbitrary module-name substrings.
        embedded = (
            [
                key
                for key, item in items.items()
                if (item.kind == "Framework" and framework and key.endswith(f"/{framework.name}"))
                or (item.kind == "Dynamic library" and library.endswith(f"/{key.removeprefix('Frameworks/')}"))
            ]
            if not system
            else []
        )
        evidence = "Mach-O load command."
        if len(embedded) == 1:
            key = embedded[0]
            items[key] = replace(
                items[key],
                linkage="Dynamic",
                paths=(*items[key].paths, library),
                evidence=(*items[key].evidence, evidence),
            )
        else:
            items[library] = IOSDependency(
                name=name,
                kind="Apple System" if system else "Framework" if framework else "Dynamic library",
                linkage="Dynamic",
                paths=(library,),
                evidence=(evidence,),
            )

    app_modules = {name.replace(" ", "_").replace("-", "_") for name in main_names}
    for name, module in sorted(modules.items()):
        if name in app_modules | {"Swift", "__C", "__C_Synthesized"}:
            continue
        evidence = (
            f"Swift types in main executable: {module['type_count']} (ipsw).",
            "Examples: " + ", ".join(module.get("examples", ())),
        )
        matches = [key for key, item in items.items() if item.name == name and item.kind != "Resource bundle"]
        if len(matches) == 1:
            key = matches[0]
            items[key] = replace(items[key], evidence=(*items[key].evidence, *evidence))
        else:
            items[f"module:{name}"] = IOSDependency(
                name=name,
                kind="Swift module",
                linkage="Static (inferred)" if macho_complete else "Unknown",
                paths=tuple(sorted(main_names)),
                evidence=evidence,
            )

    if not macho_complete:
        notes.append("Main executable linked-library metadata is unavailable or incomplete.")
    if not swift_complete:
        notes.append("Swift module extraction is unavailable or incomplete; retained observations may be partial.")
    if "embedded_paths" not in index or index.get("parse_failures"):
        notes.append("Embedded bundle inventory or plist metadata is unavailable or incomplete.")
    return IOSDependencyInventory(
        status="Partial" if notes and items else "Not evaluated" if notes else "Completed",
        notes=tuple(notes),
        items=tuple(
            sorted(items.values(), key=lambda item: (item.kind == "Apple System", item.kind, item.name, item.paths))
        ),
    )


def with_dependency_observations(report: ReportData) -> ReportData:
    """Retain OpenGrep library references without treating strings as load commands."""
    if not isinstance(report.platform_details, IOSBinaryReportDetails):
        return report
    inventory = report.platform_details.dependencies
    items = list(inventory.items)
    known_paths = {path for item in items for path in item.paths}
    for observation in report.inventories:
        if observation.platform != "ios" or observation.category != "Frameworks":
            continue
        for entry in observation.values:
            if entry.value in known_paths:
                continue
            path = PurePosixPath(entry.value)
            framework = next((parent for parent in path.parents if parent.suffix == ".framework"), None)
            items.append(
                IOSDependency(
                    name=framework.stem if framework else path.name,
                    kind="Library reference",
                    paths=(entry.value,),
                    evidence=(f"OpenGrep observation: {observation.title}. Linkage not established.", *entry.locations),
                )
            )
            known_paths.add(entry.value)
    inventory = replace(
        inventory,
        status="Partial" if items and inventory.status == "Not evaluated" else inventory.status,
        items=tuple(sorted(items, key=lambda item: (item.kind == "Apple System", item.kind, item.name, item.paths))),
    )
    return replace(report, platform_details=replace(report.platform_details, dependencies=inventory))

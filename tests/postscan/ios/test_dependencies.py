import json
from dataclasses import asdict, replace

from adapters.output.phoenix_report.builders.ios import IOSBinaryReportDataBuilder
from adapters.output.phoenix_report.pdf_report import PdfReportGenerator
from application.report_generation_service import ReportGenerationService
from domain.post_scan.ios.binary.dependencies import ios_dependencies, with_dependency_observations
from domain.report.models import InventoryValue, ReportData, RuleObservation


def _outputs():
    return {
        "lief_outputs": {
            "App.json": {
                "binary": {
                    "kind": "main",
                    "name": "App",
                    "slices": [
                        {
                            "libraries": [
                                "/System/Library/Frameworks/SwiftUI.framework/SwiftUI",
                                "@rpath/AWSSNS.framework/AWSSNS",
                                "@rpath/libExample.dylib",
                            ]
                        },
                        {"libraries": ["@rpath/AWSSNS.framework/AWSSNS"]},
                    ],
                }
            }
        },
        "ipsw_outputs": {
            "App.json": {
                "binary": {"kind": "main", "name": "App"},
                "analysis": {
                    "swift_modules": {
                        "status": "SUCCESS",
                        "modules": [
                            {"name": name, "type_count": 4, "examples": ["Example"]}
                            for name in ("App", "BoxSdkGen", "Algorithms", "PrivateModule", "Swift", "__C")
                        ],
                    },
                },
            }
        },
        "plist_index": {
            "parse_failures": 0,
            "embedded_paths": [
                "Frameworks/AWSSNS.framework",
                "Frameworks/libExample.dylib",
                "BoxSDKSuite_BoxSdkGen.bundle",
                "NoPlist.bundle",
            ],
        },
        "plist_outputs": {
            "Frameworks/AWSSNS.framework/Info.json": {
                "plist": {
                    "CFBundleName": "AWSSNS",
                    "CFBundleIdentifier": "com.amazonaws.AWSSNS",
                    "CFBundleShortVersionString": "2.41.0",
                    "CFBundleVersion": "1",
                    "MinimumOSVersion": "12.0",
                    "CFBundleExecutable": "AWSSNS",
                }
            },
            "BoxSDKSuite_BoxSdkGen.bundle/Info.json": {
                "plist": {
                    "CFBundleIdentifier": "box-ios-sdk.BoxSdkGen.resources",
                }
            },
        },
    }


def test_inventory_combines_metadata_without_guessing_package_versions_or_bundle_linkage():
    inventory = ios_dependencies(_outputs())
    by_name = {item.name: item for item in inventory.items}
    assert inventory.status == "Completed"
    assert by_name["AWSSNS"].version == "2.41.0"
    assert by_name["AWSSNS"].build == "1"
    assert by_name["AWSSNS"].minimum_os == "12.0"
    assert by_name["AWSSNS"].linkage == "Dynamic"
    assert len(by_name["AWSSNS"].paths) == 2  # Fat-binary duplicate libraries collapse.
    assert by_name["libExample"].linkage == "Dynamic"
    assert by_name["SwiftUI"].kind == "Apple System"
    assert by_name["BoxSDKSuite_BoxSdkGen"].kind == "Resource bundle"
    assert by_name["BoxSDKSuite_BoxSdkGen"].linkage == "Not applicable"
    assert by_name["NoPlist"].version == ""
    assert "Info.plist metadata unavailable." in by_name["NoPlist"].evidence
    for name in ("BoxSdkGen", "Algorithms", "PrivateModule"):
        assert by_name[name].kind == "Swift module"
        assert by_name[name].linkage == "Static (inferred)"
        assert by_name[name].version == ""
    assert not {"App", "Swift", "__C"} & by_name.keys()


def test_partial_and_missing_evidence_does_not_become_a_complete_inventory():
    outputs = _outputs()
    outputs["ipsw_outputs"]["App.json"]["analysis"]["swift_modules"]["status"] = "TIMEOUT"
    outputs["lief_outputs"] = {"App.json": None}
    outputs["plist_index"]["parse_failures"] = 1
    inventory = ios_dependencies(outputs)
    assert inventory.status == "Partial"
    assert len(inventory.notes) == 3
    assert next(item for item in inventory.items if item.name == "BoxSdkGen").linkage == "Unknown"
    assert ios_dependencies({}).status == "Not evaluated"


def test_inventory_survives_json_round_trip_and_pdf_mapping():
    report = ReportGenerationService([IOSBinaryReportDataBuilder()]).build_report_data(
        {
            "target_information": {"target_kind": "ios_binary", "platform": "ios", "target_type": "binary"},
            "dependencies": asdict(ios_dependencies(_outputs())),
        }
    )
    saved = json.loads(json.dumps(report.to_dict()))
    restored = ReportData.from_dict(saved)
    assert restored == report
    assert PdfReportGenerator._presentation_data(restored)["ios_dependencies"] == asdict(
        report.platform_details.dependencies
    )
    assert sum(asdict(report.findings_severity).values()) == 0
    report = with_dependency_observations(
        replace(
            report,
            inventories=(
                RuleObservation(
                    category="Frameworks",
                    title="External libraries",
                    rule_id="ios.binary.libraries",
                    platform="ios",
                    severity="info",
                    description="Library references",
                    execution_status="success",
                    values=(
                        InventoryValue("@rpath/AWSSNS.framework/AWSSNS", ("strings/App.txt:1",)),
                        InventoryValue("@rpath/Unconfirmed.framework/Unconfirmed", ("strings/App.txt:2",)),
                    ),
                ),
            ),
        )
    )
    items = report.platform_details.dependencies.items
    assert len([item for item in items if item.name == "AWSSNS"]) == 1
    reference = next(item for item in items if item.name == "Unconfirmed")
    assert reference.kind == "Library reference"
    assert reference.linkage == "Unknown"
    assert "strings/App.txt:2" in reference.evidence
    del saved["platform_details"]["dependencies"]
    assert ReportData.from_dict(saved).platform_details.dependencies.status == "Not evaluated"

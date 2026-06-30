from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from adapters.binary_scanners.androguard_scanner import AndroguardScanner
from domain.models import ScanConfig, ScanType

EXPECTED_ARTIFACTS = [
    "metadata.json",
    "manifest.json",
    "permissions.json",
    "components.json",
    "strings.json",
    "api_calls.json",
    "xrefs.json",
    "native_libs.json",
    "assets.json",
    "certificates.json",
    "files.json",
    "findings.json",
    "report_summary.json",
    "scan_index.json",
    "errors.json",
]


class FakeName:
    def __init__(self, native):
        self.native = native


class FakeCertificate:
    subject = FakeName({"common_name": "AppcritIQ Test"})
    issuer = FakeName({"common_name": "AppcritIQ CA"})
    serial_number = 12345
    not_valid_before = "2026-01-01 00:00:00+00:00"
    not_valid_after = "2027-01-01 00:00:00+00:00"

    def dump(self):
        return b"certificate-bytes"


class FakeClassAnalysis:
    name = "Lcom/example/LoginActivity;"


class FakeMethodAnalysis:
    def __init__(
        self,
        class_name,
        name,
        descriptor,
        *,
        method_text="",
        external=False,
        xrefs_to=None,
    ):
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor
        self.full_name = f"{class_name} {name} {descriptor}"
        self.method = method_text or self.full_name
        self._external = external
        self._xrefs_to = xrefs_to or []

    def is_external(self):
        return self._external

    def get_xref_to(self):
        return self._xrefs_to


class FakeStringAnalysis:
    def __init__(self, value, xrefs):
        self._value = value
        self._xrefs = xrefs

    def get_value(self):
        return self._value

    def get_xref_from(self):
        return self._xrefs


class FakeAnalysis:
    def __init__(self):
        self.callee = FakeMethodAnalysis(
            "Ljava/lang/Runtime;",
            "exec",
            "(Ljava/lang/String;)Ljava/lang/Process;",
            method_text=("Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"),
            external=True,
        )
        self.caller = FakeMethodAnalysis(
            "Lcom/example/LoginActivity;",
            "runCommand",
            "()V",
            xrefs_to=[(FakeClassAnalysis(), self.callee, 12)],
        )
        self.string_method = FakeMethodAnalysis(
            "Lcom/example/LoginActivity;",
            "login",
            "()V",
        )

    def get_strings(self):
        return [
            FakeStringAnalysis(
                "https://api.example.com/auth?token=abc",
                [(FakeClassAnalysis(), self.string_method)],
            ),
            FakeStringAnalysis("ordinary text", []),
        ]

    def get_methods(self):
        return [self.caller, self.callee]


class FakeApk:
    def get_package(self):
        return "com.example.app"

    def get_app_name(self):
        return "Example"

    def get_androidversion_code(self):
        return "7"

    def get_androidversion_name(self):
        return "1.2.3"

    def get_min_sdk_version(self):
        return "23"

    def get_target_sdk_version(self):
        return "35"

    def get_android_manifest_xml(self):
        return ElementTree.Element("manifest", {"package": "com.example.app"})

    def get_permissions(self):
        return [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
        ]

    def get_declared_permissions(self):
        return {"com.example.PRIVATE": {}}

    def get_main_activity(self):
        return "com.example.LoginActivity"

    def get_activities(self):
        return ["com.example.LoginActivity"]

    def get_services(self):
        return []

    def get_receivers(self):
        return ["com.example.SyncReceiver"]

    def get_providers(self):
        return ["com.example.DataProvider"]

    def get_intent_filters(self, component_type, name):
        if name == "com.example.SyncReceiver":
            return {"action": ["com.example.SYNC"]}
        if name == "com.example.LoginActivity":
            return {
                "action": ["android.intent.action.MAIN"],
                "category": ["android.intent.category.LAUNCHER"],
            }
        return {}

    def get_attribute_value(self, component_type, name, attribute):
        values = {
            ("activity", "com.example.LoginActivity", "exported"): "true",
            ("provider", "com.example.DataProvider", "permission"): ("com.example.PRIVATE"),
        }
        return values.get((component_type, name, attribute))

    def get_certificates(self):
        return [FakeCertificate()]

    def get_certificates_v1(self):
        return [FakeCertificate()]

    def get_certificates_v2(self):
        return []

    def get_certificates_v3(self):
        return []


def make_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
        archive.writestr("assets/config.json", b"{}")
        archive.writestr("lib/arm64-v8a/libnative.so", b"native")
    return path


def scan_config(apk_path: Path) -> ScanConfig:
    return ScanConfig(
        project_path=apk_path,
        output_path=apk_path.parent / "scan-results",
        mode="binary",
        enabled_scans=[ScanType.ANDROGUARD],
    )


def results_by_path(results):
    return {result.relative_target_path: json.loads(result.raw_output) for result in results}


def test_androguard_scan_skips_non_apk(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    target.write_text("not an apk")

    results = AndroguardScanner().scan(scan_config(target))

    assert len(results) == 1
    assert results[0].skipped
    assert "APK files" in results[0].error_message


def test_androguard_scan_skips_when_dependency_is_unavailable(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    scanner = AndroguardScanner()
    monkeypatch.setattr(scanner, "_load_apk", lambda _: (_ for _ in ()).throw(ImportError))

    results = scanner.scan(scan_config(apk_path))

    assert len(results) == 1
    assert results[0].skipped
    assert "not installed" in results[0].error_message


def test_androguard_scan_emits_expected_json_outputs(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    scanner = AndroguardScanner()
    monkeypatch.setattr(
        scanner,
        "_load_apk",
        lambda _: (FakeApk(), [], FakeAnalysis()),
    )

    results = scanner.scan(scan_config(apk_path))
    outputs = results_by_path(results)

    assert [result.relative_target_path for result in results] == EXPECTED_ARTIFACTS
    assert all(result.success for result in results)
    assert set(outputs) == set(EXPECTED_ARTIFACTS)
    assert outputs["errors.json"] == {"errors": []}

    component = outputs["components.json"]["receivers"][0]
    assert component["name"] == "com.example.SyncReceiver"
    assert component["exported"] is None
    assert component["has_intent_filters"] is True
    assert component["intent_filters"] == {"action": ["com.example.SYNC"]}

    certificate = outputs["certificates.json"]["all"][0]
    assert certificate["subject"] == {"common_name": "AppcritIQ Test"}
    assert certificate["issuer"] == {"common_name": "AppcritIQ CA"}
    assert certificate["sha1"] == hashlib.sha1(b"certificate-bytes").hexdigest()
    assert certificate["sha256"] == hashlib.sha256(b"certificate-bytes").hexdigest()

    string_items = outputs["strings.json"]["items"]
    assert [item["value"] for item in string_items] == ["https://api.example.com/auth?token=abc"]
    assert {"url", "domain", "token", "auth"} <= set(string_items[0]["categories"])

    api_items = outputs["api_calls.json"]["items"]
    assert len(api_items) == 1
    assert api_items[0]["categories"] == ["runtime_exec"]
    assert api_items[0]["caller"]["method_name"] == "runCommand"

    relationships = {item["relationship"] for item in outputs["xrefs.json"]["items"]}
    assert "STRING_TO_METHOD" in relationships
    assert "METHOD_TO_SENSITIVE_API" in relationships

    finding_ids = {item["id"] for item in outputs["findings.json"]["items"]}
    assert "android-sensitive-permissions" in finding_ids
    assert "android-component-attack-surface" in finding_ids
    assert "android-api-runtime_exec" in finding_ids
    assert "android-string-token" in finding_ids

    summary = outputs["report_summary.json"]
    assert summary["package"] == "com.example.app"
    assert summary["finding_count"] == len(outputs["findings.json"]["items"])
    assert summary["api_category_counts"]["runtime_exec"] == 1
    assert summary["string_category_counts"]["token"] == 1

    scan_index_names = {item["name"] for item in outputs["scan_index.json"]["artifacts"]}
    assert "report_summary.json" in scan_index_names
    assert "errors.json" in scan_index_names


def test_androguard_scan_records_extractor_failure_and_continues(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    scanner = AndroguardScanner()
    monkeypatch.setattr(
        scanner,
        "_load_apk",
        lambda _: (FakeApk(), [], FakeAnalysis()),
    )

    def fail_metadata(_androguard_context):
        raise ValueError("metadata broke")

    monkeypatch.setattr(scanner, "_extract_metadata", fail_metadata)

    outputs = results_by_path(scanner.scan(scan_config(apk_path)))

    assert outputs["metadata.json"] == {"items": [], "partial_failure": True}
    assert outputs["errors.json"] == {"errors": [{"artifact": "metadata.json", "error": "metadata broke"}]}
    assert outputs["components.json"]["activities"][0]["name"] == ("com.example.LoginActivity")

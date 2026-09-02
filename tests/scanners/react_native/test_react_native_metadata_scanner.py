from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest

from adapters.scanners.react_native.react_native_metadata_scanner import ReactNativeMetadataScanner
from domain.models import ScanConfig, ScanType

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def test_scanner_metadata() -> None:
    scanner = ReactNativeMetadataScanner()

    assert scanner.scan_type is ScanType.REACT_NATIVE_METADATA
    assert scanner.name == "React Native Metadata Scanner"
    assert scanner.is_available() is True
    assert "metadata" in scanner.description.lower()


def test_recognizes_committed_react_native_project_fixture(tmp_path: Path) -> None:
    project = Path(__file__).parent / "fixtures" / "project"

    result = ReactNativeMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert result.skipped is False
    assert payload["identity"]["package_name"] == "phoenix-react-native-fixture"
    assert payload["identity"]["display_name"] == "Phoenix React Native Fixture"
    assert payload["framework"]["react_native_version"] == "0.81.0"
    assert payload["framework"]["typescript"] is True


def test_extracts_javascript_project_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(
        project / "package.json",
        {
            "name": "example-app",
            "displayName": "Ignored package display name",
            "description": "Example React Native application",
            "version": "1.2.3",
            "private": True,
            "main": "src/main.js",
            "packageManager": "yarn@4.9.2",
            "engines": {"node": ">=20", "yarn": ">=4", "npm": 10},
            "dependencies": {
                "react": "19.1.0",
                "react-native": "0.81.0",
                "workspace-package": "workspace:*",
            },
            "devDependencies": {"jest": "^30.0.0"},
        },
    )
    _write_json(project / "app.json", {"name": "ExampleApp", "displayName": "Example App"})
    _write(project / "src/main.js", "")
    _write(project / "index.js", "")
    _write(project / "yarn.lock", "")

    result = ReactNativeMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert result.skipped is False
    assert result.relative_target_path == "project_metadata.json"
    assert payload["schema_version"] == "1.0"
    assert payload["extraction"] == {"status": "complete", "warnings": []}
    assert payload["project"] == {
        "app_json_path": "app.json",
        "lockfiles": ["yarn.lock"],
        "package_json_path": "package.json",
        "package_manager": "yarn",
        "project_path": str(project.resolve()),
    }
    assert payload["identity"] == {
        "app_name": "ExampleApp",
        "description": "Example React Native application",
        "display_name": "Example App",
        "package_name": "example-app",
        "private": True,
        "slug": "",
        "version": "1.2.3",
    }
    assert payload["framework"] == {
        "expo_version": "",
        "react_native_version": "0.81.0",
        "react_version": "19.1.0",
        "typescript": False,
    }
    assert payload["engines"] == {"node": ">=20", "npm": "", "pnpm": "", "yarn": ">=4"}
    assert payload["platforms"] == {"android": False, "ios": False}
    assert payload["entrypoints"] == {
        "expo_router_path": "",
        "files": ["src/main.js", "index.js"],
        "package_main": "src/main.js",
    }
    assert payload["dependencies"]["direct"] == [
        {"constraint": "19.1.0", "name": "react", "source": "registry"},
        {"constraint": "0.81.0", "name": "react-native", "source": "registry"},
        {"constraint": "workspace:*", "name": "workspace-package", "source": "workspace"},
    ]
    assert payload["dependencies"]["development"] == [{"constraint": "^30.0.0", "name": "jest", "source": "registry"}]
    assert payload["android"] == {"available": False, "metadata": None, "project_path": ""}
    assert payload["ios"] == {"available": False, "metadata": None, "project_path": ""}


def test_extracts_static_expo_identity_and_typescript_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(
        project / "package.json",
        {
            "dependencies": {"expo": "~54.0.0", "react-native": "0.81.0"},
        },
    )
    _write_json(
        project / "app.json",
        {
            "expo": {
                "name": "Expo Example",
                "slug": "expo-example",
                "version": "2.3.4",
            }
        },
    )
    _write(project / "app/home.tsx", "")

    payload = _payload(project, tmp_path)

    assert payload["identity"]["app_name"] == "Expo Example"
    assert payload["identity"]["display_name"] == "Expo Example"
    assert payload["identity"]["slug"] == "expo-example"
    assert payload["identity"]["version"] == "2.3.4"
    assert payload["framework"]["expo_version"] == "~54.0.0"
    assert payload["framework"]["typescript"] is True
    assert payload["entrypoints"]["expo_router_path"] == "app"


@pytest.mark.parametrize(
    ("constraint", "source"),
    (
        ("^1.0.0", "registry"),
        ("workspace:*", "workspace"),
        ("file:../local", "path"),
        ("../local", "path"),
        ("owner/repository#main", "git"),
        ("git+https://example.com/repository.git#main", "git"),
        ("https://example.com/package.tgz", "url"),
        (None, "unknown"),
    ),
)
def test_classifies_declared_dependency_sources(
    tmp_path: Path,
    constraint: object,
    source: str,
) -> None:
    project = tmp_path / "project"
    _write_json(
        project / "package.json",
        {
            "dependencies": {
                "example": constraint,
                "react-native": "0.81.0",
            }
        },
    )

    dependency = next(
        item for item in _payload(project, tmp_path)["dependencies"]["direct"] if item["name"] == "example"
    )

    assert dependency["source"] == source


def test_reports_conflicting_package_manager_evidence(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(
        project / "package.json",
        {
            "packageManager": "npm@11.0.0",
            "dependencies": {"react-native": "0.81.0"},
        },
    )
    _write(project / "pnpm-lock.yaml", "")
    _write(project / "yarn.lock", "")

    payload = _payload(project, tmp_path)

    assert payload["project"]["package_manager"] == "npm"
    assert payload["project"]["lockfiles"] == ["pnpm-lock.yaml", "yarn.lock"]
    assert payload["extraction"]["status"] == "partial"
    assert payload["extraction"]["warnings"] == [
        "Multiple package-manager lockfiles found: pnpm-lock.yaml, yarn.lock.",
        "packageManager declares npm, but the selected lockfile belongs to pnpm.",
    ]


def test_rejects_entrypoints_outside_project(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(
        project / "package.json",
        {
            "main": "../outside.ts",
            "dependencies": {"react-native": "0.81.0"},
        },
    )
    _write(tmp_path / "outside.ts", "")

    payload = _payload(project, tmp_path)

    assert payload["entrypoints"]["package_main"] == ""
    assert payload["entrypoints"]["files"] == []
    assert payload["framework"]["typescript"] is False


def test_extracts_embedded_android_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(project / "package.json", {"version": "9.9.9", "dependencies": {"react-native": "0.81.0"}})
    _write(
        project / "android/app/build.gradle",
        """
plugins { id "com.android.application" }
android {
    namespace "com.example.namespace"
    defaultConfig {
        applicationId "com.example.app"
        versionName "1.2.3"
        versionCode 42
    }
}
""",
    )
    _write(
        project / "android/app/src/main/AndroidManifest.xml",
        f"""
<manifest xmlns:android="{ANDROID_NS}">
    <uses-permission android:name="android.permission.CAMERA" />
    <application android:label="Example">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
""",
    )

    payload = _payload(project, tmp_path)
    android = payload["android"]

    assert payload["platforms"]["android"] is True
    assert android["available"] is True
    assert android["project_path"] == "android"
    assert android["metadata"]["identity"]["package_name"] == "com.example.app"
    assert android["metadata"]["identity"]["version_name"] == "1.2.3"
    assert android["metadata"]["permissions"] == [{"max_sdk_version": "", "name": "android.permission.CAMERA"}]


def test_android_failure_produces_partial_react_native_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(project / "package.json", {"dependencies": {"react-native": "0.81.0"}})
    _write(project / "android/app/src/main/AndroidManifest.xml", "<manifest>")

    result = ReactNativeMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert payload["extraction"]["status"] == "partial"
    assert payload["android"] == {"available": True, "metadata": None, "project_path": "android"}
    assert payload["extraction"]["warnings"][0].startswith("Android metadata: Unable to parse")


def test_extracts_ios_identity_and_security_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(project / "package.json", {"dependencies": {"react-native": "0.81.0"}})
    _write(
        project / "ios/Example.xcodeproj/project.pbxproj",
        """
PRODUCT_NAME = ExampleApp;
PRODUCT_BUNDLE_IDENTIFIER = com.example.app;
MARKETING_VERSION = 1.2.3;
CURRENT_PROJECT_VERSION = 42;
IPHONEOS_DEPLOYMENT_TARGET = 15.0;
INFOPLIST_FILE = $(SRCROOT)/Example/Info.plist;
""",
    )
    _write_plist(
        project / "ios/Example/Info.plist",
        {
            "CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)",
            "CFBundleName": "$(PRODUCT_NAME)",
            "CFBundleExecutable": "$(EXECUTABLE_NAME)",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "$(MARKETING_VERSION)",
            "CFBundleVersion": "$(CURRENT_PROJECT_VERSION)",
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False},
            "NSCameraUsageDescription": "Take photos",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["example"]}],
            "LSApplicationQueriesSchemes": ["partner-app"],
            "UIBackgroundModes": ["fetch"],
        },
    )
    _write_plist(
        project / "ios/Example/Example.entitlements",
        {
            "aps-environment": "development",
            "com.apple.developer.associated-domains": ["applinks:example.com"],
        },
    )
    _write_plist(
        project / "ios/Example/PrivacyInfo.xcprivacy",
        {
            "NSPrivacyTracking": True,
            "NSPrivacyTrackingDomains": ["tracking.example.com"],
        },
    )
    _write_plist(project / "ios/Pods/Dependency/Dependency.entitlements", {"aps-environment": "production"})

    payload = _payload(project, tmp_path)
    ios = payload["ios"]
    metadata = ios["metadata"]

    assert payload["platforms"]["ios"] is True
    assert ios["available"] is True
    assert metadata["xcode_project_path"] == "Example.xcodeproj/project.pbxproj"
    assert metadata["info_plist_path"] == "Example/Info.plist"
    assert metadata["identity"]["bundle_identifier"] == "com.example.app"
    assert metadata["identity"]["version"] == "1.2.3"
    assert metadata["identity"]["build"] == "42"
    assert metadata["identity"]["minimum_os"] == "15.0"
    assert metadata["permissions"] == [{"key": "NSCameraUsageDescription", "purpose": "Take photos"}]
    assert metadata["app_transport_security"]["allows_arbitrary_loads"] is False
    assert metadata["url_schemes"]["declared_schemes"] == ["example"]
    assert metadata["url_schemes"]["queried_schemes"] == ["partner-app"]
    assert metadata["background_modes"] == ["fetch"]
    assert metadata["entitlements"] == [
        {
            "metadata": {
                "application_groups": [],
                "application_identifier": "",
                "aps_environment": "development",
                "associated_domains": ["applinks:example.com"],
                "healthkit": False,
                "icloud_containers": [],
                "in_app_payments": [],
                "keychain_access_groups": [],
            },
            "path": "Example/Example.entitlements",
        }
    ]
    assert len(metadata["privacy_manifests"]) == 1
    assert metadata["privacy_manifests"][0]["metadata"]["tracking"] is True


def test_unresolved_ios_value_and_malformed_supporting_plist_are_partial(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(project / "package.json", {"dependencies": {"react-native": "0.81.0"}})
    _write(
        project / "ios/Example.xcodeproj/project.pbxproj",
        "INFOPLIST_FILE = Example/Info.plist;\n",
    )
    _write_plist(
        project / "ios/Example/Info.plist",
        {
            "CFBundleDisplayName": "$(APP_DISPLAY_NAME)",
            "CFBundleIdentifier": "com.example.app",
            "CFBundlePackageType": "APPL",
        },
    )
    _write(project / "ios/Example/Broken.entitlements", "not a plist")

    payload = _payload(project, tmp_path)

    assert payload["extraction"]["status"] == "partial"
    assert payload["ios"]["metadata"]["identity"]["display_name"] == "$(APP_DISPLAY_NAME)"
    assert payload["ios"]["metadata"]["entitlements"] == [{"metadata": None, "path": "Example/Broken.entitlements"}]
    assert any("APP_DISPLAY_NAME" in warning for warning in payload["extraction"]["warnings"])
    assert any("Broken.entitlements" in warning for warning in payload["extraction"]["warnings"])


def test_missing_ios_application_plist_is_partial(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(project / "package.json", {"dependencies": {"react-native": "0.81.0"}})
    _write(project / "ios/Example.xcodeproj/project.pbxproj", "PRODUCT_NAME = Example;")
    _write_plist(project / "ios/Pods/Dependency/Info.plist", {"CFBundlePackageType": "APPL"})

    payload = _payload(project, tmp_path)

    assert payload["ios"] == {"available": True, "metadata": None, "project_path": "ios"}
    assert payload["extraction"]["status"] == "partial"
    assert any("No application Info.plist" in warning for warning in payload["extraction"]["warnings"])


def test_malformed_optional_app_json_is_partial_for_recognized_project(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(project / "package.json", {"dependencies": {"react-native": "0.81.0"}})
    _write(project / "app.json", "{")

    result = ReactNativeMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert payload["extraction"]["status"] == "partial"
    assert payload["project"]["app_json_path"] == "app.json"
    assert payload["extraction"]["warnings"][0].startswith("Unable to parse app.json")


def test_non_directory_target_returns_failure(tmp_path: Path) -> None:
    target = tmp_path / "package.json"
    _write_json(target, {"dependencies": {"react-native": "0.81.0"}})

    result = ReactNativeMetadataScanner().scan(_config(target, tmp_path))[0]

    assert result.success is False
    assert result.skipped is False
    assert result.relative_target_path == "scan_summary.json"


def test_missing_package_json_returns_skipped_result(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    result = ReactNativeMetadataScanner().scan(_config(project, tmp_path))[0]

    assert result.success is False
    assert result.skipped is True
    assert result.relative_target_path == "scan_summary.json"


@pytest.mark.parametrize("content", ("{", "[]"))
def test_invalid_package_json_returns_failure(tmp_path: Path, content: str) -> None:
    project = tmp_path / "project"
    _write(project / "package.json", content)

    result = ReactNativeMetadataScanner().scan(_config(project, tmp_path))[0]

    assert result.success is False
    assert result.skipped is False
    assert result.relative_target_path == "scan_summary.json"


def test_unrelated_package_returns_skipped_result(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_json(project / "package.json", {"dependencies": {"react": "19.1.0"}})

    result = ReactNativeMetadataScanner().scan(_config(project, tmp_path))[0]

    assert result.success is False
    assert result.skipped is True
    assert "does not declare react-native or expo" in result.error_message


def _payload(project: Path, tmp_path: Path) -> dict:
    result = ReactNativeMetadataScanner().scan(_config(project, tmp_path))[0]
    assert result.success is True
    return json.loads(result.raw_output)


def _config(project: Path, tmp_path: Path) -> ScanConfig:
    return ScanConfig(
        project_path=project,
        output_path=tmp_path / "scan-results",
        mode="source",
        platform="ANY",
        stack="REACT_NATIVE",
    )


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, content: object) -> None:
    _write(path, json.dumps(content))


def _write_plist(path: Path, content: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(content))

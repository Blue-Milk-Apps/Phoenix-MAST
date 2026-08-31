from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest

from adapters.scanners.flutter import FlutterSourceMetadataScanner
from domain.models import ScanConfig, ScanType

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def test_scanner_metadata() -> None:
    scanner = FlutterSourceMetadataScanner()

    assert scanner.scan_type is ScanType.FLUTTER_SOURCE_METADATA
    assert scanner.name == "Flutter Source Metadata Scanner"
    assert scanner.is_available() is True
    assert "metadata" in scanner.description.lower()


def test_extracts_pubspec_identity_sdk_platforms_and_declared_dependencies(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(
        project / "pubspec.yaml",
        """
name: example_app
description: Example Flutter application
version: 1.2.3+42
publish_to: none
homepage: https://example.com
repository: https://example.com/repository
environment:
  sdk: ">=3.3.0 <4.0.0"
  flutter: ">=3.22.0"
dependencies:
  flutter:
    sdk: flutter
  git_package:
    git: https://example.com/package.git
  hosted_package:
    hosted: https://packages.example.com
    version: ^2.0.0
  http: ^1.2.0
  local_package:
    path: ../local_package
dev_dependencies:
  test: ^1.25.0
""",
    )
    (project / "web").mkdir()

    result = FlutterSourceMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert result.skipped is False
    assert result.relative_target_path == "project_metadata.json"
    assert payload["schema_version"] == "1.0"
    assert payload["extraction"] == {
        "status": "partial",
        "warnings": ["No pubspec.lock file found; resolved dependencies were not assessed."],
    }
    assert payload["project"] == {
        "project_path": str(project.resolve()),
        "pubspec_lock_path": "",
        "pubspec_path": "pubspec.yaml",
    }
    assert payload["identity"] == {
        "description": "Example Flutter application",
        "homepage": "https://example.com",
        "package_name": "example_app",
        "publish_to": "none",
        "repository": "https://example.com/repository",
        "version": "1.2.3+42",
        "version_code": "42",
        "version_name": "1.2.3",
    }
    assert payload["sdk"] == {
        "dart_constraint": ">=3.3.0 <4.0.0",
        "flutter_constraint": ">=3.22.0",
    }
    assert payload["platforms"] == {
        "android": False,
        "ios": False,
        "linux": False,
        "macos": False,
        "web": True,
        "windows": False,
    }
    assert payload["android"] == {"available": False, "metadata": None, "project_path": ""}
    assert payload["ios"] == {"available": False, "metadata": None, "project_path": ""}
    assert payload["dependencies"] == {
        "development": [{"constraint": "^1.25.0", "name": "test", "source": "hosted"}],
        "direct": [
            {"constraint": "flutter", "name": "flutter", "source": "sdk"},
            {"constraint": "", "name": "git_package", "source": "git"},
            {"constraint": "^2.0.0", "name": "hosted_package", "source": "hosted"},
            {"constraint": "^1.2.0", "name": "http", "source": "hosted"},
            {"constraint": "", "name": "local_package", "source": "path"},
        ],
        "resolved": [],
    }


def test_extracts_resolved_dependencies_from_pubspec_lock(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "pubspec.yaml", "name: example_app\n")
    _write(
        project / "pubspec.lock",
        """
packages:
  flutter:
    dependency: direct main
    description: flutter
    source: sdk
    version: "0.0.0"
  git_package:
    dependency: transitive
    description:
      path: .
      ref: main
      resolved-ref: abc123
      url: https://example.com/package.git
    source: git
    version: "1.0.0"
  hosted_package:
    dependency: direct main
    description:
      name: hosted_package
      sha256: abc123
      url: https://pub.dev
    source: hosted
    version: "2.3.4"
  local_package:
    dependency: direct dev
    description:
      path: ../local_package
      relative: true
    source: path
    version: "0.5.0"
""",
    )

    result = FlutterSourceMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert payload["extraction"] == {"status": "complete", "warnings": []}
    assert payload["project"]["pubspec_lock_path"] == "pubspec.lock"
    assert payload["dependencies"]["resolved"] == [
        {
            "dependency_kind": "direct",
            "hosted_url": "",
            "name": "flutter",
            "path": "",
            "source": "sdk",
            "vcs_url": "",
            "version": "0.0.0",
        },
        {
            "dependency_kind": "transitive",
            "hosted_url": "",
            "name": "git_package",
            "path": "",
            "source": "git",
            "vcs_url": "https://example.com/package.git",
            "version": "1.0.0",
        },
        {
            "dependency_kind": "direct",
            "hosted_url": "https://pub.dev",
            "name": "hosted_package",
            "path": "",
            "source": "hosted",
            "vcs_url": "",
            "version": "2.3.4",
        },
        {
            "dependency_kind": "development",
            "hosted_url": "",
            "name": "local_package",
            "path": "../local_package",
            "source": "path",
            "vcs_url": "",
            "version": "0.5.0",
        },
    ]


def test_extracts_android_metadata_and_uses_pubspec_version_fallback(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "pubspec.yaml", "name: example_app\nversion: 3.4.5+67\n")
    _write(project / "pubspec.lock", "packages: {}\n")
    _write(
        project / "android/app/build.gradle",
        """
plugins { id 'com.android.application' }
android {
    namespace 'com.example.namespace'
    compileSdk flutter.compileSdkVersion
    defaultConfig {
        applicationId 'com.example.app'
        minSdk flutter.minSdkVersion
        targetSdk flutter.targetSdkVersion
        versionName flutterVersionName
        versionCode flutterVersionCode.toInteger()
    }
}
""",
    )
    _write(
        project / "android/app/src/main/res/values/strings.xml",
        '<resources><string name="app_name">Example App</string></resources>',
    )
    _write(
        project / "android/app/src/main/AndroidManifest.xml",
        f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}">
    <uses-permission android:name="android.permission.CAMERA" />
    <application android:label="@string/app_name" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
    )

    result = FlutterSourceMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)
    android = payload["android"]

    assert result.success is True
    assert payload["platforms"]["android"] is True
    assert payload["extraction"]["status"] == "partial"
    assert any(warning.startswith("Android metadata:") for warning in payload["extraction"]["warnings"])
    assert android["available"] is True
    assert android["project_path"] == "android"
    assert android["metadata"]["identity"]["app_name"] == "Example App"
    assert android["metadata"]["identity"]["package_name"] == "com.example.app"
    assert android["metadata"]["identity"]["version_name"] == "3.4.5"
    assert android["metadata"]["identity"]["version_code"] == "67"
    assert android["metadata"]["permissions"] == [{"max_sdk_version": "", "name": "android.permission.CAMERA"}]
    assert android["metadata"]["components"]["activities"][0]["name"] == "com.example.app.MainActivity"


def test_android_metadata_failure_is_partial_flutter_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "pubspec.yaml", "name: example_app\n")
    _write(project / "pubspec.lock", "packages: {}\n")
    _write(project / "android/app/src/main/AndroidManifest.xml", "<manifest>")

    result = FlutterSourceMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert payload["extraction"]["status"] == "partial"
    assert payload["android"] == {"available": True, "metadata": None, "project_path": "android"}
    assert payload["extraction"]["warnings"][0].startswith("Android metadata: Unable to parse")


def test_extracts_ios_metadata_and_resolves_flutter_build_values(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "pubspec.yaml", "name: example_app\nversion: 2.3.4+56\n")
    _write(project / "pubspec.lock", "packages: {}\n")
    _write_plist(
        project / "ios/Runner/Info.plist",
        {
            "CFBundleDisplayName": "Example App",
            "CFBundleExecutable": "$(EXECUTABLE_NAME)",
            "CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)",
            "CFBundleName": "$(PRODUCT_NAME)",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "$(FLUTTER_BUILD_NAME)",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["example-app"]}],
            "CFBundleVersion": "$(FLUTTER_BUILD_NUMBER)",
            "LSApplicationQueriesSchemes": ["partner-app"],
            "LSRequiresIPhoneOS": True,
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoads": False,
                "NSExceptionDomains": {"legacy.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True}},
            },
            "NSCameraUsageDescription": "Take profile photos",
            "UIBackgroundModes": ["fetch", "remote-notification"],
        },
    )
    _write(
        project / "ios/Runner.xcodeproj/project.pbxproj",
        """
PRODUCT_BUNDLE_IDENTIFIER = com.example.app;
PRODUCT_NAME = ExampleApp;
IPHONEOS_DEPLOYMENT_TARGET = 13.0;
""",
    )
    _write_plist(
        project / "ios/Runner/Runner.entitlements",
        {
            "aps-environment": "development",
            "com.apple.developer.associated-domains": ["applinks:example.com"],
        },
    )
    _write_plist(
        project / "ios/Runner/PrivacyInfo.xcprivacy",
        {
            "NSPrivacyTracking": False,
            "NSPrivacyAccessedAPITypes": [{"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryFileTimestamp"}],
        },
    )

    result = FlutterSourceMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)
    ios = payload["ios"]
    metadata = ios["metadata"]

    assert result.success is True
    assert payload["platforms"]["ios"] is True
    assert payload["extraction"] == {"status": "complete", "warnings": []}
    assert ios["available"] is True
    assert ios["project_path"] == "ios"
    assert metadata["info_plist_path"] == "Runner/Info.plist"
    assert metadata["xcode_project_path"] == "Runner.xcodeproj/project.pbxproj"
    assert metadata["identity"]["bundle_identifier"] == "com.example.app"
    assert metadata["identity"]["bundle_name"] == "ExampleApp"
    assert metadata["identity"]["executable"] == "ExampleApp"
    assert metadata["identity"]["version"] == "2.3.4"
    assert metadata["identity"]["build"] == "56"
    assert metadata["identity"]["minimum_os"] == "13.0"
    assert metadata["permissions"] == [{"key": "NSCameraUsageDescription", "purpose": "Take profile photos"}]
    assert metadata["background_modes"] == ["fetch", "remote-notification"]
    assert metadata["url_schemes"] == {
        "declared_schemes": ["example-app"],
        "queried_schemes": ["partner-app"],
    }
    assert metadata["app_transport_security"]["exception_domains"][0] == {
        "allows_insecure_http_loads": True,
        "domain": "legacy.example.com",
        "minimum_tls_version": "",
        "requires_forward_secrecy": None,
    }
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
            "path": "Runner/Runner.entitlements",
        }
    ]
    assert metadata["privacy_manifests"][0]["path"] == "Runner/PrivacyInfo.xcprivacy"
    assert metadata["privacy_manifests"][0]["metadata"]["tracking"] is False


def test_invalid_ios_info_plist_returns_partial_flutter_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "pubspec.yaml", "name: example_app\n")
    _write(project / "pubspec.lock", "packages: {}\n")
    _write(project / "ios/Runner/Info.plist", "not a plist")

    result = FlutterSourceMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert payload["extraction"]["status"] == "partial"
    assert payload["ios"] == {"available": True, "metadata": None, "project_path": "ios"}
    assert payload["extraction"]["warnings"][0].startswith("iOS metadata: Unable to parse Runner/Info.plist")


@pytest.mark.parametrize("content", ("packages: [\n", "sdks:\n  dart: '>=3.3.0 <4.0.0'\n"))
def test_invalid_pubspec_lock_returns_partial_metadata(tmp_path: Path, content: str) -> None:
    project = tmp_path / "project"
    _write(project / "pubspec.yaml", "name: example_app\n")
    _write(project / "pubspec.lock", content)

    result = FlutterSourceMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert payload["extraction"]["status"] == "partial"
    assert "resolved dependencies were not assessed" in payload["extraction"]["warnings"][0]
    assert payload["dependencies"]["resolved"] == []


@pytest.mark.parametrize(
    ("version", "expected_name", "expected_code"),
    (("1.2.3+42", "1.2.3", "42"), ("1.2.3", "1.2.3", "")),
)
def test_extracts_flutter_version_parts(
    tmp_path: Path,
    version: str,
    expected_name: str,
    expected_code: str,
) -> None:
    project = tmp_path / "project"
    _write(project / "pubspec.yaml", f"name: example_app\nversion: {version}\n")

    result = FlutterSourceMetadataScanner().scan(_config(project, tmp_path))[0]
    identity = json.loads(result.raw_output)["identity"]

    assert identity["version"] == version
    assert identity["version_name"] == expected_name
    assert identity["version_code"] == expected_code


def test_non_directory_target_returns_failure(tmp_path: Path) -> None:
    target = tmp_path / "pubspec.yaml"
    target.write_text("name: example_app\n", encoding="utf-8")

    result = FlutterSourceMetadataScanner().scan(_config(target, tmp_path))[0]

    assert result.success is False
    assert result.skipped is False
    assert result.relative_target_path == "scan_summary.json"
    assert json.loads(result.raw_output)["success"] is False


def test_missing_pubspec_returns_skipped_result(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    result = FlutterSourceMetadataScanner().scan(_config(project, tmp_path))[0]

    assert result.success is False
    assert result.skipped is True
    assert result.relative_target_path == "scan_summary.json"
    assert json.loads(result.raw_output)["skipped"] is True


@pytest.mark.parametrize("content", ("name: [\n", "- example_app\n"))
def test_invalid_pubspec_returns_failure(tmp_path: Path, content: str) -> None:
    project = tmp_path / "project"
    _write(project / "pubspec.yaml", content)

    result = FlutterSourceMetadataScanner().scan(_config(project, tmp_path))[0]

    assert result.success is False
    assert result.skipped is False
    assert result.relative_target_path == "scan_summary.json"
    assert json.loads(result.raw_output)["success"] is False


def _config(project: Path, tmp_path: Path) -> ScanConfig:
    return ScanConfig(
        project_path=project,
        output_path=tmp_path / "scan-results",
        mode="source",
        platform="ANY",
        stack="FLUTTER",
    )


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_plist(path: Path, content: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(content))

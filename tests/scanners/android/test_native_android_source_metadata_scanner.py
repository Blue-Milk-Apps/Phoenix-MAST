from __future__ import annotations

import json
from pathlib import Path

from adapters.scanners.android import NativeAndroidSourceMetadataScanner
from application.mobile_analysis_workflow_service import MobileScannerFactory
from domain.models import ScanConfig, ScanType

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def test_scanner_metadata() -> None:
    scanner = NativeAndroidSourceMetadataScanner()

    assert scanner.scan_type is ScanType.NATIVE_ANDROID_SOURCE_METADATA
    assert scanner.is_available() is True
    assert "source" in scanner.name.lower()


def test_extracts_groovy_manifest_and_resource_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(
        project / "app" / "build.gradle",
        """
plugins { id 'com.android.application' }
android {
    namespace 'com.example.namespace'
    compileSdk 35
    defaultConfig {
        applicationId 'com.example.app'
        minSdk 24
        targetSdk 35
        versionName '1.2.3'
        versionCode 42
    }
}
""",
    )
    _write(project / "settings.gradle", 'rootProject.name = "Example Project"')
    _write(
        project / "app/src/main/res/values/strings.xml",
        '<resources><string name="app_name">Example</string></resources>',
    )
    _write(
        project / "app/src/main/AndroidManifest.xml",
        _manifest(
            application_attributes='android:label="@string/app_name" android:allowBackup="false" '
            'android:debuggable="true" android:usesCleartextTraffic="false"',
            body="""
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="example" android:host="open" android:pathPrefix="/item" />
            </intent-filter>
        </activity>
        <service android:name="SyncService" />
""",
            permissions='<uses-permission android:name="android.permission.CAMERA" />',
        ),
    )

    result = NativeAndroidSourceMetadataScanner().scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert result.relative_target_path == "project_metadata.json"
    assert payload["extraction"] == {"status": "complete", "warnings": []}
    assert payload["identity"] == {
        "app_name": "Example",
        "package_name": "com.example.app",
        "namespace": "com.example.namespace",
        "main_activity": "com.example.app.MainActivity",
        "compile_sdk": "35",
        "min_sdk": "24",
        "target_sdk": "35",
        "version_name": "1.2.3",
        "version_code": "42",
    }
    assert payload["application"]["debuggable"] is True
    assert payload["application"]["allow_backup"] is False
    assert payload["application"]["uses_cleartext_traffic"] is False
    assert payload["permissions"] == [{"max_sdk_version": "", "name": "android.permission.CAMERA"}]
    assert payload["components"]["activities"][0]["exported"] is True
    assert payload["components"]["services"][0]["name"] == "com.example.app.SyncService"
    assert payload["deep_links"] == [
        {
            "component": "com.example.app.MainActivity",
            "host": "open",
            "mime_type": "",
            "path": "",
            "path_pattern": "",
            "path_prefix": "/item",
            "port": "",
            "scheme": "example",
        }
    ]


def test_extracts_kotlin_dsl_literals_and_manifest_package_fallback(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(
        project / "mobile/build.gradle.kts",
        """
plugins { id("com.android.application") }
android {
    namespace = "com.example.namespace"
    compileSdk = 34
    defaultConfig {
        minSdk = 23
        targetSdk = 34
        versionName = "2.0"
        versionCode = 7
    }
}
""",
    )
    _write(
        project / "mobile/src/main/AndroidManifest.xml",
        _manifest(package="com.example.manifest", application_attributes='android:label="Literal App"'),
    )

    payload = _payload(project, tmp_path)

    assert payload["identity"]["package_name"] == "com.example.manifest"
    assert payload["identity"]["namespace"] == "com.example.namespace"
    assert payload["identity"]["version_name"] == "2.0"
    assert payload["identity"]["version_code"] == "7"
    assert payload["identity"]["app_name"] == "Literal App"


def test_selects_application_module_and_warns_for_multiple_manifests(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "library/build.gradle", "plugins { id 'com.android.library' }")
    _write(project / "library/src/main/AndroidManifest.xml", _manifest(package="com.example.library"))
    _write(project / "app/build.gradle", "plugins { alias(libs.plugins.android.application) }")
    _write(project / "app/src/main/AndroidManifest.xml", _manifest(package="com.example.application"))

    payload = _payload(project, tmp_path)

    assert payload["project"]["module_path"] == "app"
    assert payload["identity"]["package_name"] == "com.example.application"
    assert payload["extraction"]["status"] == "partial"
    assert "Multiple main manifests found" in payload["extraction"]["warnings"][0]


def test_dynamic_gradle_values_are_blank_and_reported(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/build.gradle",
        """
plugins { id 'com.android.application' }
android {
    defaultConfig {
        applicationId System.getenv("APP_ID")
        versionName computeVersionName()
        versionCode buildNumber
    }
}
""",
    )
    _write(project / "app/src/main/AndroidManifest.xml", _manifest())

    payload = _payload(project, tmp_path)

    assert payload["identity"]["package_name"] == ""
    assert payload["identity"]["version_name"] == ""
    assert payload["identity"]["version_code"] == ""
    assert payload["extraction"]["status"] == "partial"
    assert len(payload["extraction"]["warnings"]) == 3


def test_ignores_generated_manifests_and_skips_when_no_source_manifest(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "app/build/intermediates/src/main/AndroidManifest.xml", _manifest())

    result = NativeAndroidSourceMetadataScanner().scan(_config(project, tmp_path))[0]

    assert result.success is False
    assert result.skipped is True
    assert result.relative_target_path == "scan_summary.json"


def test_malformed_selected_manifest_returns_failed_summary(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "app/src/main/AndroidManifest.xml", "<manifest>")

    result = NativeAndroidSourceMetadataScanner().scan(_config(project, tmp_path))[0]

    assert result.success is False
    assert result.skipped is False
    assert result.relative_target_path == "scan_summary.json"
    assert "Unable to parse" in result.error_message


def test_factory_includes_scanner_only_for_native_android_source(tmp_path: Path) -> None:
    android_config = _config(tmp_path / "android", tmp_path)
    android_config.platform = "ANDROID"
    android_config.stack = "NATIVE_ANDROID"
    ios_config = _config(tmp_path / "ios", tmp_path)
    ios_config.platform = "IOS"
    ios_config.stack = "NATIVE_IOS"

    android_scanners = MobileScannerFactory().build_scanner_list(android_config)
    ios_scanners = MobileScannerFactory().build_scanner_list(ios_config)

    assert any(isinstance(scanner, NativeAndroidSourceMetadataScanner) for scanner in android_scanners)
    assert not any(isinstance(scanner, NativeAndroidSourceMetadataScanner) for scanner in ios_scanners)


def _payload(project: Path, tmp_path: Path) -> dict:
    result = NativeAndroidSourceMetadataScanner().scan(_config(project, tmp_path))[0]
    assert result.success is True
    return json.loads(result.raw_output)


def _config(project: Path, tmp_path: Path) -> ScanConfig:
    return ScanConfig(
        project_path=project,
        output_path=tmp_path / "scan-results",
        mode="source",
    )


def _manifest(
    *,
    package: str = "",
    application_attributes: str = "",
    body: str = "",
    permissions: str = "",
) -> str:
    package_attribute = f' package="{package}"' if package else ""
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}"{package_attribute}>
    {permissions}
    <application {application_attributes}>
        {body}
    </application>
</manifest>
"""


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

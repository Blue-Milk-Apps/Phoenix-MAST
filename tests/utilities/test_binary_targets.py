import zipfile
from pathlib import Path

from utilities.apk_utils import ExtractedAPK, iter_apk_analysis_targets
from utilities.ipa_utils import ExtractedIPA, get_scanable_binary_paths


def test_iter_ipa_analysis_targets_returns_runner_and_framework_binary(
    tmp_path: Path,
) -> None:
    temp_dir = tmp_path / "ipa"
    app_bundle = temp_dir / "Payload" / "Runner.app"
    framework_dir = app_bundle / "Frameworks" / "Alamofire.framework"
    framework_dir.mkdir(parents=True)

    runner_binary = app_bundle / "Runner"
    framework_binary = framework_dir / "Alamofire"
    plist_file = app_bundle / "Info.plist"

    app_bundle.mkdir(parents=True, exist_ok=True)
    runner_binary.write_text("runner")
    framework_binary.write_text("framework")
    plist_file.write_text("plist")

    extracted = ExtractedIPA(
        temp_dir=temp_dir,
        app_bundle=app_bundle,
        binary_path=runner_binary,
    )

    targets = get_scanable_binary_paths(extracted)

    assert targets == [runner_binary, framework_binary]


def test_iter_apk_analysis_targets_returns_native_libs(tmp_path: Path) -> None:
    temp_dir = tmp_path / "apk"
    lib_one = temp_dir / "lib" / "arm64-v8a" / "libfoo.so"
    lib_two = temp_dir / "lib" / "x86_64" / "libbar.so"
    lib_one.parent.mkdir(parents=True)
    lib_two.parent.mkdir(parents=True)
    lib_one.write_text("foo")
    lib_two.write_text("bar")

    extracted = ExtractedAPK(
        temp_dir=temp_dir,
        native_libs=[lib_one, lib_two],
    )

    targets = iter_apk_analysis_targets(extracted)

    assert targets == [lib_one, lib_two]


def test_extract_apk_targets_include_dex_manifest_assets_and_libs(
    tmp_path: Path,
) -> None:
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"manifest")
        zf.writestr("classes.dex", b"dex")
        zf.writestr("classes2.dex", b"dex2")
        zf.writestr("resources.arsc", b"resources")
        zf.writestr("assets/config.json", b'{"key": "value"}')
        zf.writestr("lib/arm64-v8a/libfoo.so", b"libfoo")

    from utilities.apk_utils import extract_apk

    extracted = extract_apk(apk_path)

    target_names = [
        path.relative_to(extracted.temp_dir).as_posix()
        for path in iter_apk_analysis_targets(extracted)
    ]

    assert target_names == [
        "AndroidManifest.xml",
        "assets/config.json",
        "classes.dex",
        "classes2.dex",
        "lib/arm64-v8a/libfoo.so",
        "resources.arsc",
    ]

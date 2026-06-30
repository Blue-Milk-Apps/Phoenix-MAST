"""Command-line interface for AppcritIQ."""

from __future__ import annotations

import argparse
import os
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Sequence

from adapters.binary_scanners import (
    Aapt2Scanner,
    AndroguardScanner,
    ApkidScanner,
    ApksignerScanner,
    ApktoolScanner,
    BinaryOpenGrepScanner,
    IpswScanner,
    LIEFScanner,
    MobSFScanner,
    PlistBinaryScanner,
)
from adapters.output import FileScanOutput
from adapters.source_code_scanners import (
    DependencyCheckScanner,
    GitleaksScanner,
    OpenGrepScanner,
    PlistSourceScanner,
    StringsScanner,
    SyftScanner,
    TrufflehogScanner,
)
from application.scanner_service import ScannerService
from domain.models import ScanConfig
from ports.scanner_port import ScannerPort

DEFAULT_SYFT_OUTPUT_FORMAT = "cyclonedx-json"
DEFAULT_OPENGREP_RULES_DIRS = {
    "ios_binary": "ios",
    "android_binary": "android",
    "flutter_source": "flutter",
    "react_native_source": "react_native",
    "native_android_source": "android",
    "native_ios_source": "ios",
}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the AppcritIQ command-line interface."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appcritiq",
        description="AppcritIQ - Mobile Application Security Platform",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_package_version()}",
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run a AppcritIQ scan")
    scan_paths = scan_parser.add_mutually_exclusive_group(required=True)
    scan_paths.add_argument(
        "--ios-binary-path",
        type=Path,
        metavar="PATH",
        help="Path to compiled iOS .ipa or .app",
    )
    scan_paths.add_argument(
        "--android-binary-path",
        type=Path,
        metavar="PATH",
        help="Path to compiled Android .apk or .aab",
    )
    scan_paths.add_argument(
        "--flutter-source-path",
        type=Path,
        metavar="PATH",
        help="Path to Flutter project root directory",
    )
    scan_paths.add_argument(
        "--react-native-source-path",
        type=Path,
        metavar="PATH",
        help="Path to React Native project root directory",
    )
    scan_paths.add_argument(
        "--native-android-source-path",
        type=Path,
        metavar="PATH",
        help="Path to Native Android project root directory",
    )
    scan_paths.add_argument(
        "--native-ios-source-path",
        type=Path,
        metavar="PATH",
        help="Path to Native iOS project root directory",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("./scan-results"),
        help="Output directory for scan results",
    )
    scan_parser.add_argument(
        "--syft-output-format",
        default=DEFAULT_SYFT_OUTPUT_FORMAT,
        help=(f"Syft SBOM output format to capture from stdout (default: {DEFAULT_SYFT_OUTPUT_FORMAT})"),
    )
    scan_parser.add_argument("--ios-binary-opengrep-rules-path", type=Path, metavar="PATH")
    scan_parser.add_argument("--android-binary-opengrep-rules-path", type=Path, metavar="PATH")
    scan_parser.add_argument("--flutter-source-opengrep-rules-path", type=Path, metavar="PATH")
    scan_parser.add_argument("--react-native-source-opengrep-rules-path", type=Path, metavar="PATH")
    scan_parser.add_argument("--native-android-source-opengrep-rules-path", type=Path, metavar="PATH")
    scan_parser.add_argument("--native-ios-source-opengrep-rules-path", type=Path, metavar="PATH")
    scan_parser.set_defaults(func=_scan_command)

    return parser


def _scan_command(args: argparse.Namespace) -> int:
    scan_config: ScanConfig = _create_scan_config(args)

    print("AppcritIQ scan")
    print(f"Project: {scan_config.project_path}")
    print(f"Output: {scan_config.output_path}")
    print(f"Scan type: {scan_config.scan_label}")
    print(f"Proceeding with {scan_config.scan_label} scan")

    scan_config.output_path.mkdir(parents=True, exist_ok=True)
    report_context = _report_context_from_scan_config(scan_config)
    scan_output_method = FileScanOutput(scan_config.output_path)
    scan_output_method.write_scan_metadata(scan_config, report_context)
    scanner_service = ScannerService(scan_config.scanners)

    wall_start = time.perf_counter()
    scan_results = scanner_service.scan_project(scan_config)
    for result in scan_results:
        scan_output_method.write_result(result)
    print(f"Results: {len(scan_results)}")
    print(f"Duration: {time.perf_counter() - wall_start:.2f} seconds")
    return 0


def _package_version() -> str:
    try:
        return version("appcritiq-core")
    except PackageNotFoundError:
        return "0.1.0"


def _report_context_from_scan_config(scan_config: ScanConfig) -> dict[str, str]:
    scan_label = scan_config.scan_label.lower()
    platform = "ANY"
    if "ios" in scan_label:
        platform = "IOS"
    elif "android" in scan_label:
        platform = "ANDROID"

    stack = "ANY"
    if "flutter" in scan_label:
        stack = "FLUTTER"
    elif "react native" in scan_label:
        stack = "REACT_NATIVE"
    elif "native ios" in scan_label:
        stack = "NATIVE_IOS"
    elif "native android" in scan_label:
        stack = "NATIVE_ANDROID"

    return {
        "platform": platform,
        "target_type": scan_config.mode.upper(),
        "stack": stack,
    }


def _create_scan_config(args: argparse.Namespace) -> ScanConfig:
    match args:
        case argparse.Namespace(android_binary_path=Path() as project_path):
            scan_mode = "binary"
            scan_label = "Android binary"
            scan_slug = "android_binary"
            scanners: list[ScannerPort] = [
                AndroguardScanner(),
                Aapt2Scanner(),
                ApktoolScanner(),
                ApksignerScanner(),
                ApkidScanner(),
                StringsScanner(),
            ]
            rules_path = _resolve_opengrep_rules_path(
                args.android_binary_opengrep_rules_path,
                "android_binary",
            )
            if rules_path:
                scanners.append(BinaryOpenGrepScanner(rules_path=rules_path))

        case argparse.Namespace(ios_binary_path=Path() as project_path):
            scan_mode = "binary"
            scan_label = "iOS binary"
            scan_slug = "ios_binary"
            scanners = [
                IpswScanner(),
                LIEFScanner(),
                StringsScanner(),
                PlistBinaryScanner(),
            ]
            rules_path = _resolve_opengrep_rules_path(
                args.ios_binary_opengrep_rules_path,
                "ios_binary",
            )
            if rules_path:
                scanners.append(BinaryOpenGrepScanner(rules_path=rules_path))

        case argparse.Namespace(flutter_source_path=Path() as project_path):
            scan_mode = "source"
            scan_label = "Flutter source"
            scan_slug = "flutter_source"
            scanners = [
                TrufflehogScanner(),
                GitleaksScanner(),
                PlistSourceScanner(),
                DependencyCheckScanner(),
                SyftScanner(output_format=args.syft_output_format),
            ]
            rules_path = _resolve_opengrep_rules_path(
                args.flutter_source_opengrep_rules_path,
                "flutter_source",
            )
            if rules_path:
                scanners.insert(
                    0,
                    OpenGrepScanner(rules_path=rules_path),
                )

        case argparse.Namespace(react_native_source_path=Path() as project_path):
            scan_mode = "source"
            scan_label = "React Native source"
            scan_slug = "react_native_source"
            scanners = [
                TrufflehogScanner(),
                GitleaksScanner(),
                PlistSourceScanner(),
                DependencyCheckScanner(),
                SyftScanner(output_format=args.syft_output_format),
            ]
            rules_path = _resolve_opengrep_rules_path(
                args.react_native_source_opengrep_rules_path,
                "react_native_source",
            )
            if rules_path:
                scanners.insert(
                    0,
                    OpenGrepScanner(rules_path=rules_path),
                )

        case argparse.Namespace(native_android_source_path=Path() as project_path):
            scan_mode = "source"
            scan_label = "Native Android source"
            scan_slug = "native_android_source"
            scanners = [
                TrufflehogScanner(),
                GitleaksScanner(),
                DependencyCheckScanner(),
                SyftScanner(output_format=args.syft_output_format),
            ]
            rules_path = _resolve_opengrep_rules_path(
                args.native_android_source_opengrep_rules_path,
                "native_android_source",
            )
            if rules_path:
                scanners.insert(
                    0,
                    OpenGrepScanner(rules_path=rules_path),
                )

        case argparse.Namespace(native_ios_source_path=Path() as project_path):
            scan_mode = "source"
            scan_label = "Native iOS source"
            scan_slug = "native_ios_source"
            scanners = [
                TrufflehogScanner(),
                GitleaksScanner(),
                PlistSourceScanner(),
                SyftScanner(output_format=args.syft_output_format),
            ]
            rules_path = _resolve_opengrep_rules_path(
                args.native_ios_source_opengrep_rules_path,
                "native_ios_source",
            )
            if rules_path:
                scanners.insert(
                    0,
                    OpenGrepScanner(rules_path=rules_path),
                )

        case _:
            raise ValueError("No valid scan type provided")
    if _mobsf_url_configured():
        scanners.append(MobSFScanner())
    project_path = project_path.resolve()
    run_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_path = args.output.resolve() / f"SAST_{scan_slug}_{run_timestamp}"
    scan_config = ScanConfig(
        project_path=project_path,
        output_path=output_path,
        mode=scan_mode,
        scan_label=scan_label,
        scanners=scanners,
        enabled_scans=[scanner.scan_type for scanner in scanners],
    )
    return scan_config


def _mobsf_url_configured() -> bool:
    return bool(os.environ.get("MOBSF_URL", "").strip())


def _resolve_opengrep_rules_path(
    override_path: Path | None,
    scan_slug: str,
) -> Path | None:
    if override_path is not None:
        return override_path.resolve()

    default_dir = DEFAULT_OPENGREP_RULES_DIRS.get(scan_slug)
    if not default_dir:
        return None

    candidates = [
        (Path(__file__).parent.parent / "rules" / default_dir).resolve(),
        (Path("/app/rules") / default_dir).resolve(),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


if __name__ == "__main__":
    raise SystemExit(main())

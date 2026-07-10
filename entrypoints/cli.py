"""Command-line interface for AppcritIQ."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Sequence

from application.mobile_analysis_workflow_service import MobileAnalysisWorkflowService
from domain.models import ScanConfig

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

    MobileAnalysisWorkflowService().run(scan_config)
    return 0


def _package_version() -> str:
    try:
        return version("appcritiq-core")
    except PackageNotFoundError:
        return "0.1.0"


def _create_scan_config(args: argparse.Namespace) -> ScanConfig:
    match args:
        case argparse.Namespace(android_binary_path=Path() as project_path):
            scan_mode = "binary"
            scan_label = "Android binary"
            scan_slug = "android_binary"
            platform = "ANDROID"
            stack = "ANY"
            rules_path = _resolve_opengrep_rules_path(
                args.android_binary_opengrep_rules_path,
                "android_binary",
            )

        case argparse.Namespace(ios_binary_path=Path() as project_path):
            scan_mode = "binary"
            scan_label = "iOS binary"
            scan_slug = "ios_binary"
            platform = "IOS"
            stack = "ANY"
            rules_path = _resolve_opengrep_rules_path(
                args.ios_binary_opengrep_rules_path,
                "ios_binary",
            )

        case argparse.Namespace(flutter_source_path=Path() as project_path):
            scan_mode = "source"
            scan_label = "Flutter source"
            scan_slug = "flutter_source"
            platform = "ANY"
            stack = "FLUTTER"
            rules_path = _resolve_opengrep_rules_path(
                args.flutter_source_opengrep_rules_path,
                "flutter_source",
            )

        case argparse.Namespace(react_native_source_path=Path() as project_path):
            scan_mode = "source"
            scan_label = "React Native source"
            scan_slug = "react_native_source"
            platform = "ANY"
            stack = "REACT_NATIVE"
            rules_path = _resolve_opengrep_rules_path(
                args.react_native_source_opengrep_rules_path,
                "react_native_source",
            )

        case argparse.Namespace(native_android_source_path=Path() as project_path):
            scan_mode = "source"
            scan_label = "Native Android source"
            scan_slug = "native_android_source"
            platform = "ANDROID"
            stack = "NATIVE_ANDROID"
            rules_path = _resolve_opengrep_rules_path(
                args.native_android_source_opengrep_rules_path,
                "native_android_source",
            )

        case argparse.Namespace(native_ios_source_path=Path() as project_path):
            scan_mode = "source"
            scan_label = "Native iOS source"
            scan_slug = "native_ios_source"
            platform = "IOS"
            stack = "NATIVE_IOS"
            rules_path = _resolve_opengrep_rules_path(
                args.native_ios_source_opengrep_rules_path,
                "native_ios_source",
            )

        case _:
            raise ValueError("No valid scan type provided")
    project_path = project_path.resolve()
    run_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_path = args.output.resolve() / f"SAST_{scan_slug}_{run_timestamp}"
    scan_config = ScanConfig(
        project_path=project_path,
        output_path=output_path,
        mode=scan_mode,
        scan_label=scan_label,
        platform=platform,
        stack=stack,
        opengrep_rules_path=rules_path,
        syft_output_format=args.syft_output_format,
    )
    return scan_config


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

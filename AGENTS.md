# AGENTS.md

This file gives repo-specific guidance to AI coding agents working on AppcritIQ Core. It is not runtime code and is not used by the Python package.

## Project Summary

AppcritIQ Core is the Python foundation for AppcritIQ, an all-in-one Mobile Application Security Testing (MAST) tool for iOS and Android applications.

The project coordinates security scanning workflows for:

- Static analysis for mobile application security issues
- Secret detection for accidental credential exposure
- Dependency vulnerability checks
- Software Bill of Materials (SBOM) generation
- IPA/APK binary analysis

AppcritIQ Core is intended to make mobile application reviews repeatable by collecting scanner orchestration, configuration, adapter behavior in one Python project.

## Architecture

Use the existing port-and-adapter structure.

- `domain/` contains core dataclasses and enums such as `ScanType`, `ScanResult`, and `ScanConfig`.
- `ports/` contains interfaces for external behavior.
- `ports/scanner_port.py` defines `ScannerPort`.
- `ports/storage_port.py` defines `ArtifactStorePort`.
- `application/` contains orchestration such as `ScannerService`.
- `adapters/source_code_scanners/` contains source/source code scanner adapters.
- `adapters/binary_scanners/` contains binary scanner adapters.
- `adapters/storage/` contains storage adapters.
- `entrypoints/cli.py` contains the AppcritIQ CLI.
- `utilities/` contains helper code for APK/IPA extraction and binary target discovery.
- `setup/` contains local setup notes for external scanner tools.
- `tests/` contains unit and integration tests.

Scanner implementations should satisfy `ScannerPort`.

Storage implementations should satisfy `ArtifactStorePort`.

Keep domain models free of external tool or filesystem-specific behavior unless explicitly requested.

## Scope Control

When the user asks to update a specific file, only edit that file unless the change cannot work without touching another file.

Before adding new files, tests, package config changes, lockfile changes, exports, or documentation, ask the user first.

Before broadening the task beyond the requested change, ask a short question and wait for approval.

Prefer the smallest working change that satisfies the request.

Do not make opportunistic refactors while completing a focused request.

Do not modify `uv.lock`, package metadata, generated files, or unrelated modules unless the user asks for that change or approves it.

## Communication

If the task scope is ambiguous, ask a concise clarifying question before proceeding.

If there is a meaningful tradeoff, describe it briefly and ask before choosing the broader or riskier option.

If a command needs network access, escalated permissions, or access outside the workspace, ask before proceeding.

When work is in progress, explain what context is being gathered and why.

When finished, summarize the files changed and the verification performed.

## Commands

Common project commands:

See the [scan target flags](README.md#scan-target-flags) list for valid `<scan-target-flag>` values.

```bash
uv venv
uv sync
make test
python -m pytest
uv run pytest
uv run appcritiq scan <scan-target-flag> path/to/target
```

The CLI entrypoint accepts exactly one scan target flag:

```bash
appcritiq scan --ios-binary-path path/to/app.ipa
appcritiq scan --android-binary-path path/to/app.apk
appcritiq scan --flutter-source-path path/to/project
appcritiq scan --react-native-source-path path/to/project
appcritiq scan --native-android-source-path path/to/project
appcritiq scan --native-ios-source-path path/to/project
```

For local MobSF binary scans:

```bash
make services-up
MOBSF_URL=http://localhost:8000 uv run appcritiq scan --ios-binary-path path/to/app.ipa
make services-down
```

Use focused tests first when they already exist and are relevant. Run broader tests only when the change affects shared behavior or the user asks for a full test pass.

## Testing Rules

Do not add tests unless the user asks for tests or approves adding them.

It is OK to run existing focused tests when relevant.

External scanner binaries should not be required for unit tests. Mock subprocesses, filesystem inputs, and availability checks where possible.

Keep adapter tests focused and use temporary directories.

Integration tests that require external tools, Docker, MobSF, network access, or local scanner databases should be clearly marked or isolated.

## External Scanner Notes

AppcritIQ may use the following tools from the local `PATH`:

- `trufflehog`
- `gitleaks`
- `dependency-check`
- `syft`
- `strings`

MobSF binary scanning uses a sidecar service configured through `MOBSF_URL` and `MOBSF_API_KEY`.

OWASP Dependency-Check may require a local NVD data directory, commonly configured with `DEPENDENCY_CHECK_DATA_DIR` or `nvd-owasp-data/`.

Do not assume these tools are installed when writing unit tests.

## Coding Guidelines

Follow the existing style in nearby modules.

Use `pathlib.Path` for filesystem paths.

Keep adapters responsible for external tool, subprocess, HTTP, or filesystem behavior.

Return `ScanResult` objects from scanners with clear `success`, `skipped`, `error_message`, `raw_output`, and `description` values.

Create output directories before writing scanner reports.

Avoid adding abstractions unless they remove real duplication or match an existing project pattern.

Keep comments brief and only where they clarify non-obvious behavior.

## Git And Generated Files

The worktree may contain user changes. Do not revert changes you did not make.

Do not delete or regenerate files unless the user asks.

Ignore unrelated dirty files.

Do not commit unless the user asks for a commit.

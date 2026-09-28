# Phoenix MAST agent guidance

Phoenix MAST is the public Python engine that coordinates mobile security tools
for iOS, Android, Flutter, and React Native. Private OpenGrep rules live in
Phoenix-Rules and are supplied at runtime.

## Engine boundaries and terminology

- A **rule** means an OpenGrep rule. Call Python transformations and report logic
  post-processing, normalization, or aggregation.
- A **scan** is one Phoenix run. An individual tool invocation is a **tool execution**.
- Keep the engine simple: use included tools for capabilities they already provide.
  Scrutinize custom Python that duplicates their behavior.
- OpenGrep owns security findings and functionality detection. Syft owns resolved
  dependency inventories. Python coordinates tools, normalizes evidence, and reports results.
- MobSF is not used. See [the tool inventory](docs/ToolInventory.md) before adding
  tools or changing responsibility for an output.
- Keep the same `<platform>/source` and `<platform>/binary` rule-directory structure
  across platforms. Missing binary rules are reported as not evaluated; source rules are required.

## Architecture

Follow the existing ports and adapters:

| Location | Responsibility |
| --- | --- |
| `domain/` | Models, assessment semantics, and report aggregates |
| `ports/` | Interfaces such as `ScannerPort` and `ArtifactStorePort` |
| `application/` | Workflow and tool orchestration |
| `adapters/scanners/` | Tool execution and platform metadata extraction |
| `adapters/post_scan/` | Artifact loading and evidence normalization |
| `adapters/output/` | Console, JSON, and PDF presentation |
| `adapters/storage/` | Artifact persistence |
| `entrypoints/cli.py` | CLI arguments and entrypoint |
| `utilities/` | Shared extraction, path, and exclusion helpers |

Keep external tool, subprocess, HTTP, and filesystem operations in adapters or
existing utilities. Keep domain models independent of those operations.

## Output contracts

- Stdout and tool artifacts are the default output. Aggregate JSON and PDF are
  independently opt-in through `--json` and `--pdf`.
- JSON and PDF use the same report aggregate. Severity counts include all matched
  security checks, including reviews, controls, and observations. Functionality
  stays separate; category risk assessments use weakness findings.
- Severity counts use Critical, High, Medium, Low, and Info. Secure is not a severity.
- `--severity` filters stdout findings and counts at that level or higher; reports
  and raw artifacts remain complete.
- Use Rich for static, CI-friendly formatting. Avoid animations and cursor redraws;
  respect `NO_COLOR` and keep credential values out of stdout.
- `--exclude` accepts comma-separated paths and glob patterns. Use the shared
  exclusion handling rather than implementing different behavior per tool.
- Preserve the distinction between failed, skipped, incomplete, and successful
  tool executions. Missing evidence must not become a clean assessment.

## Working conventions

- Make the smallest complete change within the requested scope. Avoid unrelated refactors.
- For a request naming one file, edit only that file unless related changes are necessary.
- Get approval before adding files, tests, package configuration, lockfile changes,
  exports, or documentation unless the request or earlier authorization already covers them.
- Ask before expanding scope or choosing a materially broader or riskier approach.
  Resolve routine implementation details using the existing code and conversation.
- Ask before network access, elevated permissions, or work outside the workspace
  unless already authorized; follow the environment's permission controls.
- Preserve user changes. Do not delete or regenerate unrelated files, and do not
  commit unless requested.
- Explain relevant findings during work and summarize changes, validation, and
  remaining limitations when finished.

## Coding and verification

- Follow nearby code style and use `pathlib.Path` for filesystem paths.
- Keep related fields and behavior together. Prefer dataclasses and enums where
  appropriate; avoid unnecessary wrappers, parallel maps, and one-off abstractions.
- Implement the existing ports and return `ScanResult` with accurate status,
  errors, raw output, and descriptions. Create output directories before writing.
- Keep comments brief and focused on non-obvious behavior.
- Run relevant existing tests first. Broaden verification when shared behavior changes.
  Add tests only when requested or approved.
- Unit tests should mock tool execution and availability, use temporary directories,
  and avoid requiring installed external binaries or private rules.
- Isolate integration tests that require tools, Docker, network access, or databases.
  PDF tests require native rendering dependencies described in [setup](setup/README.md).
- For console changes, check GitHub Actions color settings and `NO_COLOR`. Compare
  plain text separately from ANSI styling so environment differences do not break assertions.

## Commands and references

Use Python 3.12+ and run commands from the repository root:

```bash
uv sync
uv run pytest tests/path/to/test_file.py
uv run pytest
uv run ruff check .
uv run phoenix scan <scan-target-flag> path/to/target
```

Pass exactly one [scan target flag](README.md#scan-target-flags).
See [README.md](README.md) for CLI and container workflows, and
[the report guide](adapters/output/phoenix_report/README.md) for rendering contracts.

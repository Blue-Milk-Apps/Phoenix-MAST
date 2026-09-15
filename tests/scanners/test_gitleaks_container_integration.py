from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False

    checks = [
        ["docker", "info"],
        ["docker", "compose", "version"],
    ]
    for cmd in checks:
        try:
            subprocess.run(
                cmd,
                cwd=REPO_ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=20,
            )
        except Exception:
            return False

    return True


def test_gitleaks_compose_container_detects_fake_secret(tmp_path: Path) -> None:
    if not _docker_ready():
        pytest.skip("Docker is not available for the Gitleaks integration test.")

    fake_repo = tmp_path / "fake-repo"
    fake_repo.mkdir()
    (fake_repo / ".gitleaks.toml").write_text(
        "\n".join(
            [
                'title = "AppcritIQ Gitleaks Integration Test"',
                "",
                "[[rules]]",
                'id = "test-secret"',
                'description = "Detect the test secret"',
                "regex = '''TEST_SECRET=[A-Z0-9]{8,}'''",
                'tags = ["test"]',
            ]
        )
        + "\n"
    )
    (fake_repo / "secrets.env").write_text("TEST_SECRET=SECRET12345\n")

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    env = os.environ.copy()
    env.update(
        {
            "PROJECT_MOUNT_PATH": str(fake_repo),
            "OUTPUT_PATH": str(results_dir),
            "GITLEAKS_SCAN_PATH": "/workspace",
            "SCAN_FLAG": "--native-android-source-path",
            "PHOENIX_SCAN_FLAG": "--native-android-source-path",
            "PHOENIX_SCAN_PATH": "/workspace",
        }
    )

    process = subprocess.run(
        [
            "docker",
            "compose",
            "run",
            "--rm",
            "--no-deps",
            "gitleaks",
            "dir",
            "/workspace",
            "--config",
            "/workspace/.gitleaks.toml",
            "--report-format",
            "json",
            "--report-path",
            "/app/results/gitleaks-report.json",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )

    assert process.returncode in (0, 1), process.stderr or process.stdout

    report_file = results_dir / "gitleaks-report.json"
    assert report_file.exists(), process.stdout + process.stderr

    report_data = json.loads(report_file.read_text())
    findings = report_data if isinstance(report_data, list) else report_data.get("findings", [])

    assert findings, report_data

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path


def test_pure_python_wheel_contains_typing_markers() -> None:
    root = Path(__file__).resolve().parents[1]
    dist_dir = root / "dist-test"
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist_dir)],
        cwd=root,
        check=True,
    )
    wheels = sorted(dist_dir.glob("pii_mcp-*.whl"))
    assert wheels, "expected a wheel build artifact"

    with zipfile.ZipFile(wheels[-1]) as wheel:
        names = set(wheel.namelist())

    assert "pii_mcp/py.typed" in names
    assert "pii_mcp/_native.pyi" in names

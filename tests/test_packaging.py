from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path


def test_pure_python_wheel_contains_typing_markers(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(tmp_path), str(root)],
        check=True,
    )
    wheels = sorted(tmp_path.glob("pii_mcp-*.whl"))
    assert wheels, "expected a wheel build artifact"

    with zipfile.ZipFile(wheels[-1]) as wheel:
        names = set(wheel.namelist())

    assert "pii_mcp/py.typed" in names
    assert "pii_mcp/_native.pyi" in names

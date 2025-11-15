import os
import sys
import subprocess
import pytest


def _run_demo_path():
    return os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "scripts", "run_demo.py"))


def test_run_demo_exits_cleanly():
    demo = _run_demo_path()
    if not os.path.exists(demo):
        pytest.skip("demo script not found: scripts/run_demo.py")

    # Run demo using same Python interpreter; it should complete quickly
    proc = subprocess.run([sys.executable, demo], capture_output=True, text=True, timeout=10)
    out = proc.stdout + proc.stderr
    # Basic smoke checks
    assert proc.returncode == 0, f"demo exited non-zero: {proc.returncode}\n{out}"
    assert "Server listening" in out or "Server listening on" in out or "Accepted connection" in out

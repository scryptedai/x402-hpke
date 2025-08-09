import os
import subprocess
import sys


REPO = os.path.dirname(os.path.dirname(__file__))
NODE_DIR = os.path.join(REPO, "packages", "node")
PY_DIR = os.path.join(REPO, "packages", "python")


def _run(cmd: list[str], cwd: str | None = None) -> int:
    print("$", " ".join(cmd))
    return subprocess.call(cmd, cwd=cwd or REPO)


def build_all() -> None:
    code = 0
    # Ensure Python package env is ready first (Node tests call into Poetry)
    code |= _run(["poetry", "env", "use", sys.executable], cwd=PY_DIR)
    code |= _run(["poetry", "lock", "--no-update"], cwd=PY_DIR)
    code |= _run(["poetry", "install"], cwd=PY_DIR)
    # Build Node package
    code |= _run(["npm", "ci"], cwd=NODE_DIR)
    code |= _run(["npm", "run", "build"], cwd=NODE_DIR)
    sys.exit(code)


def test_node() -> None:
    code = 0
    code |= _run(["npm", "ci"], cwd=NODE_DIR)
    code |= _run(["npm", "test"], cwd=NODE_DIR)
    sys.exit(code)


def test_python() -> None:
    code = 0
    code |= _run(["poetry", "env", "use", sys.executable], cwd=PY_DIR)
    code |= _run(["poetry", "install"], cwd=PY_DIR)
    code |= _run(["poetry", "run", "pytest", "-q"], cwd=PY_DIR)
    sys.exit(code)


def test_all() -> None:
    code = 0
    # Prepare Python package first so Node interop tests can call Poetry
    code |= _run(["poetry", "env", "use", sys.executable], cwd=PY_DIR)
    code |= _run(["poetry", "lock", "--no-update"], cwd=PY_DIR)
    code |= _run(["poetry", "install"], cwd=PY_DIR)
    # Run Node tests (will invoke Poetry scripts)
    code |= _run(["npm", "ci"], cwd=NODE_DIR)
    code |= _run(["npm", "test"], cwd=NODE_DIR)
    code |= _run(["poetry", "run", "pytest", "-q"], cwd=PY_DIR)
    sys.exit(code)


def ci() -> None:
    """CI-friendly composite: build, then test Node and Python."""
    code = 0
    # Prepare Python env/install first
    code |= _run(["poetry", "env", "use", sys.executable], cwd=PY_DIR)
    code |= _run(["poetry", "lock", "--no-update"], cwd=PY_DIR)
    code |= _run(["poetry", "install"], cwd=PY_DIR)
    # Build and test Node
    code |= _run(["npm", "ci"], cwd=NODE_DIR)
    code |= _run(["npm", "run", "build"], cwd=NODE_DIR)
    code |= _run(["npm", "test"], cwd=NODE_DIR)
    code |= _run(["poetry", "run", "pytest", "-q"], cwd=PY_DIR)
    sys.exit(code)

 
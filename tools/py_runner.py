import subprocess, os

PY_DIR = os.path.join(os.path.dirname(__file__), "..", "packages", "python")
NODE_DIR = os.path.join(os.path.dirname(__file__), "..", "packages", "node")


def _run(cmd: list[str], cwd: str):
    print(">>", " ".join(cmd), flush=True)
    subprocess.check_call(cmd, cwd=cwd)


def test():
    _run(["poetry", "install"], cwd=PY_DIR)
    _run(["poetry", "run", "pytest", "-q"], cwd=PY_DIR)


def build():
    _run(["poetry", "build"], cwd=PY_DIR)


def publish():
    _run(
        [
            "poetry",
            "publish",
            "--username",
            os.getenv("PYPI_USER", "__token__"),
            "--password",
            os.getenv("PYPI_TOKEN", ""),
        ],
        cwd=PY_DIR,
    )


def interop():
    # These helpers can be implemented later; wire basic test commands to ensure packages import
    _run(["node", "-e", "console.log('node ok')"], cwd=NODE_DIR)
    _run(["poetry", "run", "python", "-c", "import x402_hpke; print('python ok')"], cwd=PY_DIR)
import os
import subprocess
import sys


REPO = os.path.dirname(os.path.dirname(__file__))
NODE_DIR = os.path.join(REPO, "packages", "node")
PY_DIR = os.path.join(REPO, "packages", "python")
EX_NODE_CLIENT = os.path.join(REPO, "examples", "client-node")
EX_NODE_SERVER = os.path.join(REPO, "examples", "express-server")
DEMO_PORT = os.environ.get("DEMO_PORT", "43102")


def _run(cmd: list[str], cwd: str | None = None) -> int:
    print("$", " ".join(cmd))
    return subprocess.call(cmd, cwd=cwd or REPO)
def _run_output(cmd: list[str], cwd: str | None = None) -> tuple[int, str]:
    print("$", " ".join(cmd))
    try:
        out = subprocess.check_output(cmd, cwd=cwd or REPO, text=True)
        return 0, out
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output or ""



def build_all() -> None:
    code = 0
    # Ensure Python package env is ready first (Node tests call into Poetry)
    code |= _run(["poetry", "env", "use", sys.executable], cwd=PY_DIR)
    code |= _run(["poetry", "lock", "--no-update"], cwd=PY_DIR)
    code |= _run(["poetry", "install"], cwd=PY_DIR)
    # Build Node package
    # Use npm install in CI, npm ci locally for determinism
    if os.getenv("GITHUB_ACTIONS") == "true":
      code |= _run(["npm", "install"], cwd=NODE_DIR)
    else:
      code |= _run(["npm", "ci"], cwd=NODE_DIR)
    code |= _run(["npm", "run", "build"], cwd=NODE_DIR)
    sys.exit(code)


def test_node() -> None:
    code = 0
    if os.getenv("GITHUB_ACTIONS") == "true":
      code |= _run(["npm", "install"], cwd=NODE_DIR)
    else:
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
    if os.getenv("GITHUB_ACTIONS") == "true":
      code |= _run(["npm", "install"], cwd=NODE_DIR)
    else:
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
    if os.getenv("GITHUB_ACTIONS") == "true":
      code |= _run(["npm", "install"], cwd=NODE_DIR)
    else:
      code |= _run(["npm", "ci"], cwd=NODE_DIR)
    code |= _run(["npm", "run", "build"], cwd=NODE_DIR)
    code |= _run(["npm", "test"], cwd=NODE_DIR)
    code |= _run(["poetry", "run", "pytest", "-q"], cwd=PY_DIR)
    sys.exit(code)


def _ensure_example_node_env(example_dir: str, extra_deps: list[str], tarball_path: str) -> int:
    code = 0
    # Initialize if no package.json
    if not os.path.exists(os.path.join(example_dir, "package.json")):
        code |= _run(["npm", "init", "-y"], cwd=example_dir)
    # Install our local build tarball explicitly
    code |= _run(["npm", "install", tarball_path], cwd=example_dir)
    # Install deps (idempotent)
    deps = ["tsx", *extra_deps]
    code |= _run(["npm", "install", *deps], cwd=example_dir)
    return code


def _wait_for_port(host: str, port: int, timeout_s: int = 20) -> bool:
    import socket, time
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def demo_node() -> None:
    """Run the Node server and client examples end-to-end.

    Steps:
      - Build local Node package
      - Prepare example environments (npm link + deps)
      - Start Express server (background)
      - Run Node client once
      - Stop server
    """
    code = 0
    # Build Node package so examples can link it
    if os.getenv("GITHUB_ACTIONS") == "true":
        code |= _run(["npm", "install"], cwd=NODE_DIR)
    else:
        code |= _run(["npm", "ci"], cwd=NODE_DIR)
    code |= _run(["npm", "run", "build"], cwd=NODE_DIR)
    # Pack Node package to a tarball and use that for examples
    pack_code, pack_out = _run_output(["npm", "pack", "--json"], cwd=NODE_DIR)
    if pack_code != 0:
        sys.exit(pack_code)
    import json as _json
    try:
        entries = _json.loads(pack_out)
        tarball = entries[0]["filename"] if isinstance(entries, list) else entries.get("filename")
    except Exception:
        tarball = None
    if not tarball:
        print("Failed to determine npm pack tarball name", file=sys.stderr)
        sys.exit(1)
    tarball_path = os.path.join(NODE_DIR, tarball)

    # Prepare examples
    code |= _ensure_example_node_env(EX_NODE_SERVER, ["express", "body-parser"], tarball_path)
    code |= _ensure_example_node_env(EX_NODE_CLIENT, ["node-fetch@3"], tarball_path)
    if code != 0:
        sys.exit(code)

    # Start server in background
    server_cmd = ["npx", "tsx", "server.ts"]
    print("$", " ".join(server_cmd), f"(cwd={EX_NODE_SERVER})")
    env = dict(os.environ)
    env["PORT"] = DEMO_PORT
    server_proc = subprocess.Popen(server_cmd, cwd=EX_NODE_SERVER, env=env)

    try:
        if not _wait_for_port("127.0.0.1", int(DEMO_PORT), timeout_s=20):
            print(f"Server did not start listening on :{DEMO_PORT} in time", file=sys.stderr)
            server_proc.terminate()
            server_proc.wait(timeout=5)
            sys.exit(1)

        # Run client once
        code |= _run(["npx", "tsx", "index.ts"], cwd=EX_NODE_CLIENT)
    finally:
        # Stop server
        try:
            server_proc.terminate()
            server_proc.wait(timeout=5)
        except Exception:
            try:
                server_proc.kill()
            except Exception:
                pass
    sys.exit(code)
 
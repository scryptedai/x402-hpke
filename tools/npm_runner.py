import subprocess, os

NODE_DIR = os.path.join(os.path.dirname(__file__), "..", "packages", "node")


def run(cmd: list[str]):
    print(">>", " ".join(cmd), flush=True)
    subprocess.check_call(cmd, cwd=NODE_DIR)


def build():
    run(["npm", "install"])
    run(["npm", "run", "build"])


def test():
    run(["npm", "install"])
    run(["npm", "test"])


def publish():
    run(["npm", "run", "build"])
    run(["npm", "publish", "--access", "public"])
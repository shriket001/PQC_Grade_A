"""One-command dev launcher for VAYUNX.

Starts the Docker infra (Postgres, Redis, MinIO, Mailhog), then the backend
(uvicorn --reload), the arq worker (email delivery), and the frontend (vite)
as native processes, waits for backend + frontend to come up, and opens the
app in the default browser.

Usage (from anywhere):
    python backend/run.py
    (or, from inside backend/):  python run.py

Ctrl+C stops backend, worker, and frontend. Docker infra is left running
(cheap to leave up, slow to reprovision) — pass --stop-docker to tear it
down on exit too.
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent
FRONTEND_DIR = ROOT_DIR / "frontend"
COMPOSE_FILE = ROOT_DIR / "docker" / "docker-compose.yml"
ENV_FILE = ROOT_DIR / ".env"

# Dev-only self-signed cert (generate once, e.g. via openssl, into this exact
# path) for "localhost" + 127.0.0.1. If both files are present, the backend
# serves https directly (uvicorn --ssl-keyfile/--ssl-certfile) and vite's own
# config (frontend/vite.config.ts) picks the same cert up independently for
# the frontend dev server. Absent either file, everything falls back to plain
# http exactly as before — this is opt-in, not a requirement to run the app.
DEV_CERT_DIR = ROOT_DIR / "docker" / "certs" / "dev-https"
DEV_CERT_FILE = DEV_CERT_DIR / "server.crt"
DEV_KEY_FILE = DEV_CERT_DIR / "server.key"
USE_HTTPS = DEV_CERT_FILE.exists() and DEV_KEY_FILE.exists()

BACKEND_HOST, BACKEND_PORT = "127.0.0.1", 8000
FRONTEND_HOST, FRONTEND_PORT = "127.0.0.1", 5173
_SCHEME = "https" if USE_HTTPS else "http"
FRONTEND_URL = f"{_SCHEME}://{FRONTEND_HOST}:{FRONTEND_PORT}"

INFRA_SERVICES = ["postgres", "redis", "minio", "mailhog"]
# mailhog has no healthcheck defined in docker-compose.yml, so it never
# reports "healthy" — only wait on the services that actually define one.
HEALTH_CHECKED_SERVICES = ["postgres", "redis", "minio"]

VENV_PYTHON = BACKEND_DIR / ".venv" / "Scripts" / "python.exe"
NPM_CMD = "npm.cmd" if sys.platform == "win32" else "npm"


def wait_for_port(host: str, port: int, timeout: float, label: str) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(1)
    print(f"[run.py] Timed out waiting for {label} on {host}:{port}")
    return False


def start_docker_infra() -> None:
    print("[run.py] Starting Docker infra (postgres, redis, minio, mailhog)...")
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "--env-file", str(ENV_FILE),
         "up", "-d", *INFRA_SERVICES],
        cwd=ROOT_DIR,
        check=True,
    )

    print("[run.py] Waiting for infra services to report healthy...")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "--env-file", str(ENV_FILE),
             "ps", "--format", "{{.Service}} {{.Health}}"],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=True,
        )
        statuses = dict(line.split(" ", 1) for line in result.stdout.splitlines() if " " in line)
        if all(statuses.get(svc) == "healthy" for svc in HEALTH_CHECKED_SERVICES):
            print("[run.py] Infra is healthy.")
            return
        time.sleep(2)
    print("[run.py] WARNING: infra did not report healthy in time, continuing anyway.")


def start_backend() -> subprocess.Popen:
    python_exe = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable
    cmd = [python_exe, "-m", "uvicorn", "src.main:app", "--reload",
           "--host", BACKEND_HOST, "--port", str(BACKEND_PORT)]
    if USE_HTTPS:
        print(f"[run.py] Starting backend (uvicorn --reload, https via {DEV_CERT_FILE})...")
        cmd += ["--ssl-keyfile", str(DEV_KEY_FILE), "--ssl-certfile", str(DEV_CERT_FILE)]
    else:
        print("[run.py] Starting backend (uvicorn --reload, plain http — "
              f"no dev cert found at {DEV_CERT_FILE})...")
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    return subprocess.Popen(
        cmd,
        cwd=BACKEND_DIR,
        creationflags=creationflags,
    )


def start_worker() -> subprocess.Popen:
    python_exe = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable
    print("[run.py] Starting arq worker (email delivery)...")
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    return subprocess.Popen(
        [python_exe, "-m", "arq", "src.workers.worker_settings.WorkerSettings"],
        cwd=BACKEND_DIR,
        creationflags=creationflags,
    )


def start_frontend() -> subprocess.Popen:
    print("[run.py] Starting frontend (vite dev server)...")
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    return subprocess.Popen([NPM_CMD, "run", "dev"], cwd=FRONTEND_DIR, creationflags=creationflags)


def kill_process_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
        )
    else:
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stop-docker", action="store_true",
                         help="Stop the Docker infra containers on exit (Ctrl+C).")
    parser.add_argument("--no-browser", action="store_true",
                         help="Don't auto-open the browser.")
    args = parser.parse_args()

    start_docker_infra()

    backend_proc = start_backend()
    worker_proc = start_worker()
    frontend_proc = start_frontend()

    try:
        backend_up = wait_for_port(BACKEND_HOST, BACKEND_PORT, 60, "backend")
        frontend_up = wait_for_port(FRONTEND_HOST, FRONTEND_PORT, 60, "frontend")

        if backend_up and frontend_up and not args.no_browser:
            print(f"[run.py] Opening {FRONTEND_URL} in your default browser...")
            webbrowser.open(FRONTEND_URL)
        elif not (backend_up and frontend_up):
            print("[run.py] Backend or frontend did not come up in time; check the logs above.")

        print("[run.py] Running. Press Ctrl+C to stop backend, worker, and frontend.")
        while True:
            for proc, name in ((backend_proc, "Backend"), (worker_proc, "Worker"), (frontend_proc, "Frontend")):
                if proc.poll() is not None:
                    print(f"[run.py] {name} process exited; shutting down.")
                    raise KeyboardInterrupt
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[run.py] Stopping...")
    finally:
        for proc, name in ((frontend_proc, "frontend"), (worker_proc, "worker"), (backend_proc, "backend")):
            kill_process_tree(proc)
            print(f"[run.py] {name} stopped.")

        if args.stop_docker:
            print("[run.py] Stopping Docker infra...")
            subprocess.run(
                ["docker", "compose", "-f", str(COMPOSE_FILE), "--env-file", str(ENV_FILE),
                 "stop", *INFRA_SERVICES],
                cwd=ROOT_DIR,
            )


if __name__ == "__main__":
    main()

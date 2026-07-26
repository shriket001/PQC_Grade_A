# VAYUNX Chat Application — Grade A

Secure chat application with end-to-end encryption, post-quantum key exchange,
MFA, and SSO (OAuth/SAML). Backend: FastAPI + PostgreSQL + Redis + MinIO.
Frontend: React + Vite + TypeScript.

## Prerequisites

- Python 3.11 (backend requires `>=3.11,<3.12`)
- Node.js 18+ and npm
- Docker Desktop (for PostgreSQL, Redis, MinIO, Mailhog)
- OpenSSL (for local dev certs, optional)

## 1. Clone and configure environment

```bash
git clone <repo-url>
cd Grade_A
cp .env.example .env
```

Edit `.env` and fill in values (DB/Redis/MinIO passwords, `MFA_SECRET_ENCRYPTION_KEY`,
etc.). Generate the MFA key with:

```bash
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

Google OAuth and SAML SSO are optional — leave those variables blank to disable
them. See the comments in `.env.example` for full setup instructions.

## 2. Backend setup

Dependencies are declared in [`backend/pyproject.toml`](backend/pyproject.toml)
(source of truth) and mirrored in `backend/requirements.txt` for `pip`-based
installs (includes runtime + dev/test/lint tools).

```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# Option A — editable install from pyproject.toml
pip install -e ".[dev]"

# Option B — requirements.txt
pip install -r requirements.txt
```

Run database migrations (requires Postgres up — see step 4):

```bash
alembic upgrade head
```

## 3. Frontend setup

```bash
cd frontend
npm install
```

## 4. Start infrastructure (Postgres, Redis, MinIO, Mailhog)

```bash
docker compose -f docker/docker-compose.yml --env-file .env up -d postgres redis minio mailhog
```

## 5. Run the app

### Option A — one-command dev launcher (recommended)

From the project root, with the backend venv already created (step 2):

```bash
python backend/run.py
```

This starts Docker infra, the backend (`uvicorn --reload` on `:8000`), the
`arq` worker (email delivery), and the frontend (`vite` on `:5173`), waits for
both to come up, and opens the app in your browser. Press `Ctrl+C` to stop
backend/worker/frontend (Docker infra is left running; pass `--stop-docker` to
also stop it on exit).

### Option B — run each service manually

```bash
# Terminal 1 — backend
cd backend
.venv\Scripts\activate        # or: source .venv/bin/activate
uvicorn src.main:app --reload --host 127.0.0.1 --port 8000

# Terminal 2 — background worker (email delivery)
cd backend
.venv\Scripts\activate
python -m arq src.workers.worker_settings.WorkerSettings

# Terminal 3 — frontend
cd frontend
npm run dev
```

App runs at `http://localhost:5173` (or `https://localhost:5173` if you've
generated dev TLS certs — see `.env.example`).

### Option C — full Docker stack (backend, worker, frontend, reverse proxy)

```bash
docker compose -f docker/docker-compose.yml --env-file .env up --build
```

Serves the app via nginx reverse proxy at `https://localhost`.

## Running tests

```bash
# Backend
cd backend
pytest

# Frontend
cd frontend
npm test
```

## Useful ports

| Service        | Port |
|----------------|------|
| Frontend (Vite)| 5173 |
| Backend (API)  | 8000 |
| PostgreSQL     | 5433 |
| Redis          | 6379 |
| MinIO API      | 9000 |
| MinIO Console  | 9001 |
| Mailhog SMTP   | 1025 |
| Mailhog Web UI | 8025 |
| Reverse proxy  | 443  |

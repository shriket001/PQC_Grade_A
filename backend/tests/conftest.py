"""Shared Pytest fixtures: async test database, test HTTP client.

Model-factory fixtures are added by each user story alongside its models
(e.g. a `user_factory` fixture lands with US1's `User` model).
"""

import base64
import os
from pathlib import Path

from dotenv import dotenv_values

# Load the developer's own repo-root `.env` (if present) so test credentials
# always match whatever real local Postgres/Redis instance they configured,
# rather than guessing/hardcoding a password here. CI supplies its own
# throwaway service credentials directly as environment variables (see
# .github/workflows/ci.yml), which take precedence via setdefault below.
_repo_root_env = dotenv_values(Path(__file__).resolve().parents[2] / ".env")


def _derive_test_db_url(database_url: str | None) -> str:
    if not database_url:
        return "postgresql+asyncpg://vayunx:test-password@localhost:5432/vayunx_test"
    base, _, _ = database_url.rpartition("/")
    return f"{base}/vayunx_test"


def _derive_test_redis_url(redis_url: str | None) -> str:
    if not redis_url:
        return "redis://localhost:6379/1"
    base, _, _ = redis_url.rpartition("/")
    return f"{base}/1"


os.environ.setdefault("DATABASE_URL", _derive_test_db_url(_repo_root_env.get("DATABASE_URL")))
os.environ.setdefault("REDIS_URL", _derive_test_redis_url(_repo_root_env.get("REDIS_URL")))
# Same MinIO server as dev (there's no separate test instance), isolated by
# bucket name only — same pattern as DATABASE_URL/REDIS_URL above. Real
# credentials are required since MinIO validates them against its own IAM
# records; a fabricated access key would always fail with InvalidAccessKeyId.
_object_storage_endpoint = _repo_root_env.get("OBJECT_STORAGE_ENDPOINT") or "http://localhost:9000"
_object_storage_access_key = _repo_root_env.get("OBJECT_STORAGE_ACCESS_KEY") or "test-access-key"
_object_storage_secret_key = _repo_root_env.get("OBJECT_STORAGE_SECRET_KEY") or "test-secret-key"
os.environ.setdefault("OBJECT_STORAGE_ENDPOINT", _object_storage_endpoint)
os.environ.setdefault("OBJECT_STORAGE_BUCKET", "vayunx-files-test")
os.environ.setdefault("OBJECT_STORAGE_ACCESS_KEY", _object_storage_access_key)
os.environ.setdefault("OBJECT_STORAGE_SECRET_KEY", _object_storage_secret_key)
os.environ.setdefault(
    "JWT_SIGNING_PRIVATE_KEY_PATH",
    str(Path(__file__).resolve().parent / "fixtures" / "test_ed25519_private.pem"),
)
os.environ.setdefault(
    "JWT_SIGNING_PUBLIC_KEY_PATH",
    str(Path(__file__).resolve().parent / "fixtures" / "test_ed25519_public.pem"),
)
os.environ.setdefault("CRYPTO_GRADE", "grade-a")
os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://localhost:5173")
# The test client talks to the ASGI app over plain http://testserver (no TLS),
# and a `Secure`-flagged cookie is never sent back by a real cookie jar over
# plain http — httpx's AsyncClient enforces this exactly like a browser would.
# Tests need the refresh cookie to round-trip, so relax `Secure` here only.
os.environ.setdefault("REFRESH_COOKIE_SECURE", "false")
os.environ.setdefault(
    "MFA_SECRET_ENCRYPTION_KEY",
    _repo_root_env.get("MFA_SECRET_ENCRYPTION_KEY") or base64.b64encode(b"\x00" * 32).decode(),
)
os.environ.setdefault("SMTP_HOST", "localhost")
os.environ.setdefault("SMTP_FROM_ADDRESS", "test@vayunx.example")
# Pinned (not left to fall through from the developer's own .env) so
# OIDC/SAML redirect-target assertions in tests stay deterministic regardless
# of whatever real APP_BASE_URL a developer has configured locally (e.g. for
# their own https://localhost:5173 dev setup).
os.environ.setdefault("APP_BASE_URL", "http://localhost:5173")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.core.config import get_settings  # noqa: E402
from src.core.database import Base  # noqa: E402

# Import every model module so Base.metadata is fully populated for
# create_all/drop_all — mirrors alembic/env.py's import list. Aliased to
# avoid shadowing the `session` variable name used by the db_session fixture.
from src.models import email_verification_token as _ev_token_module  # noqa: F401,E402
from src.models import external_identity_link as _ext_id_link_module  # noqa: F401,E402
from src.models import mfa_factor as _mfa_factor_module  # noqa: F401,E402
from src.models import role as _role_module  # noqa: F401,E402
from src.models import session as _session_module  # noqa: F401,E402
from src.models import user as _user_module  # noqa: F401,E402


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    engine = create_async_engine(get_settings().database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def client() -> AsyncClient:
    from src.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# ---------------------------------------------------------------------------
# Phase 4 (Authentication) fixtures
# ---------------------------------------------------------------------------

from collections.abc import AsyncIterator  # noqa: E402
from dataclasses import dataclass  # noqa: E402

from src.core.database import get_db_session  # noqa: E402
from src.core.dependencies import (  # noqa: E402
    get_audit_logger,
    get_verification_email_sender,
)
from src.main import app  # noqa: E402


class CapturingEmailSender:
    """In-memory VerificationEmailSender — records (email, token) for tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def send(self, to_email: str, token: str) -> None:
        self.calls.append((to_email, token))


class CapturingAuditLogger:
    """In-memory AuditLogger — records every auth event for assertions."""

    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    async def record(
        self, *, action: str, actor_id: object, outcome: str, context: dict[str, object]
    ) -> None:
        self.records.append(
            {"action": action, "actor_id": actor_id, "outcome": outcome, "context": context}
        )


@dataclass
class TestApp:
    """Bundle yielded by `api_client`: the HTTP client plus capture sinks."""

    # pytest would otherwise try to collect this helper class as a test suite
    # because its name starts with "Test" — it's a fixture payload, not tests.
    __test__ = False

    client: AsyncClient
    emails: CapturingEmailSender
    audit: CapturingAuditLogger


@pytest_asyncio.fixture
async def api_client() -> AsyncIterator[TestApp]:
    """Tables created + capturing email/audit sinks wired via DI overrides.

    `get_db_session` is overridden to a per-test engine/session_factory so the
    app never touches the module-level `_engine` in database.py — that engine's
    asyncpg connections would otherwise outlive pytest-asyncio's
    function-scoped event loop and race with loop teardown (Windows
    ProactorEventLoop ``send`` on a closed loop). The per-test engine is the
    same pattern the `db_session` fixture uses (which is why repo tests pass).
    """
    engine = create_async_engine(get_settings().database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)

    async def _get_db_session_override() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    emails = CapturingEmailSender()
    audit = CapturingAuditLogger()
    app.dependency_overrides[get_db_session] = _get_db_session_override
    app.dependency_overrides[get_verification_email_sender] = lambda: emails
    app.dependency_overrides[get_audit_logger] = lambda: audit

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield TestApp(client=ac, emails=emails, audit=audit)

    app.dependency_overrides.clear()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _reset_rate_limiter() -> AsyncIterator[None]:
    """Flush the slowapi Redis counters before each test so cross-test login
    counts (same test-client IP) don't accumulate into false 429s. Tolerant of a
    missing Redis so unit/crypto tests still pass without it.

    Also clears the `get_redis()` lru_cache singleton (`src/core/redis_client.py`)
    at the start of each test: pytest-asyncio hands each test function its own
    event loop, but `get_redis()` is process-lifetime-cached, so a client created
    on a previous (now-closed) loop would otherwise be reused by any code path
    that calls `get_redis()` from within a test (e.g. `ConnectionManager` fan-out
    triggered by a REST endpoint) — "Event loop is closed" on Windows'
    ProactorEventLoop. Clearing the cache forces a fresh client bound to the
    current test's loop; the stale client is simply dropped (its connections were
    already unusable on the closed loop).
    """
    from src.core.redis_client import get_redis

    get_redis.cache_clear()
    import redis.asyncio as aioredis

    try:
        client = aioredis.from_url(get_settings().redis_url)
        await client.flushdb()
        await client.aclose()
    except Exception:
        pass
    yield
    try:
        client = aioredis.from_url(get_settings().redis_url)
        await client.flushdb()
        await client.aclose()
    except Exception:
        pass


def username_from_email(email: str) -> str:
    """Derive a valid username handle (matches `^[a-z0-9_]{3,32}$`) from an
    email's local-part, for test fixtures: lowercased, non-handle chars replaced
    with `_`, truncated to 32, padded to 3. Used so test helpers can register
    users without spelling out a username each time."""
    import re

    handle = re.sub(r"[^a-z0-9_]", "_", email.split("@", 1)[0].lower())[:32]
    return handle.ljust(3, "_") if len(handle) < 3 else handle


async def register_and_verify(
    api_client: TestApp, *, email: str, password: str, username: str | None = None
) -> dict:
    """Helper: register, capture+submit the verification token, return the
    register response JSON (with user_id + username). Used across the auth test
    files. A username is derived from the email local-part when not given."""
    handle = username or username_from_email(email)
    resp = await api_client.client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "username": handle},
    )
    assert resp.status_code == 201, resp.text
    assert api_client.emails.calls, "no verification email was enqueued"
    token = api_client.emails.calls[-1][1]
    verify = await api_client.client.post(
        "/api/v1/auth/verify-email", json={"verification_token": token}
    )
    assert verify.status_code == 200, verify.text
    return resp.json()

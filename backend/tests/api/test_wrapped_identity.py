"""FR-054 — password-wrapped recoverable identity keys (Phase 5c).

The server is a public-key directory that additionally stores the user's
private keypair **wrapped** (encrypted) under a password-derived key, so the
same identity can be recovered on a new browser. The wrapped blobs + wrap
parameters are opaque to the server — it stores and relays them but never
decrypts (FR-051/SC-002 preserved).

These tests pin the security boundary:
- `GET /users/me/identity-key` (auth-scoped) returns the wrapped material.
- `GET /users/{user_id}/identity-keys` (public directory) NEVER exposes wrapped
  material (no auth-to-other-users leak — enforced like the email-PII boundary).
- publish/rotate persist wrapped fields verbatim; rotation re-wraps.
- Half-wrapped publishes are rejected (all-or-none rule).
- Migration 0004 adds the columns and downgrades cleanly.
"""

import asyncio
import base64
import os
import uuid
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import asyncpg
import pytest
import pytest_asyncio
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alembic import command
from src.core.config import get_settings
from src.core.database import Base, get_db_session
from src.core.dependencies import get_audit_logger, get_verification_email_sender
from src.crypto.factory import get_identity_key_provider
from src.main import app
from src.models import (  # noqa: F401
    conversation,
    email_verification_token,
    identity_key,
    message,
    role,
    session,
    user,
)
from tests.conftest import CapturingAuditLogger, CapturingEmailSender, TestApp, username_from_email

_PASSWORD = "Sup3rSecret!pw"

_WRAP_FIELDS = (
    "wrapped_signing_private_key",
    "wrapped_kem_private_key",
    "wrap_nonce",
    "wrap_kdf_salt",
    "wrap_kdf_params",
    "wrap_alg",
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _wrapped_payload() -> dict[str, str]:
    # Opaque wrapped blobs — the server never inspects their contents, so any
    # distinct bytes stand in for the real AES-256-GCM ciphertexts.
    return {
        "wrapped_signing_private_key": _b64(b"\x11" * 40),
        "wrapped_kem_private_key": _b64(b"\x22" * 32),
        "wrap_nonce": _b64(b"\x00" * 12),
        "wrap_kdf_salt": _b64(b"\x33" * 16),
        "wrap_kdf_params": "argon2id:t=3:m=65536:p=4",
        "wrap_alg": "aes-256-gcm",
    }


async def _register_login(api: TestApp, *, email: str) -> tuple[str, str]:
    resp = await api.client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": _PASSWORD, "username": username_from_email(email)},
    )
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["user_id"]
    token = api.emails.calls[-1][1]
    verify = await api.client.post("/api/v1/auth/verify-email", json={"verification_token": token})
    assert verify.status_code == 200, verify.text
    login = await api.client.post(
        "/api/v1/auth/login", json={"email": email, "password": _PASSWORD, "device_context": "web"}
    )
    assert login.status_code == 200, login.text
    return user_id, login.json()["access_token"]


async def _publish_with_wrap(api: TestApp, token: str, *, device_label: str) -> dict:
    provider = get_identity_key_provider()
    signing_pub, _ = provider.generate_keypair()
    kem_pub, _ = provider.generate_keypair()
    payload = {
        "device_label": device_label,
        "public_signing_key": _b64(signing_pub),
        "public_kem_key": _b64(kem_pub),
    }
    payload.update(_wrapped_payload())
    resp = await api.client.post(
        "/api/v1/users/me/identity-keys", json=payload, headers=_headers(token)
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest_asyncio.fixture
async def api_client() -> AsyncIterator[TestApp]:
    engine = create_async_engine(get_settings().database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)

    async def _get_db_session_override() -> AsyncIterator[AsyncSession]:
        async with session_factory() as db_session:
            try:
                yield db_session
                await db_session.commit()
            except Exception:
                await db_session.rollback()
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


@pytest.mark.asyncio
class TestWrappedIdentityPublish:
    async def test_publish_persists_and_returns_wrapped_fields(self, api_client: TestApp) -> None:
        _, token = await _register_login(api_client, email="wrap@example.test")
        published = await _publish_with_wrap(api_client, token, device_label="laptop")
        # The auth-scoped publish response carries the wrapped material back.
        for field in _WRAP_FIELDS:
            assert published[field] is not None, f"{field} missing from publish response"
        assert published["wrap_kdf_params"] == "argon2id:t=3:m=65536:p=4"
        assert published["wrap_alg"] == "aes-256-gcm"

        # GET /users/me/identity-key returns the same wrapped material (owner fetch).
        mine = await api_client.client.get("/api/v1/users/me/identity-key", headers=_headers(token))
        assert mine.status_code == 200, mine.text
        body = mine.json()
        assert body["id"] == published["id"]
        for field in _WRAP_FIELDS:
            assert body[field] is not None, f"{field} missing from me/identity-key"

    async def test_my_identity_key_404_when_none_published(self, api_client: TestApp) -> None:
        _, token = await _register_login(api_client, email="none@example.test")
        resp = await api_client.client.get("/api/v1/users/me/identity-key", headers=_headers(token))
        assert resp.status_code == 404, resp.text

    async def test_my_identity_key_requires_auth(self, api_client: TestApp) -> None:
        resp = await api_client.client.get("/api/v1/users/me/identity-key")
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "unauthenticated"

    async def test_publish_without_wrapped_is_allowed_legacy(self, api_client: TestApp) -> None:
        # Legacy / non-recovering publishes omit wrapped fields entirely.
        _, token = await _register_login(api_client, email="legacy@example.test")
        provider = get_identity_key_provider()
        signing_pub, _ = provider.generate_keypair()
        kem_pub, _ = provider.generate_keypair()
        resp = await api_client.client.post(
            "/api/v1/users/me/identity-keys",
            json={
                "device_label": "legacy-device",
                "public_signing_key": _b64(signing_pub),
                "public_kem_key": _b64(kem_pub),
            },
            headers=_headers(token),
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        for field in _WRAP_FIELDS:
            assert body[field] is None

    async def test_publish_rejects_partial_wrapped_set(self, api_client: TestApp) -> None:
        # FR-054 all-or-none: supplying a subset of wrapped fields must 400 so a
        # half-wrapped record can never be persisted.
        _, token = await _register_login(api_client, email="partial@example.test")
        provider = get_identity_key_provider()
        signing_pub, _ = provider.generate_keypair()
        kem_pub, _ = provider.generate_keypair()
        payload = {
            "device_label": "partial-device",
            "public_signing_key": _b64(signing_pub),
            "public_kem_key": _b64(kem_pub),
            "wrapped_signing_private_key": _b64(b"\x44" * 40),  # only one of the set
        }
        resp = await api_client.client.post(
            "/api/v1/users/me/identity-keys", json=payload, headers=_headers(token)
        )
        assert resp.status_code == 400, resp.text


@pytest.mark.asyncio
class TestWrappedIdentityDirectoryBoundary:
    async def test_directory_strips_wrapped_fields(self, api_client: TestApp) -> None:
        # SECURITY BOUNDARY (FR-054): the public directory must never expose
        # wrapped private material — only public keys.
        alice_id, alice_token = await _register_login(api_client, email="dir@example.test")
        await _publish_with_wrap(api_client, alice_token, device_label="alice-laptop")

        _, bob_token = await _register_login(api_client, email="dirbob@example.test")
        listing = await api_client.client.get(
            f"/api/v1/users/{alice_id}/identity-keys", headers=_headers(bob_token)
        )
        assert listing.status_code == 200, listing.text
        keys = listing.json()
        assert len(keys) == 1
        for field in _WRAP_FIELDS:
            assert field not in keys[0], f"directory leaked {field}"
        # Public material is still present.
        assert keys[0]["public_signing_key"]
        assert keys[0]["public_kem_key"]


@pytest.mark.asyncio
class TestWrappedIdentityRotation:
    async def test_rotation_re_wraps_private_material(self, api_client: TestApp) -> None:
        _, token = await _register_login(api_client, email="rewrap@example.test")
        provider = get_identity_key_provider()

        old_signing_pub, old_signing_priv = provider.generate_keypair()
        old_kem_pub, _ = provider.generate_keypair()
        first_payload = {
            "device_label": "device-1",
            "public_signing_key": _b64(old_signing_pub),
            "public_kem_key": _b64(old_kem_pub),
        }
        first_payload.update(_wrapped_payload())
        pub = await api_client.client.post(
            "/api/v1/users/me/identity-keys", json=first_payload, headers=_headers(token)
        )
        assert pub.status_code == 201, pub.text

        new_signing_pub, _ = provider.generate_keypair()
        new_kem_pub, _ = provider.generate_keypair()
        attestation = provider.sign(old_signing_priv, new_signing_pub + new_kem_pub)

        # Re-wrap under the same password-derived key: new wrapped blobs.
        new_wrap = _wrapped_payload()
        new_wrap["wrapped_signing_private_key"] = _b64(b"\x55" * 40)
        new_wrap["wrapped_kem_private_key"] = _b64(b"\x66" * 32)
        rot_payload = {
            "new_public_signing_key": _b64(new_signing_pub),
            "new_public_kem_key": _b64(new_kem_pub),
            "rotation_attestation": _b64(attestation),
        }
        rot_payload.update(new_wrap)
        rot = await api_client.client.post(
            "/api/v1/users/me/identity-keys/rotate", json=rot_payload, headers=_headers(token)
        )
        assert rot.status_code == 200, rot.text
        rotated = rot.json()
        assert rotated["key_version"] == 2
        # The re-wrapped blobs are persisted verbatim and returned to the owner.
        assert rotated["wrapped_signing_private_key"] == new_wrap["wrapped_signing_private_key"]
        assert rotated["wrapped_kem_private_key"] == new_wrap["wrapped_kem_private_key"]

        # And reflected by the auth-scoped fetch.
        mine = await api_client.client.get("/api/v1/users/me/identity-key", headers=_headers(token))
        assert mine.status_code == 200
        assert mine.json()["wrapped_signing_private_key"] == new_wrap["wrapped_signing_private_key"]


@pytest.mark.asyncio
class TestMigration0004WrappedIdentityKeys:
    """Isolated alembic roundtrip on a throwaway database — proves 0004 adds the
    six wrap columns and downgrades cleanly, without touching the shared test
    DB used by the create_all fixtures."""

    async def test_migration_0004_up_then_down_then_up(self) -> None:
        settings = get_settings()
        # Parse the configured test DB URL to build a server DSN + a unique name.
        parsed = urlparse(settings.database_url.replace("+asyncpg", ""))
        server_dsn = (
            f"postgres://{parsed.username}:{parsed.password}@{parsed.hostname}:{parsed.port}"
        )
        unique = f"vayunx_mig_{uuid.uuid4().hex[:8]}"

        # Create the throwaway DB from the maintenance connection.
        admin = await asyncpg.connect(f"{server_dsn}/postgres")
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{unique}"')
            await admin.execute(f'CREATE DATABASE "{unique}"')
        finally:
            await admin.close()

        cfg = Config("alembic.ini")
        os.environ["DATABASE_URL"] = (
            f"postgresql+asyncpg://{parsed.username}:{parsed.password}"
            f"@{parsed.hostname}:{parsed.port}/{unique}"
        )
        get_settings.cache_clear()

        async def _columns() -> set[str]:
            engine = create_async_engine(get_settings().database_url)
            async with engine.connect() as conn:
                cols = await conn.run_sync(
                    lambda sync_conn: {
                        c["name"] for c in inspect(sync_conn).get_columns("identity_keys")
                    }
                )
            await engine.dispose()
            return cols

        try:
            # alembic env.py uses asyncio.run(), which cannot nest in this test's
            # running loop — run the sync command in a worker thread instead.
            await asyncio.to_thread(command.upgrade, cfg, "head")
            cols = await _columns()
            for col in (
                "wrapped_signing_private_key",
                "wrapped_kem_private_key",
                "wrap_nonce",
                "wrap_kdf_salt",
                "wrap_kdf_params",
                "wrap_alg",
            ):
                assert col in cols, f"{col} missing after upgrade"

            # Downgrade past 0004 (to 0003): the wrap columns are dropped. We
            # target the explicit revision rather than `-1` so this stays correct
            # as later migrations extend the chain past 0004 (e.g. 0005).
            await asyncio.to_thread(command.downgrade, cfg, "0003")
            cols_after = await _columns()
            for col in (
                "wrapped_signing_private_key",
                "wrapped_kem_private_key",
                "wrap_nonce",
                "wrap_kdf_salt",
                "wrap_kdf_params",
                "wrap_alg",
            ):
                assert col not in cols_after, f"{col} present after downgrade"

            # Re-upgrade: columns return (idempotent, no leftover state).
            await asyncio.to_thread(command.upgrade, cfg, "head")
            assert "wrap_alg" in (await _columns())
        finally:
            get_settings.cache_clear()
            # Restore the original DATABASE_URL for any subsequent tests.
            os.environ["DATABASE_URL"] = settings.database_url
            get_settings.cache_clear()
            admin = await asyncpg.connect(f"{server_dsn}/postgres")
            try:
                await admin.execute(f'DROP DATABASE IF EXISTS "{unique}"')
            finally:
                await admin.close()

"""US4 file-sharing API tests (T071): upload/download round trip, oversized
upload rejected before storage, non-participant blocked, no partially-uploaded
file is ever addressable.

The uploaded "ciphertext" is a fabricated opaque blob — this service never
inspects file content (FR-051/SC-002); real client-side encryption is a
frontend concern covered by `crypto/fileCrypto.test.ts`.
"""

import base64
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.config import get_settings
from src.core.database import Base, get_db_session
from src.core.dependencies import get_audit_logger, get_verification_email_sender
from src.crypto.factory import get_identity_key_provider
from src.main import app
from src.models import (  # noqa: F401
    conversation,
    email_verification_token,
    file_attachment,
    identity_key,
    message,
    role,
    session,
    user,
)
from tests.conftest import CapturingAuditLogger, CapturingEmailSender, TestApp, username_from_email

_PASSWORD = "Sup3rSecret!pw"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _file_envelope() -> str:
    import json

    return json.dumps({"alg": "aes-256-gcm", "nonce": _b64(b"\x00" * 12), "version": 1})


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


async def _publish_key(api: TestApp, token: str, *, device_label: str) -> str:
    provider = get_identity_key_provider()
    signing_pub, _ = provider.generate_keypair()
    kem_pub, _ = provider.generate_keypair()
    resp = await api.client.post(
        "/api/v1/users/me/identity-keys",
        json={
            "device_label": device_label,
            "public_signing_key": _b64(signing_pub),
            "public_kem_key": _b64(kem_pub),
        },
        headers=_headers(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _create_direct(api: TestApp, token: str, *, peer_id: str) -> str:
    resp = await api.client.post(
        "/api/v1/conversations",
        json={"type": "direct", "participant_user_ids": [peer_id]},
        headers=_headers(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _upload(
    api: TestApp,
    token: str,
    *,
    conversation_id: str,
    identity_key_id: str,
    payload: bytes,
    content_type: str = "image/png",
    declared_size: int | None = None,
):
    return await api.client.post(
        f"/api/v1/conversations/{conversation_id}/files",
        headers=_headers(token),
        data={
            "sender_identity_key_id": identity_key_id,
            "file_envelope": _file_envelope(),
            "content_type": content_type,
            "size_bytes": str(declared_size if declared_size is not None else len(payload)),
        },
        files={"file_ciphertext": ("blob.bin", payload, "application/octet-stream")},
    )


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
class TestFileUploadDownload:
    async def test_upload_then_download_round_trip(self, api_client: TestApp) -> None:
        alice_id, alice_token = await _register_login(api_client, email="alice@example.test")
        bob_id, bob_token = await _register_login(api_client, email="bob@example.test")
        alice_key = await _publish_key(api_client, alice_token, device_label="alice-laptop")
        conv_id = await _create_direct(api_client, alice_token, peer_id=bob_id)

        payload = b"\x89PNG-fake-ciphertext-bytes"
        upload_resp = await _upload(
            api_client,
            alice_token,
            conversation_id=conv_id,
            identity_key_id=alice_key,
            payload=payload,
        )
        assert upload_resp.status_code == 201, upload_resp.text
        body = upload_resp.json()
        assert body["upload_status"] == "complete"
        assert body["size_bytes"] == len(payload)
        file_id = body["file_attachment_id"]

        download = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/files/{file_id}", headers=_headers(bob_token)
        )
        assert download.status_code == 200, download.text
        assert download.content == payload
        assert download.headers["x-file-content-type"] == "image/png"

    async def test_oversized_upload_rejected_before_storage(self, api_client: TestApp) -> None:
        alice_id, alice_token = await _register_login(api_client, email="alice2@example.test")
        bob_id, _ = await _register_login(api_client, email="bob2@example.test")
        alice_key = await _publish_key(api_client, alice_token, device_label="alice-laptop")
        conv_id = await _create_direct(api_client, alice_token, peer_id=bob_id)

        max_bytes = get_settings().max_file_upload_size_mb * 1024 * 1024
        resp = await _upload(
            api_client,
            alice_token,
            conversation_id=conv_id,
            identity_key_id=alice_key,
            payload=b"tiny",
            declared_size=max_bytes + 1,
        )
        assert resp.status_code == 413, resp.text
        assert resp.json()["error_code"] == "file_too_large"

    async def test_non_participant_cannot_download(self, api_client: TestApp) -> None:
        alice_id, alice_token = await _register_login(api_client, email="alice3@example.test")
        bob_id, _ = await _register_login(api_client, email="bob3@example.test")
        _, mallory_token = await _register_login(api_client, email="mallory3@example.test")
        alice_key = await _publish_key(api_client, alice_token, device_label="alice-laptop")
        conv_id = await _create_direct(api_client, alice_token, peer_id=bob_id)

        upload_resp = await _upload(
            api_client,
            alice_token,
            conversation_id=conv_id,
            identity_key_id=alice_key,
            payload=b"secret",
        )
        assert upload_resp.status_code == 201, upload_resp.text
        file_id = upload_resp.json()["file_attachment_id"]

        download = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/files/{file_id}", headers=_headers(mallory_token)
        )
        assert download.status_code == 403, download.text
        assert download.json()["error_code"] == "not_participant"

    async def test_file_appears_in_message_timeline(self, api_client: TestApp) -> None:
        alice_id, alice_token = await _register_login(api_client, email="alice4@example.test")
        bob_id, bob_token = await _register_login(api_client, email="bob4@example.test")
        alice_key = await _publish_key(api_client, alice_token, device_label="alice-laptop")
        conv_id = await _create_direct(api_client, alice_token, peer_id=bob_id)

        upload_resp = await _upload(
            api_client,
            alice_token,
            conversation_id=conv_id,
            identity_key_id=alice_key,
            payload=b"hello-file",
        )
        assert upload_resp.status_code == 201, upload_resp.text
        message_id = upload_resp.json()["message_id"]
        file_id = upload_resp.json()["file_attachment_id"]

        history = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/messages", headers=_headers(bob_token)
        )
        assert history.status_code == 200, history.text
        messages = history.json()["messages"]
        assert len(messages) == 1
        assert messages[0]["id"] == message_id
        assert messages[0]["envelope"]["kind"] == "file"
        assert messages[0]["envelope"]["file_attachment_id"] == file_id

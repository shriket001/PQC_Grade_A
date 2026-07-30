"""US2 messaging backend tests — identity key directory, rotation, conversations,
opaque message send/list, and participant authorization (T048–T050, T051a).

These exercise the real ML-DSA-65 / ML-KEM-768 providers (liboqs) end-to-end
through the HTTP layer: keypairs are generated with the `IdentityKeyProvider`
interface, the rotation attestation is a real signature over the new public
material, and ciphertext/envelope are fabricated as opaque blobs (the backend
never inspects them — FR-051/SC-002).
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


def _envelope() -> dict[str, object]:
    # Opaque envelope; only the structural fields matter to the backend.
    return {"alg": "aes-256-gcm", "nonce": _b64(b"\x00" * 12), "version": 1}


async def _register_login(api: TestApp, *, email: str) -> tuple[str, str]:
    """Register, verify, login. Returns (user_id, access_token)."""
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
    """Publish a fresh identity key; return the published key id."""
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
class TestIdentityKeyDirectory:
    async def test_publish_then_list_active(self, api_client: TestApp) -> None:
        alice_id, alice_token = await _register_login(api_client, email="alice@example.test")
        provider = get_identity_key_provider()
        signing_pub, _ = provider.generate_keypair()
        kem_pub, _ = provider.generate_keypair()

        resp = await api_client.client.post(
            "/api/v1/users/me/identity-keys",
            json={
                "device_label": "alice-laptop",
                "public_signing_key": _b64(signing_pub),
                "public_kem_key": _b64(kem_pub),
            },
            headers=_headers(alice_token),
        )
        assert resp.status_code == 201, resp.text
        published = resp.json()
        assert published["key_version"] == 1
        assert published["superseded_at"] is None

        # A second user can look up Alice's active public keys (directory).
        _, bob_token = await _register_login(api_client, email="bob@example.test")
        listing = await api_client.client.get(
            f"/api/v1/users/{alice_id}/identity-keys", headers=_headers(bob_token)
        )
        assert listing.status_code == 200, listing.text
        keys = listing.json()
        assert len(keys) == 1
        assert keys[0]["public_signing_key"] == _b64(signing_pub)

    async def test_publish_requires_auth(self, api_client: TestApp) -> None:
        provider = get_identity_key_provider()
        signing_pub, _ = provider.generate_keypair()
        kem_pub, _ = provider.generate_keypair()
        resp = await api_client.client.post(
            "/api/v1/users/me/identity-keys",
            json={
                "device_label": "anon",
                "public_signing_key": _b64(signing_pub),
                "public_kem_key": _b64(kem_pub),
            },
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_code"] == "unauthenticated"


@pytest.mark.asyncio
class TestIdentityKeyRotation:
    async def test_valid_rotation_supersedes_and_increments_version(
        self, api_client: TestApp
    ) -> None:
        _, token = await _register_login(api_client, email="rotator@example.test")
        provider = get_identity_key_provider()

        old_signing_pub, old_signing_priv = provider.generate_keypair()
        old_kem_pub, _ = provider.generate_keypair()
        pub = await api_client.client.post(
            "/api/v1/users/me/identity-keys",
            json={
                "device_label": "device-1",
                "public_signing_key": _b64(old_signing_pub),
                "public_kem_key": _b64(old_kem_pub),
            },
            headers=_headers(token),
        )
        assert pub.status_code == 201

        new_signing_pub, _ = provider.generate_keypair()
        new_kem_pub, _ = provider.generate_keypair()
        attestation = provider.sign(old_signing_priv, new_signing_pub + new_kem_pub)

        rot = await api_client.client.post(
            "/api/v1/users/me/identity-keys/rotate",
            json={
                "new_public_signing_key": _b64(new_signing_pub),
                "new_public_kem_key": _b64(new_kem_pub),
                "rotation_attestation": _b64(attestation),
            },
            headers=_headers(token),
        )
        assert rot.status_code == 200, rot.text
        rotated = rot.json()
        assert rotated["key_version"] == 2
        assert rotated["public_signing_key"] == _b64(new_signing_pub)
        assert rotated["superseded_at"] is None

        # The old key is superseded; the active directory shows only v2.
        listing = await api_client.client.get(
            f"/api/v1/users/{rotated['user_id']}/identity-keys", headers=_headers(token)
        )
        assert [k["key_version"] for k in listing.json()] == [2]

    async def test_invalid_attestation_rejected(self, api_client: TestApp) -> None:
        _, token = await _register_login(api_client, email="badrot@example.test")
        provider = get_identity_key_provider()

        old_signing_pub, _ = provider.generate_keypair()
        old_kem_pub, _ = provider.generate_keypair()
        await api_client.client.post(
            "/api/v1/users/me/identity-keys",
            json={
                "device_label": "device-1",
                "public_signing_key": _b64(old_signing_pub),
                "public_kem_key": _b64(old_kem_pub),
            },
            headers=_headers(token),
        )

        new_signing_pub, _ = provider.generate_keypair()
        new_kem_pub, _ = provider.generate_keypair()
        # Attestation signed by an unrelated private key — must be rejected.
        _, stranger_priv = provider.generate_keypair()
        bad_attestation = provider.sign(stranger_priv, new_signing_pub + new_kem_pub)

        rot = await api_client.client.post(
            "/api/v1/users/me/identity-keys/rotate",
            json={
                "new_public_signing_key": _b64(new_signing_pub),
                "new_public_kem_key": _b64(new_kem_pub),
                "rotation_attestation": _b64(bad_attestation),
            },
            headers=_headers(token),
        )
        assert rot.status_code == 400, rot.text
        assert rot.json()["error_code"] == "invalid_rotation_attestation"


@pytest.mark.asyncio
class TestConversations:
    async def test_create_direct_conversation_visible_to_both(self, api_client: TestApp) -> None:
        alice_id, alice = await _register_login(api_client, email="conv-alice@example.test")
        bob_id, bob = await _register_login(api_client, email="conv-bob@example.test")

        resp = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["type"] == "direct"
        participant_ids = {p["user_id"] for p in body["participants"]}
        assert participant_ids == {str(alice_id), str(bob_id)}

        for tok in (alice, bob):
            listing = await api_client.client.get("/api/v1/conversations", headers=_headers(tok))
            assert listing.status_code == 200
            assert any(c["id"] == body["id"] for c in listing.json())

    async def test_participants_carry_username(self, api_client: TestApp) -> None:
        """The conversation response includes each participant's public username
        (joined server-side) so the client renders labels without a per-peer
        `GET /users/{id}` round-trip — no truncated-id flash on refresh."""
        alice_id, alice = await _register_login(api_client, email="uname-alice@example.test")
        bob_id, bob = await _register_login(api_client, email="uname-bob@example.test")

        resp = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        assert resp.status_code == 201, resp.text
        participants = resp.json()["participants"]
        by_id = {p["user_id"]: p for p in participants}
        assert by_id[str(alice_id)]["username"] == username_from_email("uname-alice@example.test")
        assert by_id[str(bob_id)]["username"] == username_from_email("uname-bob@example.test")
        # display_name defaults to the username at registration.
        assert by_id[str(bob_id)]["display_name"] == username_from_email("uname-bob@example.test")

        # The list endpoint carries the same joined names.
        listing = await api_client.client.get("/api/v1/conversations", headers=_headers(bob))
        conv = next(c for c in listing.json() if c["id"] == resp.json()["id"])
        listed = {p["user_id"]: p for p in conv["participants"]}
        assert listed[str(alice_id)]["username"] == username_from_email("uname-alice@example.test")

    async def test_self_conversation_rejected(self, api_client: TestApp) -> None:
        alice_id, alice = await _register_login(api_client, email="self-alice@example.test")
        resp = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(alice_id)]},
            headers=_headers(alice),
        )
        assert resp.status_code == 400, resp.text
        assert resp.json()["error_code"] == "invalid_conversation_request"


@pytest.mark.asyncio
class TestConversationDelete:
    """Delete a direct conversation is a hard delete: the conversation row,
    both participants' memberships, and every message are removed (cascade).
    Group conversations still use the per-user soft delete (leave) — FR-055.
    """

    async def test_delete_direct_removes_for_both_participants_and_erases_history(
        self, api_client: TestApp
    ) -> None:
        _, alice = await _register_login(api_client, email="del-alice@example.test")
        bob_id, bob = await _register_login(api_client, email="del-bob@example.test")
        alice_key_id = await _publish_key(api_client, alice, device_label="alice-dev")
        create = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        conv_id = create.json()["id"]

        # Seed a message so there is ciphertext history to verify is erased.
        send = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/messages",
            json={
                "ciphertext": _b64(b"opaque"),
                "envelope": _envelope(),
                "sender_identity_key_id": str(alice_key_id),
            },
            headers=_headers(alice),
        )
        assert send.status_code == 201

        deleted = await api_client.client.delete(
            f"/api/v1/conversations/{conv_id}", headers=_headers(alice)
        )
        assert deleted.status_code == 204, deleted.text

        # It drops from both participants' lists — this is a hard delete, not
        # a per-user leave.
        alice_list = await api_client.client.get("/api/v1/conversations", headers=_headers(alice))
        assert all(c["id"] != conv_id for c in alice_list.json())
        bob_list = await api_client.client.get("/api/v1/conversations", headers=_headers(bob))
        assert all(c["id"] != conv_id for c in bob_list.json())

        # Neither participant can list its (now-gone) messages.
        bob_msgs = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/messages", headers=_headers(bob)
        )
        assert bob_msgs.status_code == 403
        alice_msgs = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/messages", headers=_headers(alice)
        )
        assert alice_msgs.status_code == 403

    async def test_peer_message_after_delete_starts_a_new_conversation(
        self, api_client: TestApp
    ) -> None:
        alice_id, alice = await _register_login(api_client, email="react-alice@example.test")
        bob_id, bob = await _register_login(api_client, email="react-bob@example.test")
        bob_key_id = await _publish_key(api_client, bob, device_label="bob-dev")
        create = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        conv_id = create.json()["id"]

        deleted = await api_client.client.delete(
            f"/api/v1/conversations/{conv_id}", headers=_headers(alice)
        )
        assert deleted.status_code == 204

        # Bob can no longer send into the deleted conversation id...
        bob_send = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/messages",
            json={
                "ciphertext": _b64(b"from-bob"),
                "envelope": _envelope(),
                "sender_identity_key_id": str(bob_key_id),
            },
            headers=_headers(bob),
        )
        assert bob_send.status_code == 403

        # ...but starting a fresh direct conversation with Alice gets a brand
        # new id (no stale history), which is how re-adding a deleted contact
        # is expected to work.
        bob_create = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(alice_id)]},
            headers=_headers(bob),
        )
        assert bob_create.status_code == 201, bob_create.text
        assert bob_create.json()["id"] != conv_id

    async def test_non_participant_cannot_leave(self, api_client: TestApp) -> None:
        _, alice = await _register_login(api_client, email="del-np-alice@example.test")
        bob_id, _ = await _register_login(api_client, email="del-np-bob@example.test")
        _, stranger = await _register_login(api_client, email="del-np-stranger@example.test")
        create = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        conv_id = create.json()["id"]

        resp = await api_client.client.delete(
            f"/api/v1/conversations/{conv_id}", headers=_headers(stranger)
        )
        assert resp.status_code == 403, resp.text
        assert resp.json()["error_code"] == "not_participant"
        # The conversation still exists for the real participants.
        listing = await api_client.client.get("/api/v1/conversations", headers=_headers(alice))
        assert any(c["id"] == conv_id for c in listing.json())

    async def test_leave_nonexistent_returns_404(self, api_client: TestApp) -> None:
        _, alice = await _register_login(api_client, email="del-404@example.test")
        resp = await api_client.client.delete(
            "/api/v1/conversations/00000000-0000-0000-0000-000000000000",
            headers=_headers(alice),
        )
        assert resp.status_code == 404, resp.text
        assert resp.json()["error_code"] == "conversation_not_found"


@pytest.mark.asyncio
class TestConversationDedup:
    """Phase 5e: get-or-create-by-peer-pair — FR-056."""

    async def test_starting_same_pair_twice_returns_one_conversation(
        self, api_client: TestApp
    ) -> None:
        _, alice = await _register_login(api_client, email="dedup-alice@example.test")
        bob_id, _ = await _register_login(api_client, email="dedup-bob@example.test")

        first = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        assert first.status_code == 201, first.text
        second = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        # Get-or-create: the same conversation is returned, not a duplicate.
        assert second.status_code == 201, second.text
        assert second.json()["id"] == first.json()["id"]

        listing = await api_client.client.get("/api/v1/conversations", headers=_headers(alice))
        ids = [c["id"] for c in listing.json()]
        assert ids.count(first.json()["id"]) == 1

    async def test_restarting_after_delete_creates_a_new_conversation(
        self, api_client: TestApp
    ) -> None:
        _, alice = await _register_login(api_client, email="restart-alice@example.test")
        bob_id, _ = await _register_login(api_client, email="restart-bob@example.test")
        create = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        conv_id = create.json()["id"]

        # Alice deletes (hard-delete), then re-starts with Bob — a brand-new
        # conversation id, not a reactivation of the deleted one, so no stale
        # history/keys carry over.
        await api_client.client.delete(f"/api/v1/conversations/{conv_id}", headers=_headers(alice))
        before = await api_client.client.get("/api/v1/conversations", headers=_headers(alice))
        assert all(c["id"] != conv_id for c in before.json())

        restarted = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        assert restarted.status_code == 201, restarted.text
        assert restarted.json()["id"] != conv_id
        after = await api_client.client.get("/api/v1/conversations", headers=_headers(alice))
        assert any(c["id"] == restarted.json()["id"] for c in after.json())


@pytest.mark.asyncio
class TestConversationListOrdering:
    """Phase 5e: list ordered by last_message_at desc (newest first) — FR-058."""

    async def test_conversation_with_latest_message_sorts_first(self, api_client: TestApp) -> None:
        _, alice = await _register_login(api_client, email="ord-alice@example.test")
        bob_id, _ = await _register_login(api_client, email="ord-bob@example.test")
        carol_id, _ = await _register_login(api_client, email="ord-carol@example.test")
        alice_key_id = await _publish_key(api_client, alice, device_label="alice-dev")

        # Two direct conversations: create the bob-conv first, carol-conv second.
        bob_conv = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        carol_conv = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(carol_id)]},
            headers=_headers(alice),
        )
        bob_conv_id = bob_conv.json()["id"]
        carol_conv_id = carol_conv.json()["id"]

        # Send a message into the BOB conversation AFTER carol-conv was created.
        # Its last_message_at becomes the newest, so it must sort first despite
        # being created earlier.
        send = await api_client.client.post(
            f"/api/v1/conversations/{bob_conv_id}/messages",
            json={
                "ciphertext": _b64(b"hi-bob"),
                "envelope": _envelope(),
                "sender_identity_key_id": str(alice_key_id),
            },
            headers=_headers(alice),
        )
        assert send.status_code == 201

        listing = await api_client.client.get("/api/v1/conversations", headers=_headers(alice))
        body = listing.json()
        ids = [c["id"] for c in body]
        assert ids[0] == bob_conv_id  # newest activity first
        # The bob conversation carries last_message_at; carol's is null.
        bob_entry = next(c for c in body if c["id"] == bob_conv_id)
        carol_entry = next(c for c in body if c["id"] == carol_conv_id)
        assert bob_entry["last_message_at"] is not None
        assert carol_entry["last_message_at"] is None


@pytest.mark.asyncio
class TestMessages:
    async def _two_party_setup(self, api_client: TestApp) -> tuple[str, str, str, str, str, str]:
        """Returns (alice_id, alice_token, bob_token, conversation_id, alice_key_id, bob_id)."""
        alice_id, alice = await _register_login(api_client, email="msg-alice@example.test")
        bob_id, bob = await _register_login(api_client, email="msg-bob@example.test")
        alice_key_id = await _publish_key(api_client, alice, device_label="alice-dev")
        resp = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        conv_id = resp.json()["id"]
        return alice_id, alice, bob, conv_id, alice_key_id, bob_id

    async def test_send_and_list_message(self, api_client: TestApp) -> None:
        alice_id, alice, bob, conv_id, alice_key_id, _ = await self._two_party_setup(api_client)

        send = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/messages",
            json={
                "ciphertext": _b64(b"opaque-ciphertext-bytes"),
                "envelope": _envelope(),
                "sender_identity_key_id": str(alice_key_id),
            },
            headers=_headers(alice),
        )
        assert send.status_code == 201, send.text
        msg = send.json()
        assert msg["sender_id"] == str(alice_id)
        assert msg["ciphertext"] == _b64(b"opaque-ciphertext-bytes")

        # Both participants can list; the ciphertext/envelope round-trip opaquely.
        listing = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/messages", headers=_headers(bob)
        )
        assert listing.status_code == 200, listing.text
        body = listing.json()
        assert len(body["messages"]) == 1
        assert body["messages"][0]["ciphertext"] == _b64(b"opaque-ciphertext-bytes")

    async def test_non_participant_cannot_list_or_send(self, api_client: TestApp) -> None:
        _, alice, _, conv_id, _, _ = await self._two_party_setup(api_client)
        _, stranger = await _register_login(api_client, email="stranger@example.test")

        listing = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/messages", headers=_headers(stranger)
        )
        assert listing.status_code == 403
        assert listing.json()["error_code"] == "not_participant"

        send = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/messages",
            json={
                "ciphertext": _b64(b"x"),
                "envelope": _envelope(),
                # Stranger publishes their own key and tries to send under it;
                # the participant check rejects them before key ownership matters.
                "sender_identity_key_id": await _publish_key(
                    api_client, stranger, device_label="stranger-dev"
                ),
            },
            headers=_headers(stranger),
        )
        assert send.status_code == 403
        assert send.json()["error_code"] == "not_participant"

    async def test_send_under_someone_elses_key_rejected(self, api_client: TestApp) -> None:
        _, alice, bob, conv_id, _, _ = await self._two_party_setup(api_client)
        # Bob's key belongs to Bob, not Alice — Alice cannot send under it.
        bob_key_id = await _publish_key(api_client, bob, device_label="bob-dev")
        send = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/messages",
            json={
                "ciphertext": _b64(b"y"),
                "envelope": _envelope(),
                "sender_identity_key_id": str(bob_key_id),
            },
            headers=_headers(alice),
        )
        assert send.status_code == 400, send.text
        assert send.json()["error_code"] == "invalid_identity_key"

    async def test_cursor_pagination(self, api_client: TestApp) -> None:
        _, alice, bob, conv_id, alice_key_id, _ = await self._two_party_setup(api_client)
        # Send 3 messages.
        for _ in range(3):
            r = await api_client.client.post(
                f"/api/v1/conversations/{conv_id}/messages",
                json={
                    "ciphertext": _b64(b"m"),
                    "envelope": _envelope(),
                    "sender_identity_key_id": str(alice_key_id),
                },
                headers=_headers(alice),
            )
            assert r.status_code == 201

        # Page size 2 → first page has 2 newest, with a next_cursor.
        page1 = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/messages?limit=2", headers=_headers(bob)
        )
        assert page1.status_code == 200
        body1 = page1.json()
        assert len(body1["messages"]) == 2
        assert body1["next_cursor"] is not None

        page2 = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/messages?limit=2&before={body1['next_cursor']}",
            headers=_headers(bob),
        )
        assert page2.status_code == 200
        body2 = page2.json()
        assert len(body2["messages"]) == 1
        # Combined, no duplicate ids across the two pages.
        all_ids = [m["id"] for m in body1["messages"]] + [m["id"] for m in body2["messages"]]
        assert len(set(all_ids)) == 3


@pytest.mark.asyncio
class TestConversationKeyBackup:
    """Password-recoverable per-conversation message key backup: extends
    FR-054's identity-key recovery to the 1:1 conversation symmetric key. The
    server never sees plaintext — only opaque wrapped bytes it stores/relays.
    """

    async def _direct_conversation(self, api_client: TestApp) -> tuple[str, str, str, str]:
        """Returns (alice_id, alice_token, bob_token, conversation_id)."""
        alice_id, alice = await _register_login(api_client, email="kb-alice@example.test")
        bob_id, bob = await _register_login(api_client, email="kb-bob@example.test")
        create = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        return alice_id, alice, bob, create.json()["id"]

    async def test_put_then_get_round_trips_opaque_blob(self, api_client: TestApp) -> None:
        _, alice, _, conv_id = await self._direct_conversation(api_client)

        put = await api_client.client.put(
            f"/api/v1/conversations/{conv_id}/key-backup",
            json={
                "wrapped_key": _b64(b"opaque-wrapped-message-key"),
                "wrap_nonce": _b64(b"\x00" * 12),
                "wrap_kdf_salt": _b64(b"\x01" * 16),
                "wrap_kdf_params": "argon2id:t=3:m=65536:p=4",
                "wrap_alg": "aes-256-gcm",
            },
            headers=_headers(alice),
        )
        assert put.status_code == 200, put.text
        assert put.json()["wrapped_key"] == _b64(b"opaque-wrapped-message-key")

        get = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/key-backup", headers=_headers(alice)
        )
        assert get.status_code == 200, get.text
        body = get.json()
        assert body["wrapped_key"] == _b64(b"opaque-wrapped-message-key")
        assert body["wrap_kdf_params"] == "argon2id:t=3:m=65536:p=4"

    async def test_put_again_overwrites_prior_backup(self, api_client: TestApp) -> None:
        _, alice, _, conv_id = await self._direct_conversation(api_client)
        body = {
            "wrapped_key": _b64(b"first"),
            "wrap_nonce": _b64(b"\x00" * 12),
            "wrap_kdf_salt": _b64(b"\x01" * 16),
            "wrap_kdf_params": "argon2id:t=3:m=65536:p=4",
            "wrap_alg": "aes-256-gcm",
        }
        await api_client.client.put(
            f"/api/v1/conversations/{conv_id}/key-backup", json=body, headers=_headers(alice)
        )
        body["wrapped_key"] = _b64(b"second")
        put2 = await api_client.client.put(
            f"/api/v1/conversations/{conv_id}/key-backup", json=body, headers=_headers(alice)
        )
        assert put2.status_code == 200, put2.text

        get = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/key-backup", headers=_headers(alice)
        )
        assert get.json()["wrapped_key"] == _b64(b"second")

    async def test_each_participant_has_an_independent_backup(self, api_client: TestApp) -> None:
        _, alice, bob, conv_id = await self._direct_conversation(api_client)
        body = {
            "wrapped_key": _b64(b"alices-view"),
            "wrap_nonce": _b64(b"\x00" * 12),
            "wrap_kdf_salt": _b64(b"\x01" * 16),
            "wrap_kdf_params": "argon2id:t=3:m=65536:p=4",
            "wrap_alg": "aes-256-gcm",
        }
        await api_client.client.put(
            f"/api/v1/conversations/{conv_id}/key-backup", json=body, headers=_headers(alice)
        )

        # Bob has never pushed a backup for this conversation — 404, not
        # Alice's blob.
        bob_get = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/key-backup", headers=_headers(bob)
        )
        assert bob_get.status_code == 404

    async def test_non_participant_cannot_put_or_get(self, api_client: TestApp) -> None:
        _, alice, _, conv_id = await self._direct_conversation(api_client)
        _, stranger = await _register_login(api_client, email="kb-stranger@example.test")

        put = await api_client.client.put(
            f"/api/v1/conversations/{conv_id}/key-backup",
            json={
                "wrapped_key": _b64(b"x"),
                "wrap_nonce": _b64(b"\x00" * 12),
                "wrap_kdf_salt": _b64(b"\x01" * 16),
                "wrap_kdf_params": "argon2id:t=3:m=65536:p=4",
                "wrap_alg": "aes-256-gcm",
            },
            headers=_headers(stranger),
        )
        assert put.status_code == 403
        assert put.json()["error_code"] == "not_participant"

        get = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/key-backup", headers=_headers(stranger)
        )
        assert get.status_code == 403

    async def test_backup_does_not_survive_conversation_hard_delete(
        self, api_client: TestApp
    ) -> None:
        _, alice, _, conv_id = await self._direct_conversation(api_client)
        await api_client.client.put(
            f"/api/v1/conversations/{conv_id}/key-backup",
            json={
                "wrapped_key": _b64(b"gone-with-the-conversation"),
                "wrap_nonce": _b64(b"\x00" * 12),
                "wrap_kdf_salt": _b64(b"\x01" * 16),
                "wrap_kdf_params": "argon2id:t=3:m=65536:p=4",
                "wrap_alg": "aes-256-gcm",
            },
            headers=_headers(alice),
        )
        deleted = await api_client.client.delete(
            f"/api/v1/conversations/{conv_id}", headers=_headers(alice)
        )
        assert deleted.status_code == 204

        get = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/key-backup", headers=_headers(alice)
        )
        assert get.status_code == 404  # the conversation itself is gone (hard delete)


@pytest.mark.asyncio
class TestGroupMessaging:
    """US3 (Phase 5, T063/T064) — group creation, add/remove participants,
    message visibility bounded by active membership (FR-024/025/026/028)."""

    async def _create_group(
        self, api: TestApp, admin_token: str, member_ids: list[str], name: str = "Test Group"
    ) -> str:
        resp = await api.client.post(
            "/api/v1/conversations",
            json={"type": "group", "participant_user_ids": member_ids, "name": name},
            headers=_headers(admin_token),
        )
        assert resp.status_code == 201, resp.text
        return resp.json()["id"]

    async def test_create_group_all_members_can_send_and_read(self, api_client: TestApp) -> None:
        alice_id, alice = await _register_login(api_client, email="grp-alice@example.test")
        bob_id, bob = await _register_login(api_client, email="grp-bob@example.test")
        carol_id, carol = await _register_login(api_client, email="grp-carol@example.test")

        conv_id = await self._create_group(api_client, alice, [str(bob_id), str(carol_id)])
        alice_key = await _publish_key(api_client, alice, device_label="alice-dev")

        created = await api_client.client.get("/api/v1/conversations", headers=_headers(alice))
        group = next(c for c in created.json() if c["id"] == conv_id)
        assert group["type"] == "group"
        assert group["name"] == "Test Group"
        roles = {p["user_id"]: p["role"] for p in group["participants"]}
        assert roles[str(alice_id)] == "group_admin"
        assert roles[str(bob_id)] == "member"
        assert roles[str(carol_id)] == "member"

        send = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/messages",
            json={
                "ciphertext": _b64(b"hello group"),
                "envelope": _envelope(),
                "sender_identity_key_id": str(alice_key),
            },
            headers=_headers(alice),
        )
        assert send.status_code == 201, send.text

        # Every member (including non-senders) can list the group's messages.
        for tok in (bob, carol):
            listing = await api_client.client.get(
                f"/api/v1/conversations/{conv_id}/messages", headers=_headers(tok)
            )
            assert listing.status_code == 200
            assert len(listing.json()["messages"]) == 1

    async def test_self_only_group_rejected(self, api_client: TestApp) -> None:
        _, alice = await _register_login(api_client, email="grp-solo@example.test")
        resp = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "group", "participant_user_ids": [], "name": "Solo"},
            headers=_headers(alice),
        )
        # Empty participant list fails schema validation (min_length=1) before
        # the service-layer "at least one other participant" check ever runs.
        assert resp.status_code == 422, resp.text

    async def test_group_requires_name(self, api_client: TestApp) -> None:
        alice_id, alice = await _register_login(api_client, email="grp-noname-a@example.test")
        bob_id, _ = await _register_login(api_client, email="grp-noname-b@example.test")
        resp = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "group", "participant_user_ids": [str(bob_id)], "name": None},
            headers=_headers(alice),
        )
        assert resp.status_code == 422, resp.text

    async def test_non_admin_cannot_add_participant(self, api_client: TestApp) -> None:
        alice_id, alice = await _register_login(api_client, email="grp-perm-a@example.test")
        bob_id, bob = await _register_login(api_client, email="grp-perm-b@example.test")
        dave_id, _ = await _register_login(api_client, email="grp-perm-d@example.test")
        conv_id = await self._create_group(api_client, alice, [str(bob_id)])

        resp = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/participants",
            json={"user_id": str(dave_id)},
            headers=_headers(bob),  # bob is a member, not the admin
        )
        assert resp.status_code == 403, resp.text
        assert resp.json()["error_code"] == "not_group_admin"

    async def test_admin_adds_member_who_can_then_read_and_send(self, api_client: TestApp) -> None:
        alice_id, alice = await _register_login(api_client, email="grp-add-a@example.test")
        bob_id, bob = await _register_login(api_client, email="grp-add-b@example.test")
        dave_id, dave = await _register_login(api_client, email="grp-add-d@example.test")
        conv_id = await self._create_group(api_client, alice, [str(bob_id)])

        add = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/participants",
            json={"user_id": str(dave_id)},
            headers=_headers(alice),
        )
        assert add.status_code == 201, add.text
        assert add.json()["role"] == "member"

        dave_key = await _publish_key(api_client, dave, device_label="dave-dev")
        send = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/messages",
            json={
                "ciphertext": _b64(b"hi from dave"),
                "envelope": _envelope(),
                "sender_identity_key_id": str(dave_key),
            },
            headers=_headers(dave),
        )
        assert send.status_code == 201, send.text

    async def test_removed_member_loses_server_side_access(self, api_client: TestApp) -> None:
        """FR-028 (server-side half): once removed, the member is no longer an
        active participant and MessagingService rejects them like any other
        non-participant. The crypto-level guarantee (they never receive the
        next group-key epoch) is exercised by the frontend groupKeyManager
        tests — the server cannot verify decryptability of content it never
        holds the key to (FR-051)."""
        alice_id, alice = await _register_login(api_client, email="grp-rm-a@example.test")
        bob_id, bob = await _register_login(api_client, email="grp-rm-b@example.test")
        conv_id = await self._create_group(api_client, alice, [str(bob_id)])

        remove = await api_client.client.delete(
            f"/api/v1/conversations/{conv_id}/participants/{bob_id}",
            headers=_headers(alice),
        )
        assert remove.status_code == 204, remove.text

        # Bob can no longer read the group's messages at all (server-side
        # membership check — a strict superset of FR-028's requirement).
        listing = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/messages", headers=_headers(bob)
        )
        assert listing.status_code == 403, listing.text
        assert listing.json()["error_code"] == "not_participant"

        # Alice (still admin) can re-add Bob; his membership reactivates.
        readd = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/participants",
            json={"user_id": str(bob_id)},
            headers=_headers(alice),
        )
        assert readd.status_code == 201, readd.text
        listing2 = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/messages", headers=_headers(bob)
        )
        assert listing2.status_code == 200, listing2.text

    async def test_member_can_remove_self(self, api_client: TestApp) -> None:
        alice_id, alice = await _register_login(api_client, email="grp-leave-a@example.test")
        bob_id, bob = await _register_login(api_client, email="grp-leave-b@example.test")
        conv_id = await self._create_group(api_client, alice, [str(bob_id)])

        leave = await api_client.client.delete(
            f"/api/v1/conversations/{conv_id}/participants/{bob_id}",
            headers=_headers(bob),  # bob removes himself
        )
        assert leave.status_code == 204, leave.text

    async def test_re_adding_active_member_rejected(self, api_client: TestApp) -> None:
        alice_id, alice = await _register_login(api_client, email="grp-dup-a@example.test")
        bob_id, _ = await _register_login(api_client, email="grp-dup-b@example.test")
        conv_id = await self._create_group(api_client, alice, [str(bob_id)])

        dup = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/participants",
            json={"user_id": str(bob_id)},
            headers=_headers(alice),
        )
        assert dup.status_code == 409, dup.text
        assert dup.json()["error_code"] == "participant_already_active"

    async def test_participant_management_rejected_on_direct_conversation(
        self, api_client: TestApp
    ) -> None:
        alice_id, alice = await _register_login(api_client, email="grp-direct-a@example.test")
        bob_id, bob = await _register_login(api_client, email="grp-direct-b@example.test")
        direct = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [str(bob_id)]},
            headers=_headers(alice),
        )
        conv_id = direct.json()["id"]

        dave_id = "00000000-0000-0000-0000-000000000000"
        resp = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/participants",
            json={"user_id": dave_id},
            headers=_headers(alice),
        )
        assert resp.status_code == 400, resp.text
        assert resp.json()["error_code"] == "conversation_type_mismatch"

    async def test_sending_after_removal_does_not_silently_reactivate_group_member(
        self, api_client: TestApp
    ) -> None:
        """Regression: `MessagingService.send`'s "reactivate a left recipient"
        behavior exists for direct conversations (FR-055/FR-057 — a peer
        messaging a chat you left brings it back). It MUST NOT also apply to
        groups, where removal is an explicit admin action (FR-024/FR-028) that
        a subsequent message — including the key-distribution message the
        remover sends right after removing someone — must not silently undo."""
        alice_id, alice = await _register_login(api_client, email="grp-noreact-a@example.test")
        bob_id, bob = await _register_login(api_client, email="grp-noreact-b@example.test")
        conv_id = await self._create_group(api_client, alice, [str(bob_id)])
        alice_key = await _publish_key(api_client, alice, device_label="alice-dev")

        remove = await api_client.client.delete(
            f"/api/v1/conversations/{conv_id}/participants/{bob_id}",
            headers=_headers(alice),
        )
        assert remove.status_code == 204, remove.text

        # Alice sends a message immediately after removing bob (as the
        # frontend's key-distribution flow does).
        send = await api_client.client.post(
            f"/api/v1/conversations/{conv_id}/messages",
            json={
                "ciphertext": _b64(b"post-removal message"),
                "envelope": _envelope(),
                "sender_identity_key_id": str(alice_key),
            },
            headers=_headers(alice),
        )
        assert send.status_code == 201, send.text

        # Bob is still removed — the send did NOT reactivate him.
        listing = await api_client.client.get(
            f"/api/v1/conversations/{conv_id}/messages", headers=_headers(bob)
        )
        assert listing.status_code == 403, listing.text
        assert listing.json()["error_code"] == "not_participant"

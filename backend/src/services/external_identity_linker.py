"""Shared account-linking logic for external identity providers (FR-010/FR-011
inbound directions) — composed by BOTH `OidcService` and `SamlService` so the
same behavior (and the same fix, if one is ever needed) applies identically to
both protocols, rather than two copies that can silently drift apart.

Account-linking rule (no existing spec guidance for this edge case, so
documented here): match first by `(protocol, issuer, subject)` — the stable,
un-spoofable identity. If unseen, look up by email:
  - No existing account with that email -> create a brand-new one,
    auto-verified (the external IdP already verified it) with an unusable
    password hash — that account can only ever sign in via this SSO flow.
  - An existing account with that email, and the IdP reports it verified ->
    link to it (the common "I already registered with a password, now I'm
    using SSO with the same address" case).
  - An existing account with that email, but the IdP does NOT report it
    verified -> refuse (`ExternalIdentityConflictError`) rather than either
    silently linking on an unverified claim (spoofing risk) or creating a
    second account with the same email (impossible anyway — email is
    globally unique in this schema).
"""

import re
import secrets
from dataclasses import dataclass

from src.crypto.interfaces import PasswordHasher
from src.models.external_identity_link import ExternalIdentityLink, ExternalIdentityProtocol
from src.models.user import User
from src.repositories.external_identity_link_repository import ExternalIdentityLinkRepository
from src.repositories.user_repository import UserRepository
from src.services.errors import ExternalIdentityConflictError

_MAX_USERNAME_LOCAL_PART = 28  # leaves room for a numeric disambiguation suffix, capped at 32


@dataclass(frozen=True)
class ExternalProfile:
    """Verified claims about the user, protocol-agnostic — OIDC's userinfo
    claims and SAML's assertion attributes both normalize down to this same
    shape before reaching the linker."""

    issuer: str
    subject: str
    email: str
    email_verified: bool
    name: str | None


class ExternalIdentityLinker:
    def __init__(
        self,
        *,
        user_repo: UserRepository,
        link_repo: ExternalIdentityLinkRepository,
        password_hasher: PasswordHasher,
    ) -> None:
        self._user_repo = user_repo
        self._link_repo = link_repo
        self._password_hasher = password_hasher

    async def _unique_username_from_email(self, email: str) -> str:
        local_part = email.split("@", 1)[0].lower()
        base = re.sub(r"[^a-z0-9_]", "_", local_part)[:_MAX_USERNAME_LOCAL_PART] or "user"
        base = base.ljust(3, "_")  # the username schema requires >= 3 chars
        candidate = base
        suffix = 0
        while await self._user_repo.username_exists(candidate):
            suffix += 1
            candidate = f"{base}{suffix}"[:32]
        return candidate

    async def _create_user_from_profile(self, profile: ExternalProfile) -> User:
        normalized_email = profile.email.lower()
        username = await self._unique_username_from_email(normalized_email)
        # An unusable random password hash — nobody ever chose this password,
        # so /auth/login can never succeed for this account; only the SSO flow
        # that created it can. FR-041 ("password_hash is never a real,
        # guessable secret") holds either way.
        unusable_password_hash = self._password_hasher.hash(secrets.token_urlsafe(32))
        user = User(
            email=normalized_email,
            username=username,
            password_hash=unusable_password_hash,
            display_name=profile.name or username,
            email_verified=True,  # the external IdP already verified it
        )
        await self._user_repo.add(user)
        return user

    async def find_or_create_user(
        self, protocol: ExternalIdentityProtocol, profile: ExternalProfile
    ) -> User:
        link = await self._link_repo.get_by_subject(protocol, profile.issuer, profile.subject)
        if link is not None:
            user = await self._user_repo.get_by_id(link.user_id)
            if user is not None:
                return user
            # Orphaned link (the User row is gone) — fall through and treat
            # this exactly like a first-time sign-in with this identity.

        existing = await self._user_repo.get_by_email(profile.email.lower())
        if existing is not None:
            if not profile.email_verified:
                raise ExternalIdentityConflictError(
                    "an account with this email already exists and the "
                    "identity provider did not verify the email"
                )
            user = existing
        else:
            user = await self._create_user_from_profile(profile)

        await self._link_repo.add(
            ExternalIdentityLink(
                user_id=user.id,
                protocol=protocol,
                provider_identifier=profile.issuer,
                subject=profile.subject,
            )
        )
        return user

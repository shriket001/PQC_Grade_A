"""OIDC Relying-Party client interface (FR-010 inbound direction) + Google's
concrete implementation.

This is a plain external-collaborator interface (same DIP pattern as
`VerificationEmailSender`/`AuditLogger`) — NOT part of the crypto isolation
boundary in `crypto/interfaces.py`, since it does no cryptographic work
itself; it just talks HTTP to an external IdP. Kept behind an interface so
`OidcService` is fully testable with a fake, no network calls or real Google
credentials needed, and so a second provider later is another class here, not
a change to the service or router.
"""

from abc import ABC, abstractmethod
from urllib.parse import urlencode

import httpx

from src.services.external_identity_linker import ExternalProfile

# Re-exported under the OIDC-specific name for readability at call sites and
# backward compatibility — structurally identical to (in fact just an alias
# of) the shared `ExternalProfile` the linker (and SAML) use, so callers can
# use either name interchangeably.
OidcProfile = ExternalProfile


class OidcExchangeError(Exception):
    """The authorization code couldn't be exchanged for a verified profile —
    network failure, the IdP rejected the code, or it returned no usable
    email. `OidcService` maps this to `OAuthExchangeFailedError`."""


class OidcClient(ABC):
    @abstractmethod
    def authorization_url(self, state: str) -> str:
        """Build the URL to redirect the user's browser to at the IdP."""
        ...

    @abstractmethod
    async def exchange_code(self, code: str) -> OidcProfile:
        """Redeem an authorization code for a verified profile."""
        ...


class GoogleOidcClient(OidcClient):
    # Google's OIDC issuer — becomes `ExternalIdentityLink.provider_identifier`.
    ISSUER = "https://accounts.google.com"
    _AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
    _TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
    # Calling userinfo (rather than verifying the id_token's JWT signature
    # ourselves against Google's JWKS) keeps this client dependency-free: the
    # access token came directly from Google's token endpoint over TLS, so
    # trusting what Google's own userinfo endpoint says about it needs no
    # separate signature-verification code path.
    _USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"

    def __init__(self, *, client_id: str, client_secret: str, redirect_uri: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri

    def authorization_url(self, state: str) -> str:
        params = {
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "online",
            "prompt": "select_account",
        }
        return f"{self._AUTHORIZE_ENDPOINT}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> OidcProfile:
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                token_resp = await client.post(
                    self._TOKEN_ENDPOINT,
                    data={
                        "code": code,
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "redirect_uri": self._redirect_uri,
                        "grant_type": "authorization_code",
                    },
                )
                token_resp.raise_for_status()
                access_token = token_resp.json()["access_token"]

                userinfo_resp = await client.get(
                    self._USERINFO_ENDPOINT,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                userinfo_resp.raise_for_status()
                claims = userinfo_resp.json()
            except (httpx.HTTPError, KeyError, ValueError) as err:
                raise OidcExchangeError(
                    "failed to exchange authorization code with Google"
                ) from err

        email = claims.get("email")
        subject = claims.get("sub")
        if not email or not subject:
            raise OidcExchangeError("Google profile did not include an email/subject")

        return OidcProfile(
            issuer=self.ISSUER,
            subject=subject,
            email=email,
            email_verified=bool(claims.get("email_verified", False)),
            name=claims.get("name"),
        )

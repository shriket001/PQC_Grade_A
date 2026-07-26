"""Fail-fast application configuration.

All secrets and environment-dependent values are read here, once, at process
startup. A missing required setting raises immediately rather than allowing
the application to start in a partially-configured, insecure state
(Constitution Principle VI: Fail Fast).
"""

import base64
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve to the repo-root `.env` (backend/src/core/config.py -> repo root is
# three levels up) so settings load correctly regardless of the working
# directory a command is launched from (`backend/`, repo root, a Docker
# container's WORKDIR, etc.) rather than only working when invoked from one
# specific directory.
_REPO_ROOT_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_REPO_ROOT_ENV_FILE, env_file_encoding="utf-8", extra="ignore"
    )

    database_url: str = Field(..., alias="DATABASE_URL")
    redis_url: str = Field(..., alias="REDIS_URL")

    object_storage_endpoint: str = Field(..., alias="OBJECT_STORAGE_ENDPOINT")
    object_storage_bucket: str = Field(..., alias="OBJECT_STORAGE_BUCKET")
    object_storage_access_key: str = Field(..., alias="OBJECT_STORAGE_ACCESS_KEY")
    object_storage_secret_key: str = Field(..., alias="OBJECT_STORAGE_SECRET_KEY")

    jwt_signing_private_key_path: str = Field(..., alias="JWT_SIGNING_PRIVATE_KEY_PATH")
    jwt_signing_public_key_path: str = Field(..., alias="JWT_SIGNING_PUBLIC_KEY_PATH")
    jwt_access_token_ttl_seconds: int = Field(900, alias="JWT_ACCESS_TOKEN_TTL_SECONDS")
    jwt_refresh_token_ttl_seconds: int = Field(2_592_000, alias="JWT_REFRESH_TOKEN_TTL_SECONDS")

    crypto_grade: str = Field(..., alias="CRYPTO_GRADE")

    cors_allowed_origins: str = Field(..., alias="CORS_ALLOWED_ORIGINS")

    # The refresh token travels as an HttpOnly cookie (FR-005/US10), never in a
    # JSON body or localStorage, so it's unreadable to any XSS payload. `Secure`
    # must stay True everywhere the app is reachable over TLS (Docker/prod, per
    # the Constitution's TLS-1.3-only posture) — the escape hatch here exists
    # only for a bare `vite dev` + `uvicorn` loop on plain http://localhost.
    refresh_cookie_secure: bool = Field(True, alias="REFRESH_COOKIE_SECURE")

    rate_limit_login_per_minute: int = Field(5, alias="RATE_LIMIT_LOGIN_PER_MINUTE")
    rate_limit_register_per_minute: int = Field(5, alias="RATE_LIMIT_REGISTER_PER_MINUTE")
    rate_limit_password_reset_per_hour: int = Field(3, alias="RATE_LIMIT_PASSWORD_RESET_PER_HOUR")
    rate_limit_mfa_verify_per_minute: int = Field(5, alias="RATE_LIMIT_MFA_VERIFY_PER_MINUTE")
    # Base64-encoded 32-byte key encrypting each MfaFactor.secret at rest
    # (data-model.md's "secret_encrypted... via the backend crypto module") —
    # a TOTP secret is symmetric and must stay reversible (unlike a password
    # hash), so it needs real encryption, not hashing.
    mfa_secret_encryption_key: str = Field(..., alias="MFA_SECRET_ENCRYPTION_KEY")
    # Username discovery (FR-053) — higher than auth limits since it's a
    # routine lookup, but capped to resist username enumeration abuse.
    rate_limit_user_search_per_minute: int = Field(30, alias="RATE_LIMIT_USER_SEARCH_PER_MINUTE")

    max_file_upload_size_mb: int = Field(50, alias="MAX_FILE_UPLOAD_SIZE_MB")

    smtp_host: str = Field(..., alias="SMTP_HOST")
    smtp_port: int = Field(1025, alias="SMTP_PORT")
    smtp_from_address: str = Field(..., alias="SMTP_FROM_ADDRESS")

    # Base URL of the frontend, used to build links in transactional emails.
    app_base_url: str = Field("http://localhost:5173", alias="APP_BASE_URL")
    # Single-use email-verification token lifetime (FR-002).
    email_verification_token_ttl_seconds: int = Field(
        86_400, alias="EMAIL_VERIFICATION_TOKEN_TTL_SECONDS"
    )

    # --- OIDC Relying Party — Google (FR-010 inbound direction) ---
    # Optional (unlike the settings above): OAuth login is an optional feature,
    # not a hard startup requirement — if unset, `get_oidc_clients()` simply
    # omits "google" from the configured-provider map and
    # /auth/oidc/google/authorize redirects to a friendly frontend error
    # instead of the app failing to start.
    oauth_google_client_id: str | None = Field(default=None, alias="GOOGLE_OAUTH_CLIENT_ID")
    oauth_google_client_secret: str | None = Field(default=None, alias="GOOGLE_OAUTH_CLIENT_SECRET")
    # Must exactly match an "Authorized redirect URI" configured on the Google
    # Cloud OAuth client — Google rejects the callback otherwise.
    oauth_google_redirect_uri: str = Field(
        "http://localhost:8000/api/v1/auth/oidc/google/callback",
        alias="GOOGLE_OAUTH_REDIRECT_URI",
    )

    # --- SAML Relying Party / Service Provider (FR-011 inbound direction) ---
    # Optional, same rationale as the Google settings above: unset means
    # `get_saml_clients()` returns an empty map and /auth/saml/{idp}/authorize
    # redirects to a friendly frontend error instead of failing startup.
    # `saml_idp_name` is the `{idp}` path segment (e.g. "samltest") — arbitrary,
    # just needs to match what the frontend's SSO link points at.
    #
    # UNLIKE Google OAuth, this genuinely REQUIRES real HTTPS
    # (`REFRESH_COOKIE_SECURE=true`, e.g. via docker/certs/dev-https/), not
    # just the `http://localhost` exception. The IdP's SAML response reaches
    # `/acs` via a cross-site POST (the IdP's own page submits the form), and
    # browsers only send a `SameSite=None` cookie — the only kind that
    # survives a cross-site POST — when it's also `Secure`. Over plain http
    # this cookie is silently dropped and every login attempt fails closed
    # with `saml_failed` (safe, just non-functional).
    saml_idp_name: str = Field("samltest", alias="SAML_IDP_NAME")
    # This SP's own identity, presented in outgoing AuthnRequests and in the
    # metadata XML the IdP needs to register it (GET /auth/saml/{idp}/metadata).
    saml_sp_entity_id: str = Field(
        "https://localhost:8000/api/v1/auth/saml/metadata", alias="SAML_SP_ENTITY_ID"
    )
    saml_sp_acs_url: str = Field(
        "https://localhost:8000/api/v1/auth/saml/samltest/acs", alias="SAML_SP_ACS_URL"
    )
    saml_sp_cert_path: str | None = Field(default=None, alias="SAML_SP_CERT_PATH")
    saml_sp_key_path: str | None = Field(default=None, alias="SAML_SP_KEY_PATH")
    # Local XML file with the external IdP's metadata (entity id, SSO URL,
    # signing cert) — e.g. downloaded once from samltest.id. Unset disables
    # SAML entirely (see rationale above).
    saml_idp_metadata_path: str | None = Field(default=None, alias="SAML_IDP_METADATA_PATH")
    # Only needed if the metadata file above describes more than one IdP —
    # otherwise the single one present is used automatically.
    saml_idp_entity_id: str | None = Field(default=None, alias="SAML_IDP_ENTITY_ID")
    # Absolute path to the `xmlsec1`/`xmlsec` CLI binary (the XML Security
    # Library command-line tool). pysaml2 shells out to this native binary for
    # every XML sign/verify operation — it is NOT a Python dependency, so
    # `pip install pysaml2` does NOT provide it. On Linux it's the distro's
    # `xmlsec1` package; on Windows you download the upstream win64 build once
    # (https://github.com/lsh123/xmlsec/releases — the zip bundles xmlsec.exe +
    # its DLL deps) and point this at the consolidated folder's exe. Unset →
    # pysaml2 searches PATH for ['xmlsec.exe', 'xmlsec1.exe'] and raises
    # `SigverError: Cannot find ...` at the first SAML request if none is there.
    saml_xmlsec_binary_path: str | None = Field(default=None, alias="SAML_XMLSEC_BINARY_PATH")

    @property
    def cors_allowed_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

    @property
    def mfa_secret_encryption_key_bytes(self) -> bytes:
        key = base64.b64decode(self.mfa_secret_encryption_key)
        if len(key) != 32:
            raise ValueError("MFA_SECRET_ENCRYPTION_KEY must decode to exactly 32 bytes")
        return key


@lru_cache
def get_settings() -> Settings:
    """Load settings once per process; raises at first access if misconfigured."""
    return Settings()

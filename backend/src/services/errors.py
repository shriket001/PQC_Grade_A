"""Auth-domain errors, each carrying the HTTP status and structured error_code
that the composition root (main.py) maps to the shared `{error_code, message}`
response shape (Constitution Principle VI / FR-022).

The service layer raises these; routers never hand-build HTTP errors themselves.
US11's audit integration records `outcome="failure"` for these where relevant.
"""


class AuthError(Exception):
    """Base for all auth-domain errors raised by AuthService."""

    status_code: int = 400
    error_code: str = "auth_error"

    def __init__(self, message: str = "") -> None:
        # Default the client-facing message to the error code when none is
        # given, so no internal detail leaks by accident (FR-022).
        self.message = message or self.error_code
        super().__init__(self.message)


class WeakPasswordError(AuthError):
    status_code = 400
    error_code = "weak_password"


class InvalidVerificationTokenError(AuthError):
    status_code = 400
    error_code = "invalid_verification_token"


class EmailAlreadyRegisteredError(AuthError):
    # Registration duplicate detection is allowed to surface — only login and
    # password-reset must hide account existence (spec open-questions).
    status_code = 409
    error_code = "email_already_registered"


class UsernameAlreadyRegisteredError(AuthError):
    # The username is the public handle others use to start a conversation
    # (FR-052/FR-053), so a taken username must surface at registration just
    # like a duplicate email — the caller needs to pick another handle.
    status_code = 409
    error_code = "username_taken"


class InvalidCredentialsError(AuthError):
    # Identical for "no such user" and "wrong password" — no account leak.
    status_code = 401
    error_code = "invalid_credentials"


class EmailNotVerifiedError(AuthError):
    status_code = 403
    error_code = "email_not_verified"


class AccountDisabledError(AuthError):
    status_code = 403
    error_code = "account_disabled"


class UnauthenticatedError(AuthError):
    status_code = 401
    error_code = "unauthenticated"


class InvalidRefreshTokenError(AuthError):
    # Identical status/shape whether the token is unknown, expired, or already
    # revoked — no need to distinguish for the caller (FR-022).
    status_code = 401
    error_code = "invalid_refresh_token"


class MfaRequiredError(AuthError):
    # Password verified, but the account has TOTP enabled and no code was
    # supplied — the client re-submits /auth/login with `totp_code` set.
    status_code = 401
    error_code = "mfa_required"


class InvalidMfaCodeError(AuthError):
    status_code = 401
    error_code = "invalid_mfa_code"


class MfaAlreadyEnabledError(AuthError):
    status_code = 409
    error_code = "mfa_already_enabled"


class MfaEnrollmentNotFoundError(AuthError):
    # /mfa/totp/confirm called with no prior (or already-confirmed) /enroll.
    status_code = 400
    error_code = "mfa_enrollment_not_found"


class MfaNotEnabledError(AuthError):
    status_code = 400
    error_code = "mfa_not_enabled"


class SessionNotFoundError(AuthError):
    # Also raised (rather than a distinguishing 403) when the session_id
    # exists but belongs to a different user, or is already revoked/expired —
    # no need to reveal which case to the caller (FR-022 no-account-leak
    # posture, same rationale as InvalidCredentialsError).
    status_code = 404
    error_code = "session_not_found"


class OAuthProviderNotSupportedError(AuthError):
    # Unknown `{provider}` path segment, or a known one with no client
    # credentials configured (e.g. GOOGLE_OAUTH_CLIENT_ID unset) — either way
    # there is no OidcClient to hand the request to.
    status_code = 404
    error_code = "oauth_provider_not_supported"


class OAuthExchangeFailedError(AuthError):
    # The authorization code couldn't be exchanged for a verified profile —
    # wrong/expired/replayed code, the IdP was unreachable, or it didn't
    # return a usable email. No need to distinguish these for the caller.
    status_code = 401
    error_code = "oauth_exchange_failed"


class SamlProviderNotSupportedError(AuthError):
    # Unknown `{idp}` path segment, or a known one with no IdP metadata
    # configured — either way there is no SamlClient to hand the request to.
    status_code = 404
    error_code = "saml_provider_not_supported"


class SamlAssertionRejectedError(AuthError):
    # The SAML response/assertion couldn't be validated — bad signature,
    # expired, replayed, wrong audience, or missing a usable email attribute.
    # No need to distinguish these for the caller.
    status_code = 401
    error_code = "saml_assertion_rejected"


class ExternalIdentityConflictError(AuthError):
    # Shared by both the OIDC and SAML Relying Party flows (`ExternalIdentityLinker`):
    # the claimed email matches an existing local account, but the IdP didn't
    # vouch for the email as verified — refusing to link (spoofing risk) or
    # create a duplicate (email is globally unique in this schema anyway).
    status_code = 401
    error_code = "external_identity_conflict"

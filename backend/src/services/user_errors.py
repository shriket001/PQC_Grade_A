"""User-directory errors (US2 user discovery — FR-053).

Distinct from `AuthError` (authentication/registration) and `MessagingError`
(conversations/messages): these cover the public user-directory surface
(`/users/me`, `/users/{id}`, `/users/search`). Each carries the HTTP status and
structured `error_code` that the composition root (main.py) maps to the shared
`{error_code, message}` response shape (Constitution Principle VI / FR-022).
"""


class UserServiceError(Exception):
    """Base for user-directory errors raised by UserService."""

    status_code: int = 400
    error_code: str = "user_error"

    def __init__(self, message: str = "") -> None:
        # Default the client-facing message to the error code so no internal
        # detail leaks by accident (FR-022).
        self.message = message or self.error_code
        super().__init__(self.message)


class UserNotFoundError(UserServiceError):
    status_code = 404
    error_code = "user_not_found"

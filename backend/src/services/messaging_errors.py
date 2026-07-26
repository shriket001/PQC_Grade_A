"""Messaging-domain errors (US2 / Phase 5).

Each carries an HTTP status + `error_code`; the composition root (main.py) maps
them to the shared `{error_code, message}` response shape (FR-022), the same way
auth errors are mapped. RBAC/authorization failures are raised here at the
service layer (Constitution §8), not only at the router.
"""


class MessagingError(Exception):
    """Base for all messaging-domain errors raised by the messaging services."""

    status_code: int = 400
    error_code: str = "messaging_error"

    def __init__(self, message: str = "") -> None:
        # Default to the error code so no internal detail leaks by accident.
        self.message = message or self.error_code
        super().__init__(self.message)


class ConversationNotFoundError(MessagingError):
    status_code = 404
    error_code = "conversation_not_found"


class NotParticipantError(MessagingError):
    # Returned for any operation on a conversation the user isn't an active
    # member of — including non-participants trying to read/list messages.
    status_code = 403
    error_code = "not_participant"


class InvalidEnvelopeError(MessagingError):
    status_code = 400
    error_code = "invalid_envelope"


class InvalidIdentityKeyError(MessagingError):
    status_code = 400
    error_code = "invalid_identity_key"


class InvalidRotationAttestationError(MessagingError):
    status_code = 400
    error_code = "invalid_rotation_attestation"


class InvalidConversationRequestError(MessagingError):
    status_code = 400
    error_code = "invalid_conversation_request"


class NotGroupAdminError(MessagingError):
    # FR-024: only a group_admin may add participants or remove someone other
    # than themselves.
    status_code = 403
    error_code = "not_group_admin"


class ConversationTypeMismatchError(MessagingError):
    # Participant-management endpoints only apply to group conversations; a
    # direct conversation's 2-participant membership is fixed at creation.
    status_code = 400
    error_code = "conversation_type_mismatch"


class ParticipantAlreadyActiveError(MessagingError):
    status_code = 409
    error_code = "participant_already_active"

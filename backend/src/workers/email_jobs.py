"""arq background job: send the email-verification link (US1 / Phase 4).

Runs inside the arq worker process (not the API process) — `AuthService.register`
enqueues it via `ArqVerificationEmailSender`. Delivery is best-effort with
structured logging: a missing local SMTP host in dev is expected and logged as a
warning, never raised into the job result (the enqueue side already succeeded).
"""

import asyncio
import smtplib
from email.message import EmailMessage

from src.core.config import get_settings
from src.core.logging import get_logger

logger = get_logger(__name__)


def _build_message(to_email: str, link: str) -> EmailMessage:
    settings = get_settings()
    msg = EmailMessage()
    msg["Subject"] = "Verify your VAYUNX account"
    msg["From"] = settings.smtp_from_address
    msg["To"] = to_email
    msg.set_content(f"Verify your VAYUNX account by opening this link:\n\n{link}\n")
    return msg


def _smtp_send(host: str, port: int, msg: EmailMessage) -> None:
    with smtplib.SMTP(host, port, timeout=10) as server:
        server.send_message(msg)


async def send_verification_email(ctx: dict[str, object], *, email: str, token: str) -> None:
    """arq job entrypoint. `ctx` is arq's worker context (unused here)."""
    settings = get_settings()
    link = f"{settings.app_base_url}/verify-email?token={token}"
    msg = _build_message(email, link)
    try:
        # SMTP is blocking; run it off the event loop.
        await asyncio.to_thread(_smtp_send, settings.smtp_host, settings.smtp_port, msg)
        logger.info("verification_email_sent", email=email)
    except Exception:  # noqa: BLE001 — best-effort delivery, never crash the worker
        logger.warning("verification_email_send_failed", email=email, link=link)

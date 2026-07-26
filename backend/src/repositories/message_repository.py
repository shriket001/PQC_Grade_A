"""MessageRepository — opaque ciphertext message data access (US2).

The repository treats `ciphertext` and `envelope` as opaque blobs; it never
parses envelope content (FR-051/SC-002). Pagination is cursor-based on
`(sent_at, id)` (FR-034): a cursor encodes the last-returned message's
`(sent_at, id)` so the next page starts strictly after it.
"""

import base64
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, or_, select

from src.models.message import Message
from src.repositories.base import BaseRepository

_DEFAULT_PAGE_SIZE = 50
_MAX_PAGE_SIZE = 200


def encode_cursor(*, sent_at: datetime, message_id: UUID) -> str:
    raw = f"{sent_at.isoformat()}|{message_id}".encode()
    return base64.urlsafe_b64encode(raw).decode()


def decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    sent_at_str, _, message_id_str = raw.partition("|")
    return datetime.fromisoformat(sent_at_str), UUID(message_id_str)


class MessageRepository(BaseRepository[Message]):
    model = Message

    async def list_for_conversation(
        self,
        conversation_id: UUID,
        *,
        before_cursor: str | None = None,
        limit: int = _DEFAULT_PAGE_SIZE,
    ) -> tuple[list[Message], str | None]:
        """Chronological page of messages ending at `before_cursor` (exclusive).

        Returns (messages_oldest_first, next_cursor). `next_cursor` is set when
        more older messages exist; callers request the next page with it.
        """
        page_size = min(max(1, limit), _MAX_PAGE_SIZE)
        stmt = select(Message).where(Message.conversation_id == conversation_id)
        if before_cursor is not None:
            sent_at, message_id = decode_cursor(before_cursor)
            # Strictly older than the cursor: (sent_at, id) < (cursor_sent_at, cursor_id)
            stmt = stmt.where(
                or_(
                    Message.sent_at < sent_at,
                    and_(Message.sent_at == sent_at, Message.id < message_id),
                )
            )
        stmt = stmt.order_by(Message.sent_at.desc(), Message.id.desc()).limit(page_size + 1)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())

        has_more = len(rows) > page_size
        page = rows[:page_size]
        # Oldest-first for display (caller may reverse as needed).
        page.reverse()
        next_cursor = (
            encode_cursor(sent_at=page[0].sent_at, message_id=page[0].id)
            if has_more and page
            else None
        )
        return page, next_cursor

"""WebSocket connection manager: per-instance registry + Redis pub/sub fan-out.

Per research.md #2: each backend instance holds only the connections it
physically accepted. Delivering an event to a user connected to a *different*
instance goes through a Redis Pub/Sub channel named `user:{user_id}`; every
instance subscribes to the channels for its own currently-connected users.
"""

import asyncio
import json
from uuid import UUID

from fastapi import WebSocket

from src.core.logging import get_logger
from src.core.redis_client import get_redis

logger = get_logger(__name__)


def _channel_name(user_id: UUID) -> str:
    return f"user:{user_id}"


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[UUID, set[WebSocket]] = {}
        self._subscriber_tasks: dict[UUID, asyncio.Task[None]] = {}

    async def connect(self, user_id: UUID, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.setdefault(user_id, set()).add(websocket)
        if user_id not in self._subscriber_tasks:
            self._subscriber_tasks[user_id] = asyncio.create_task(self._subscribe_loop(user_id))

    async def disconnect(self, user_id: UUID, websocket: WebSocket) -> None:
        connections = self._connections.get(user_id)
        if connections is None:
            return
        connections.discard(websocket)
        if not connections:
            del self._connections[user_id]
            task = self._subscriber_tasks.pop(user_id, None)
            if task is not None:
                task.cancel()

    async def send_to_user(self, user_id: UUID, event: dict[str, object]) -> None:
        """Publishes to Redis so whichever instance holds the user's connection can relay it."""
        await get_redis().publish(_channel_name(user_id), json.dumps(event))

    async def _subscribe_loop(self, user_id: UUID) -> None:
        redis = get_redis()
        pubsub = redis.pubsub()
        await pubsub.subscribe(_channel_name(user_id))
        try:
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                event = json.loads(message["data"])
                await self._deliver_locally(user_id, event)
        except asyncio.CancelledError:
            pass
        finally:
            await pubsub.unsubscribe(_channel_name(user_id))

    async def _deliver_locally(self, user_id: UUID, event: dict[str, object]) -> None:
        for websocket in list(self._connections.get(user_id, set())):
            try:
                await websocket.send_json(event)
            except Exception:
                logger.warning("ws_delivery_failed", user_id=str(user_id))
                await self.disconnect(user_id, websocket)


connection_manager = ConnectionManager()

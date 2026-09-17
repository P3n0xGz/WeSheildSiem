from __future__ import annotations

import logging
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from siem.config import QueueConfig
from siem.schema import RawEnvelope

logger = logging.getLogger(__name__)


class RawQueue:
    """Async wrapper over Redis Streams for producer and consumer-group pipeline semantics."""

    def __init__(
        self, config: QueueConfig, client: aioredis.Redis | None = None
    ) -> None:
        self.config = config
        self.client = client or aioredis.from_url(
            config.url, decode_responses=True
        )
        self.raw_stream = config.raw_stream
        self.deadletter_stream = config.deadletter_stream
        self.group = config.consumer_group

    async def ensure_group(self) -> None:
        """Create the consumer group from the beginning of the stream, swallowing BUSYGROUP."""
        try:
            await self.client.xgroup_create(
                name=self.raw_stream,
                groupname=self.group,
                id="0",
                mkstream=True,
            )
        except ResponseError as exc:
            if "BUSYGROUP" in str(exc):
                logger.debug("Consumer group '%s' already exists.", self.group)
            else:
                raise

    async def produce(self, env: RawEnvelope) -> str:
        """Serialize a RawEnvelope and append it to the raw stream via XADD."""
        fields = env.to_stream_fields()
        msg_id: str = await self.client.xadd(self.raw_stream, fields)
        return msg_id

    async def consume(
        self, consumer: str, count: int = 100, block_ms: int = 1000
    ) -> list[tuple[str, RawEnvelope]]:
        """Read a batch of new messages for this consumer using XREADGROUP."""
        response = await self.client.xreadgroup(
            groupname=self.group,
            consumername=consumer,
            streams={self.raw_stream: ">"},
            count=count,
            block=block_ms,
        )

        if not response:
            return []

        results: list[tuple[str, RawEnvelope]] = []
        for _stream_name, messages in response:
            for msg_id, data in messages:
                envelope = RawEnvelope.from_stream_fields(data)
                results.append((msg_id, envelope))

        return results

    async def ack(self, msg_id: str) -> None:
        """Acknowledge a processed message ID via XACK."""
        await self.client.xack(self.raw_stream, self.group, msg_id)

    async def reclaim(
        self, consumer: str, min_idle_ms: int = 60000, count: int = 100
    ) -> list[tuple[str, RawEnvelope]]:
        """Reclaim abandoned messages from crashed workers using XAUTOCLAIM."""
        response = await self.client.xautoclaim(
            name=self.raw_stream,
            groupname=self.group,
            consumername=consumer,
            min_idle_time=min_idle_ms,
            start_id="0-0",
            count=count,
        )

        if not response:
            return []

        # xautoclaim returns (next_start_id, messages, [deleted_ids])
        messages = response[1] if len(response) > 1 else []
        results: list[tuple[str, RawEnvelope]] = []

        for item in messages:
            if not item:
                continue
            msg_id, data = item
            if data:  # Skip messages deleted/pruned by Redis
                envelope = RawEnvelope.from_stream_fields(data)
                results.append((msg_id, envelope))

        return results

    async def pending_count(self) -> int:
        """Inspect stream lag and backpressure threshold using XPENDING."""
        summary = await self.client.xpending(self.raw_stream, self.group)
        if not summary:
            return 0
        return int(summary.get("pending", 0))

    async def deadletter(self, env: RawEnvelope, stage: str, error: str) -> str:
        """Push an unparseable or failed envelope to the deadletter stream."""
        fields = env.to_stream_fields()
        fields["stage"] = stage
        fields["error"] = error
        msg_id: str = await self.client.xadd(self.deadletter_stream, fields)
        return msg_id

    async def close(self) -> None:
        """Close the underlying Redis client connection."""
        await self.client.aclose()
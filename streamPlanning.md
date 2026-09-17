streamPlanning.md — src/siem/queue/streams.pyA complete architectural and implementation plan for the third component of WeShieldSIEM. Follow this top-to-bottom to build the Redis Streams buffer layer.   1. Purpose & Scopestreams.py encapsulates Redis Streams to create an asynchronous message buffer separating network collectors (inputs) from processing workers. It handles stream creation, batch production, consumer-group assignment, explicit acknowledgments, dead-letter storage, and failure reclamation.                        ┌──────────────────┐
  Inputs (Producers) │ RawEnvelope      │
                     └────────┬─────────┘
                              │ produce() -> XADD
                              ▼
                   Redis Stream: siem:raw
                              │
                    Consumer Group: pipeline
                              │
               ┌──────────────┴──────────────┐
               │ consume() -> XREADGROUP     │ reclaim() -> XAUTOCLAIM
               ▼                             ▼
        Worker Consumer 1             Worker Consumer 2
               │                             │
       ack() -> XACK                 ack() -> XACK
DependencyDirectionPurposesiem.schema.RawEnvelopeImported by streams.pySerialized into flat string maps (to_stream_fields) and reconstructed (from_stream_fields).   siem.config.QueueConfigImported by streams.pySupplies connection URL, stream identifiers, consumer-group metadata, and backpressure boundaries.   redis.asyncioExternal driverProvides native asyncio networking to Redis.   2. Key Design DecisionsDecisionChoiceRationaleString Encodingdecode_responses=TrueRedis returns string dictionaries instead of bytes. Matches RawEnvelope.from_stream_fields(dict[str, str]) directly without manual decoding loops.   Group Positioningid="0" with mkstream=TrueEnsures consumer groups process historical backlogs if messages landed before the group was initialized. mkstream=True creates the stream if it does not yet exist.   Swallowing BUSYGROUPCatch redis.exceptions.ResponseErrorxgroup_create raises a BUSYGROUP error if the group already exists. Catching this makes ensure_group() idempotent on restarts.   Read Cursorid=">"Tells Redis to deliver only new messages never delivered to any other consumer within the group.   Message Reclamationxautoclaim (not manual xpending + xclaim)Reclaims messages left pending by crashed workers whose idle duration exceeds min_idle_ms in a single call.   Idempotency StrategyContent-hash ID on OpenSearch indexRedis generates its own monotonic timestamp IDs (<time>-<seq>) on XADD. Deduplication happens downstream using Event.doc_id() during bulk indexing.   3. Module Layout & Class InterfacePython# src/siem/queue/streams.py
from __future__ import annotations

import logging
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from siem.config import QueueConfig
from siem.schema import RawEnvelope

logger = logging.getLogger(__name__)

class RawQueue:
    def __init__(self, config: QueueConfig, client: aioredis.Redis | None = None) -> None: ...
    async def ensure_group(self) -> None: ...
    async def produce(self, env: RawEnvelope) -> str: ...
    async def consume(self, consumer: str, count: int = 100, block_ms: int = 1000) -> list[tuple[str, RawEnvelope]]: ...
    async def ack(self, msg_id: str) -> None: ...
    async def reclaim(self, consumer: str, min_idle_ms: int = 60000, count: int = 100) -> list[tuple[str, RawEnvelope]]: ...
    async def pending_count(self) -> int: ...
    async def deadletter(self, env: RawEnvelope, stage: str, error: str) -> str: ...
    async def close(self) -> None: ...
4. Deep-Dive Implementation Specification__init__(self, config: QueueConfig, client: aioredis.Redis | None = None)Assign self.config = config.   Initialize self.client = client or aioredis.from_url(config.url, decode_responses=True).   Cache string attributes: self.raw_stream = config.raw_stream, self.deadletter_stream = config.deadletter_stream, and self.group = config.consumer_group.   async def ensure_group(self) -> NoneExecutes: await self.client.xgroup_create(self.raw_stream, self.group, id="0", mkstream=True).   Wraps the call in a try...except ResponseError as exc: block.   Inspects str(exc):If "BUSYGROUP" is present in the error message, silently pass/log at debug level.   If any other Redis error occurs, re-raise immediately.   async def produce(self, env: RawEnvelope) -> strCalls fields = env.to_stream_fields() to obtain a flat dictionary of strings.   Executes: msg_id = await self.client.xadd(self.raw_stream, fields).   Returns the generated Redis message ID string.   async def consume(self, consumer: str, count: int = 100, block_ms: int = 1000) -> list[tuple[str, RawEnvelope]]Executes:Pythonresponse = await self.client.xreadgroup(
    groupname=self.group,
    consumername=consumer,
    streams={self.raw_stream: ">"},
    count=count,
    block=block_ms,
)
   Parsing the Redis Data Structure:If response is empty or None, return [].   The return structure from xreadgroup is:Python# [[stream_name, [[msg_id, {field_key: field_val, ...}], ...]]]
Iterate over messages:Pythonresults: list[tuple[str, RawEnvelope]] = []
for _stream_name, messages in response:
    for msg_id, data in messages:
        envelope = RawEnvelope.from_stream_fields(data)
        results.append((msg_id, envelope))
return results
   async def ack(self, msg_id: str) -> NoneExecutes: await self.client.xack(self.raw_stream, self.group, msg_id).   Clears the message from the consumer group's Pending Entries List (PEL).   async def reclaim(self, consumer: str, min_idle_ms: int = 60000, count: int = 100) -> list[tuple[str, RawEnvelope]]Executes xautoclaim to acquire abandoned messages from failed workers:   Pythonresponse = await self.client.xautoclaim(
    name=self.raw_stream,
    groupname=self.group,
    consumername=consumer,
    min_idle_time=min_idle_ms,
    start_id="0-0",
    count=count,
)
   Handling xautoclaim Return Signatures:Redis returns a tuple: (next_start_id, messages, [deleted_ids]) (or 2 to 3 elements depending on Redis version).messages contains elements in the format (msg_id, field_dict).Convert each valid message: results.append((msg_id, RawEnvelope.from_stream_fields(data))).   Return results.   async def pending_count(self) -> intExecutes: summary = await self.client.xpending(self.raw_stream, self.group).   xpending summary returns a dictionary containing the key "pending":Pythonif not summary:
    return 0
return int(summary.get("pending", 0))
   Used to check queue backlog against config.max_pending to trigger backpressure.   async def deadletter(self, env: RawEnvelope, stage: str, error: str) -> strSerializes the envelope and appends contextual metadata:   Pythonfields = env.to_stream_fields()
fields["stage"] = stage
fields["error"] = error
return await self.client.xadd(self.deadletter_stream, fields)
   async def close(self) -> NoneCloses the active client and connection pool cleanly:   Pythonawait self.client.aclose()
5. Failure Recovery & MechanicsAt-Least-Once Delivery: Messages are kept in the Pending Entries List (PEL) until ack() is invoked.   Crash Handling: If worker A pulls 10 messages and exits unexpectedly, those messages remain un-acked in the PEL. Worker B periodically invokes reclaim(); once idle time exceeds min_idle_ms, worker B takes ownership of the messages and finishes processing.   Deduplication Safeguard: If a worker crashes after indexing a document to OpenSearch but before calling ack(), the reclaimed message will be reprocessed. Because _id is a content hash (Event.doc_id()), OpenSearch rejects the duplicate with HTTP 409.   6. Testing Plan (tests/test_streams.py)Run using pytest-asyncio against a local Redis instance or testcontainers:   ensure_group creates stream and consumer group cleanly on an empty Redis instance.   Calling ensure_group a second time swallows BUSYGROUP without raising an exception.   produce appends an envelope and returns a valid Redis message ID format (<timestamp>-<seq>).   consume returns messages with matching properties (raw, source, transport, labels).   ack removes the message ID from the pending count.   Unacknowledged messages show up in pending_count().   reclaim successfully claims an un-acked message whose idle time exceeds the threshold.   deadletter adds the record to siem:deadletter with "stage" and "error" preserved.   7. Implementation Checklist[ ] Instantiate RawQueue with decode_responses=True.   [ ] Implement ensure_group() with BUSYGROUP handling.   [ ] Implement produce() using RawEnvelope.to_stream_fields().   [ ] Implement consume() parsing XREADGROUP nested arrays.   [ ] Implement ack() wrapping XACK.   [ ] Implement reclaim() using XAUTOCLAIM.   [ ] Implement pending_count() using XPENDING.   [ ] Implement deadletter() writing to the fallback stream.   [ ] Add close() for connection cleanup.   [ ] Verify functionality with pytest tests/test_streams.py.   
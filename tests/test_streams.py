import asyncio
import pytest
import redis.asyncio as aioredis
from siem.config import QueueConfig
from siem.schema import RawEnvelope
from siem.queue.streams import RawQueue

# Use a separate Redis database (e.g., /1) for tests to avoid wiping dev data
TEST_REDIS_URL = "redis://localhost:6379/1"

@pytest.fixture
async def queue():
    """Provides a fresh RawQueue connected to a clean Redis database."""
    config = QueueConfig(
        url=TEST_REDIS_URL,
        raw_stream="test:raw",
        deadletter_stream="test:deadletter",
        consumer_group="test-group",
        max_pending=100,
    )
    client = aioredis.from_url(config.url, decode_responses=True)
    await client.flushdb()  # Start clean
    
    q = RawQueue(config, client=client)
    yield q
    
    await q.close()
    await client.aclose()

@pytest.fixture
def sample_env():
    return RawEnvelope(
        raw="test message",
        source="sshd",
        transport="syslog-udp",
        labels={"env": "test"}
    )

@pytest.mark.asyncio
class TestRawQueue:
    async def test_ensure_group_is_idempotent(self, queue):
        # First call creates the group and stream
        await queue.ensure_group()
        groups = await queue.client.xinfo_groups(queue.raw_stream)
        assert len(groups) == 1
        assert groups[0]["name"] == queue.group

        # Second call should swallow the BUSYGROUP error silently
        await queue.ensure_group()

    async def test_produce_and_consume(self, queue, sample_env):
        await queue.ensure_group()
        
        msg_id = await queue.produce(sample_env)
        assert "-" in msg_id  # Redis message IDs are formatted as <timestamp>-<sequence>

        batch = await queue.consume(consumer="worker-1", count=10, block_ms=10)
        assert len(batch) == 1
        
        consumed_id, envelope = batch[0]
        assert consumed_id == msg_id
        assert envelope.raw == "test message"
        assert envelope.labels == {"env": "test"}

    async def test_ack_removes_from_pending(self, queue, sample_env):
        await queue.ensure_group()
        await queue.produce(sample_env)
        
        # Consume moves message to Pending Entries List (PEL)
        batch = await queue.consume(consumer="worker-1", count=10, block_ms=10)
        msg_id = batch[0][0]
        
        assert await queue.pending_count() == 1
        
        await queue.ack(msg_id)
        assert await queue.pending_count() == 0

    async def test_reclaim_abandoned_messages(self, queue, sample_env):
        await queue.ensure_group()
        await queue.produce(sample_env)
        
        # Worker 1 consumes but crashes (no ack)
        batch1 = await queue.consume(consumer="worker-1", count=10, block_ms=10)
        assert len(batch1) == 1
        
        # Fast-forward time for the idle check (simulated by using min_idle_ms=0)
        await asyncio.sleep(0.01)
        
        # Worker 2 reclaims the stuck message
        reclaimed = await queue.reclaim(consumer="worker-2", min_idle_ms=0)
        assert len(reclaimed) == 1
        
        reclaimed_id, envelope = reclaimed[0]
        assert reclaimed_id == batch1[0][0]
        assert envelope.raw == "test message"

    async def test_deadletter_routing(self, queue, sample_env):
        msg_id = await queue.deadletter(sample_env, stage="parser", error="ValueError")
        
        # Read directly from deadletter stream to verify
        messages = await queue.client.xread({queue.deadletter_stream: "0-0"}, count=1)
        data = messages[0][1][0][1]
        
        assert data["raw"] == "test message"
        assert data["stage"] == "parser"
        assert data["error"] == "ValueError"
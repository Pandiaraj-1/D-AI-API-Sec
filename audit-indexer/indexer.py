"""Consume scored events from Kafka and bulk-index them into Elasticsearch."""
from __future__ import annotations
import asyncio
import json
import logging
import os
from datetime import datetime, timezone

from aiokafka import AIOKafkaConsumer
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("audit-indexer")

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "kafka:9092")
ES_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
AUDIT_TOPIC = os.getenv("AUDIT_TOPIC", "api.audit.events")
FLUSH_INTERVAL_SECONDS = float(os.getenv("FLUSH_INTERVAL_SECONDS", "2.0"))
FLUSH_BATCH_SIZE = int(os.getenv("FLUSH_BATCH_SIZE", "200"))


def _index_name() -> str:
    return f"api-audit-events-{datetime.now(timezone.utc):%Y.%m.%d}"


async def _flush(es: AsyncElasticsearch, buffer: list[dict]) -> None:
    if not buffer:
        return
    actions = [{"_index": _index_name(), "_source": event} for event in buffer]
    try:
        successes, errors = await async_bulk(es, actions, raise_on_error=False)
        if errors:
            logger.warning("Indexed %d docs, %d failed", successes, len(errors))
        else:
            logger.info("Indexed %d docs into %s", successes, _index_name())
    except Exception:
        logger.exception("Bulk index call failed; %d events dropped from this batch", len(buffer))
    finally:
        buffer.clear()


async def run() -> None:
    es = AsyncElasticsearch(hosts=[ES_URL])
    consumer = AIOKafkaConsumer(
        AUDIT_TOPIC,
        bootstrap_servers=KAFKA_BROKERS,
        group_id="audit-indexer",
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        auto_offset_reset="latest",
        enable_auto_commit=True,
    )

    while True:
        try:
            await consumer.start()
            logger.info("Connected to Kafka, consuming '%s'", AUDIT_TOPIC)
            break
        except Exception as exc:
            logger.warning("Kafka not ready (%s); retrying in 5s", exc)
            await asyncio.sleep(5)

    buffer: list[dict] = []
    try:
        while True:
            try:
                msg = await asyncio.wait_for(consumer.getone(), timeout=FLUSH_INTERVAL_SECONDS)
                buffer.append(msg.value)
                if len(buffer) >= FLUSH_BATCH_SIZE:
                    await _flush(es, buffer)
            except asyncio.TimeoutError:
                await _flush(es, buffer)
    finally:
        await _flush(es, buffer)
        await consumer.stop()
        await es.close()


if __name__ == "__main__":
    asyncio.run(run())

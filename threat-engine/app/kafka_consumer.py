"""Score the Kafka request stream and update the Redis blocklist."""
from __future__ import annotations
import asyncio
import json
import logging
import os

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
import redis.asyncio as aioredis

from app.features import RequestSignal, extract_features
from app.model import EnsembleThreatModel

logger = logging.getLogger("threat-engine.consumer")

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "kafka:9092")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
RAW_TOPIC = os.getenv("RAW_TOPIC", "api.requests.raw")
AUDIT_TOPIC = os.getenv("AUDIT_TOPIC", "api.audit.events")
BLOCKLIST_TTL_SECONDS = int(os.getenv("BLOCKLIST_TTL_SECONDS", "900"))


async def _consume_loop(model: EnsembleThreatModel):
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    consumer = AIOKafkaConsumer(
        RAW_TOPIC,
        bootstrap_servers=KAFKA_BROKERS,
        group_id="threat-engine-scorer",
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        auto_offset_reset="latest",
        enable_auto_commit=True,
    )
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BROKERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    while True:
        try:
            await consumer.start()
            await producer.start()
            logger.info("Kafka consumer connected. Listening on '%s'", RAW_TOPIC)
            break
        except Exception as exc:
            logger.warning("Kafka not ready (%s). Retrying in 5s...", exc)
            await asyncio.sleep(5)

    try:
        async for msg in consumer:
            try:
                payload = msg.value
                signal = RequestSignal(**payload["signal"])
                vector = extract_features(signal)
                result = model.score(vector)

                client_ip = payload.get("client_ip", "unknown")
                event = {
                    "request_id": payload.get("request_id"),
                    "client_ip": client_ip,
                    "endpoint": payload.get("endpoint"),
                    "method": payload.get("method"),
                    "timestamp": payload.get("timestamp"),
                    "isolation_score": result.isolation_score,
                    "xgboost_score": result.xgboost_score,
                    "final_score": result.final_score,
                    "decision": result.decision,
                    "reason": result.reason,
                }

                if result.decision == "BLOCK" and client_ip != "unknown":
                    await redis_client.setex(
                        f"blocklist:{client_ip}", BLOCKLIST_TTL_SECONDS, result.reason
                    )
                    logger.info("Blocklisted %s for %ss (%s)", client_ip, BLOCKLIST_TTL_SECONDS, result.reason)

                await producer.send_and_wait(AUDIT_TOPIC, event)

            except Exception:
                logger.exception("Failed to process message; skipping")
    finally:
        await consumer.stop()
        await producer.stop()
        await redis_client.close()


def start_consumer_in_background(model: EnsembleThreatModel) -> asyncio.Task:
    loop = asyncio.get_event_loop()
    return loop.create_task(_consume_loop(model))

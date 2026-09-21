"""
main.py
FastAPI entrypoint for the Threat Intelligence Engine.

Exposes:
  POST /score   -> synchronous, low-latency scoring call used by the
                    Spring Boot gateway on the hot path (target: single
                    digit milliseconds, models are already resident in
                    memory -- there is no I/O in the scoring path).
  GET  /health  -> liveness/readiness probe for Docker/K8s.

The Kafka consumer that powers the ASYNC path (continuous scoring of the
full request stream + adaptive Redis blocklisting) runs as a background
task started in the lifespan handler -- see kafka_consumer.py.
"""
from __future__ import annotations
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.features import RequestSignal, extract_features, FEATURE_ORDER
from app.model import EnsembleThreatModel
from app.kafka_consumer import start_consumer_in_background

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("threat-engine")

model = EnsembleThreatModel(model_dir="models")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Loading ensemble model artifacts...")
    model.load()
    logger.info("Model loaded. Feature order: %s", FEATURE_ORDER)
    consumer_task = start_consumer_in_background(model)
    yield
    consumer_task.cancel()


app = FastAPI(
    title="AI Threat Intelligence Engine",
    description="Ensemble (Isolation Forest + XGBoost) real-time API risk scoring service.",
    version="1.0.0",
    lifespan=lifespan,
)


class ScoreResponse(BaseModel):
    isolation_score: float
    xgboost_score: float
    final_score: float
    decision: str
    reason: str


@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": model.isolation_forest is not None}


@app.post("/score", response_model=ScoreResponse)
async def score(signal: RequestSignal):
    if model.isolation_forest is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet")
    vector = extract_features(signal)
    result = model.score(vector)
    return ScoreResponse(**result.__dict__)

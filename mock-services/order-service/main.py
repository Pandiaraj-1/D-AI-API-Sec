"""
Minimal stand-in for a real orders/checkout microservice. It does nothing
clever -- it just echoes back what it received plus a timestamp. Its only
purpose in this project is to be the thing sitting BEHIND the gateway, so
the attack-simulation scripts can prove a negative: a blocked request
should show up in Elasticsearch as blocked and should NEVER show up in
this service's logs at all.
"""
import time
from fastapi import FastAPI, Request

app = FastAPI(title="mock-order-service")


@app.post("/api/orders")
async def create_order(request: Request):
    body = await request.json()
    print(f"[order-service] received order: {body}")
    return {"status": "accepted", "received": body, "server_time": time.time()}


@app.post("/api/checkout")
async def checkout(request: Request):
    body = await request.json()
    print(f"[order-service] received checkout: {body}")
    return {"status": "accepted", "received": body, "server_time": time.time()}


@app.get("/health")
def health():
    return {"status": "ok"}

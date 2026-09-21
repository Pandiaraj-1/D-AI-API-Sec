"""
locustfile.py
Baseline latency/throughput test for the gateway's benign-traffic path.

Usage:
    pip install locust
    locust -f scripts/locustfile.py --host http://localhost:8080 \
        --users 50 --spawn-rate 10 --run-time 1m --headless
"""
from locust import HttpUser, task, between


class GatewayUser(HttpUser):
    wait_time = between(0.2, 1.0)

    @task(3)
    def browse_orders(self):
        self.client.post(
            "/api/orders",
            json={"item_id": 101, "qty": 1, "price": 29.99},
            headers={"Authorization": "Bearer REPLACE_WITH_VALID_TOKEN"},
            name="/api/orders [benign]",
        )

    @task(1)
    def login(self):
        self.client.post(
            "/api/auth/login",
            json={"username": "demo_user", "password": "correct-horse-battery-staple"},
            name="/api/auth/login [benign]",
        )

"""
simulate_business_logic_abuse.py

Sends a mix of NORMAL checkout requests and TAMPERED ones (negative
quantity, near-zero price, extra hidden fields like a fake
"admin_override" flag) at a LOW, human-looking request rate. This is the
scenario a rate-limiter or a signature-based WAF cannot catch: nothing
here looks like a flood, and there is no SQL-injection-shaped string to
pattern-match against. The only tell is that the numeric fields fall
outside the range a legitimate checkout would ever produce, and that the
payload shape (extra params) doesn't match the endpoint's baseline.

Usage:
    python scripts/simulate_business_logic_abuse.py --target http://localhost:8080 --token <JWT>

Get a token first:
    curl -X POST http://localhost:8080/api/auth/login \\
      -H "Content-Type: application/json" \\
      -d '{"username":"demo_user","password":"correct-horse-battery-staple"}'
"""
import argparse
import random
import time

import httpx

NORMAL_ORDERS = [
    {"item_id": 101, "qty": 1, "price": 29.99},
    {"item_id": 205, "qty": 2, "price": 14.50},
    {"item_id": 310, "qty": 1, "price": 89.00},
]

TAMPERED_ORDERS = [
    {"item_id": 101, "qty": -5, "price": 0.01, "coupon_stack": 12, "admin_override": True},
    {"item_id": 205, "qty": 999, "price": 0.00, "internal_test_mode": True},
    {"item_id": 310, "qty": 1, "price": -89.00, "refund_now": True},
]


def send_batch(target: str, token: str, orders: list[dict], label: str):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    with httpx.Client() as client:
        for i, order in enumerate(orders):
            resp = client.post(f"{target}/api/checkout", json=order, headers=headers, timeout=5.0)
            risk = resp.headers.get("X-Risk-Level", "-")
            print(f"[{label} {i}] payload={order} -> HTTP {resp.status_code}  X-Risk-Level={risk}")
            time.sleep(random.uniform(0.5, 1.5))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate business-logic abuse against the checkout endpoint.")
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--token", default="", help="JWT from /api/auth/login")
    args = parser.parse_args()

    print("--- sending normal traffic (should ALLOW) ---")
    send_batch(args.target, args.token, NORMAL_ORDERS, "normal")

    print("\n--- sending tampered traffic (should CHALLENGE/BLOCK) ---")
    send_batch(args.target, args.token, TAMPERED_ORDERS, "tampered")

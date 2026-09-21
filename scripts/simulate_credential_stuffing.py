"""
simulate_credential_stuffing.py

Fires a burst of login attempts at the gateway using a rotating list of
usernames and passwords pulled from a small local wordlist -- the classic
shape of a credential-stuffing attack (high volume, mostly-failing auth,
hammering a single endpoint, often from automation tooling).

Usage:
    python scripts/simulate_credential_stuffing.py --target http://localhost:8080 --requests 60

Expected result against a running stack:
    - The first several requests get a normal 401 (bad credentials) while
      the synchronous score stays under the CHALLENGE threshold.
    - Within a few dozen requests, req_rate_10s and failed_auth_streak push
      the combined score past BLOCK, and you should start seeing 403s with
      "Request blocked by threat engine" bodies.
    - Check Kibana / the Elasticsearch index directly afterward: you should
      see a cluster of decision=BLOCK events from this script's source IP.
"""
import argparse
import asyncio
import random
import time

import httpx

USERNAMES = ["admin", "demo_user", "root", "test", "administrator", "jsmith", "support"]
PASSWORDS = [
    "123456", "password", "letmein", "qwerty123", "Passw0rd!", "welcome1",
    "correct-horse-battery-staple",
]


async def attempt(client: httpx.AsyncClient, target: str, i: int):
    username = random.choice(USERNAMES)
    password = random.choice(PASSWORDS)
    try:
        resp = await client.post(
            f"{target}/api/auth/login",
            json={"username": username, "password": password},
            headers={"User-Agent": "python-requests/credential-stuffing-demo"},
            timeout=5.0,
        )
        risk = resp.headers.get("X-Risk-Level", "-")
        print(f"[{i:03d}] user={username:14s} -> HTTP {resp.status_code}  X-Risk-Level={risk}")
    except httpx.HTTPError as e:
        print(f"[{i:03d}] request failed: {e}")


async def main(target: str, total_requests: int, delay_ms: int):
    async with httpx.AsyncClient() as client:
        for i in range(total_requests):
            await attempt(client, target, i)
            await asyncio.sleep(delay_ms / 1000)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate a credential-stuffing burst against the gateway.")
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--requests", type=int, default=60)
    parser.add_argument("--delay-ms", type=int, default=150, help="delay between attempts, in milliseconds")
    args = parser.parse_args()

    start = time.time()
    asyncio.run(main(args.target, args.requests, args.delay_ms))
    print(f"\nDone in {time.time() - start:.1f}s")

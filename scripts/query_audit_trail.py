"""
query_audit_trail.py
Quick sanity-check query against Elasticsearch after running one of the
attack-simulation scripts: prints the most recent BLOCK/CHALLENGE
decisions so you can see the pipeline actually worked end-to-end without
opening Kibana.

Usage:
    python scripts/query_audit_trail.py --es http://localhost:9200
"""
import argparse
import json

import httpx

QUERY = {
    "size": 20,
    "sort": [{"timestamp": "desc"}],
    "query": {
        "bool": {
            "must_not": [{"term": {"decision": "ALLOW"}}]
        }
    },
}


def main(es_url: str):
    resp = httpx.post(
        f"{es_url}/api-audit-events-*/_search",
        json=QUERY,
        timeout=10.0,
    )
    resp.raise_for_status()
    hits = resp.json().get("hits", {}).get("hits", [])
    if not hits:
        print("No BLOCK/CHALLENGE events found yet. Run an attack simulation script first.")
        return

    print(f"{'timestamp':25s} {'client_ip':15s} {'decision':10s} {'final_score':>11s}  reason")
    print("-" * 100)
    for hit in hits:
        src = hit["_source"]
        print(
            f"{src.get('timestamp',''):25s} "
            f"{src.get('client_ip',''):15s} "
            f"{src.get('decision',''):10s} "
            f"{src.get('final_score', 0):>11.3f}  "
            f"{src.get('reason','')}"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--es", default="http://localhost:9200")
    args = parser.parse_args()
    main(args.es)

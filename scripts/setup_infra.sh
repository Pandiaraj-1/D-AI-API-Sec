#!/usr/bin/env bash
# One-time provisioning: run this once after `docker compose up -d` (give
# Elasticsearch and Kafka ~30s to finish starting first). Safe to re-run --
# every call here is idempotent (PUT-based).
set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"

echo "==> Waiting for Elasticsearch..."
until curl -sf "${ES_URL}/_cluster/health" > /dev/null; do
  sleep 2
done

echo "==> Creating ILM policy (api-audit-ilm-policy)"
curl -sf -X PUT "${ES_URL}/_ilm/policy/api-audit-ilm-policy" \
  -H "Content-Type: application/json" \
  --data-binary @elasticsearch/ilm-policy.json | jq . || true

echo "==> Creating index template (api-audit-events-*)"
curl -sf -X PUT "${ES_URL}/_index_template/api-audit-events-template" \
  -H "Content-Type: application/json" \
  --data-binary @elasticsearch/audit-events-template.json | jq . || true

echo "==> Creating Kafka topics"
docker exec kafka /opt/kafka/bin/kafka-topics.sh --create --if-not-exists \
  --bootstrap-server localhost:9092 --topic api.requests.raw \
  --partitions 3 --replication-factor 1
docker exec kafka /opt/kafka/bin/kafka-topics.sh --create --if-not-exists \
  --bootstrap-server localhost:9092 --topic api.audit.events \
  --partitions 3 --replication-factor 1

echo "==> Done. Topics:"
docker exec kafka /opt/kafka/bin/kafka-topics.sh --list --bootstrap-server localhost:9092

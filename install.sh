#!/usr/bin/env bash
set -euo pipefail

echo "=== G1-Manifest One-Click Docker Installer (G1163RT Security Labs) ==="
docker compose up -d --build

echo "Waiting for G1-Manifest health endpoint on http://127.0.0.1:8088/health ..."
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8088/health >/dev/null 2>&1; then
    echo "G1-Manifest is healthy! Open http://127.0.0.1:8088/"
    exit 0
  fi
  sleep 1
done

echo "ERROR: G1-Manifest did not become healthy within 30 seconds." >&2
exit 1

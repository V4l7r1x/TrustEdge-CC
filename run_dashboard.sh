#!/usr/bin/env bash
# TrustEdge-CC: Launch Dashboard and Orchestrator Server
cd "$(dirname "$0")"
echo "=== Starting TrustEdge-CC Orchestrator & Web Dashboard ==="
echo "Access Dashboard at: http://localhost:8000"
python3 -m uvicorn dashboard.server:app --app-dir . --host 0.0.0.0 --port 8000

#!/bin/bash
set -e
cd "$(dirname "$0")/.."
echo "== SentinelAI Starting =="
[ ! -d venv ] && python3 -m venv venv
source venv/bin/activate
pip install -q -r backend/requirements.txt
echo "  Backend:  http://localhost:8000"
echo "  API docs: http://localhost:8000/docs"
echo "  Dashboard: open frontend/index.html in your browser"
echo ""
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

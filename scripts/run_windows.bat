@echo off
cd /d "%~dp0\.."
if not exist venv python -m venv venv
call venv\Scripts\activate
pip install -q -r backend\requirements.txt
echo Backend: http://localhost:8000
echo Open frontend\index.html in browser
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

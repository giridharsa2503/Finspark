@echo off
echo ========================================
echo  FinSpark — Starting AI Backend
echo ========================================
cd /d "%~dp0backend"
echo Installing dependencies...
pip install -r requirements.txt
echo.
echo Starting FastAPI server on port 8000...
echo API Docs: http://localhost:8000/docs
echo.
uvicorn main:app --reload --port 8000
pause

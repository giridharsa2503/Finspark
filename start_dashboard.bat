@echo off
echo ========================================
echo  FinSpark — Starting Streamlit Dashboard
echo ========================================
cd /d "%~dp0"
set PYTHONPATH=%~dp0backend
"C:\Users\GIRIDHAR A S\AppData\Local\Python\pythoncore-3.14-64\Scripts\streamlit.exe" run dashboard.py --server.port 8501
pause

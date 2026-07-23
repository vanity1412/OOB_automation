@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Run install_windows.bat first.
    pause
    exit /b 1
)

rem SECURITY DEFAULT: local browser only. Do not expose port 8501 to the LAN directly.
".venv\Scripts\python.exe" -m streamlit run app.py ^
  --server.address 127.0.0.1 ^
  --server.port 8501 ^
  --browser.gatherUsageStats false

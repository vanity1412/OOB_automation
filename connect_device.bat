@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Run install_windows.bat first.
    pause
    exit /b 1
)

if "%~1"=="" (
    set /p TARGET=Hostname / alias / IP: 
) else (
    set "TARGET=%*"
)

".venv\Scripts\python.exe" scripts\connect_device.py "%TARGET%"

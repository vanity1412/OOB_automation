@echo off
setlocal
cd /d "%~dp0"

echo =============================================
echo OOB Device Manager Hardened Final - Windows Setup
echo =============================================

where py >nul 2>nul
if %errorlevel%==0 (
    set PY=py
) else (
    where python >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python not found.
        echo Install Python 3.10+ and enable Add Python to PATH.
        pause
        exit /b 1
    )
    set PY=python
)

%PY% --version

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating venv...
    %PY% -m venv .venv
    if errorlevel 1 goto :error
)

echo [2/3] Upgrading pip...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :error

echo [3/3] Installing packages...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :error

echo.
echo DONE.
echo Run run_windows.bat
echo Optional: run setup_daily_backup.bat once for daily backup at 02:00
pause
exit /b 0

:error
echo.
echo Setup failed.
pause
exit /b 1

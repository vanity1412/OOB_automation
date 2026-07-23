@echo off
setlocal
cd /d "%~dp0"
echo Creating daily backup task at 02:00...
schtasks /Create /TN "OOB Device Manager Daily Backup" /TR "\"%~dp0run_backup.bat\"" /SC DAILY /ST 02:00 /F
if errorlevel 1 (
  echo Failed to create Scheduled Task.
  echo Try running this file from an elevated Command Prompt if required by your policy.
  pause
  exit /b 1
)
echo Scheduled task created.
pause

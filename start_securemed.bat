@echo off
title SecureMed - Medical Device Cryptographic Communication Simulator
echo ======================================================================
echo    SecureMed: Medical Device Cryptographic Communication Simulator
echo ======================================================================
echo.

cd /d "%~dp0"

if exist "%~dp0.venv\Scripts\python.exe" (
    echo [*] Starting SecureMed with virtual environment Python...
    "%~dp0.venv\Scripts\python.exe" "%~dp0run_server.py"
) else (
    where py >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        echo [*] Starting SecureMed with py launcher...
        py "%~dp0run_server.py"
    ) else (
        echo [*] Starting SecureMed with system python...
        python "%~dp0run_server.py"
    )
)

pause

@echo off
setlocal enabledelayedexpansion
title PhantomFlow - Dashboard Only (Quick Start)
color 0B

echo.
echo  ============================================================
echo        PHANTOMFLOW - Quick Dashboard Start
echo        (API Server + Dashboard Only, No Sniffer)
echo  ============================================================
echo.

:: Set working directory to the phantomflow folder
cd /d "%~dp0"
echo [*] Working directory: %cd%

:: ────────────────────────────────────────────────────────────────
:: STEP 1: Check Docker containers
:: ────────────────────────────────────────────────────────────────
echo.
echo [1/3] Checking Docker containers...
docker ps >nul 2>&1
if %errorlevel% neq 0 (
    echo   [!!] Docker is not running. Starting Docker Desktop...
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe" 2>nul
    echo   [..] Waiting for Docker...
    :wait_docker_quick
    timeout /t 3 /nobreak >nul
    docker ps >nul 2>&1
    if %errorlevel% neq 0 goto wait_docker_quick
)
echo   [OK] Docker is running.

:: Start containers if not already running
docker compose -f docker/docker-compose.yml up -d >nul 2>&1
echo   [OK] Infrastructure containers are up.

:: Wait for PostgreSQL and Redis to be ready
timeout /t 5 /nobreak >nul

:: ────────────────────────────────────────────────────────────────
:: STEP 2: Initialize database (idempotent)
:: ────────────────────────────────────────────────────────────────
echo.
echo [2/3] Ensuring database schema is ready...
call python scratch/init_db.py >nul 2>&1
echo   [OK] Database schema verified.

:: ────────────────────────────────────────────────────────────────
:: STEP 3: Kill any existing API server and start fresh
:: ────────────────────────────────────────────────────────────────
echo.
echo [3/3] Starting FastAPI server on port 8000...

:: Kill anything on port 8000 first
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000 ^| findstr LISTENING 2^>nul') do (
    taskkill /PID %%a /F >nul 2>&1
)
timeout /t 1 /nobreak >nul

echo.
echo  ============================================================
echo   Dashboard:   http://localhost:8000/dashboard/index.html
echo   API Docs:    http://localhost:8000/docs
echo   User Guide:  http://localhost:8000/dashboard/guide.html
echo  ============================================================
echo.
echo   Press Ctrl+C to stop the server.
echo.

call python -m uvicorn api.main:app --host 0.0.0.0 --port 8000

echo.
echo [*] PhantomFlow dashboard server has stopped.
pause

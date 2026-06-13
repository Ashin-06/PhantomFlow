@echo off
setlocal enabledelayedexpansion
title PhantomFlow - Security Operations Suite
color 0A

echo.
echo  ============================================================
echo        PHANTOMFLOW - ML Threat Detection Platform
echo        Starting All Services...
echo  ============================================================
echo.

:: Set working directory to the phantomflow folder (where this bat lives)
cd /d "%~dp0"
echo [*] Working directory: %cd%

:: ────────────────────────────────────────────────────────────────
:: STEP 1: Check Docker
:: ────────────────────────────────────────────────────────────────
echo.
echo [1/5] Checking Docker status...
docker ps >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] Docker daemon is running.
    goto docker_ready
)

echo   [..] Docker is not running. Attempting to launch Docker Desktop...
start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe" 2>nul
if %errorlevel% neq 0 (
    echo   [!!] Could not find Docker Desktop at default path.
    echo   [!!] Please start Docker Desktop manually and run this script again.
    pause
    exit /b 1
)

echo   [..] Waiting for Docker daemon to initialize (this may take 30-60 seconds)...
set /a docker_wait=0
:wait_docker
timeout /t 3 /nobreak >nul
docker ps >nul 2>&1
if %errorlevel% equ 0 goto docker_ready
set /a docker_wait+=3
if %docker_wait% gtr 90 (
    echo   [!!] Docker did not start within 90 seconds. Please start it manually.
    pause
    exit /b 1
)
echo   [..] Still waiting... (%docker_wait%s elapsed)
goto wait_docker

:docker_ready
echo   [OK] Docker daemon is online.

:: ────────────────────────────────────────────────────────────────
:: STEP 2: Start Infrastructure Containers
:: ────────────────────────────────────────────────────────────────
echo.
echo [2/5] Starting infrastructure containers (PostgreSQL, Redis, Kafka, Prometheus, Grafana)...
docker compose -f docker/docker-compose.yml up -d
if %errorlevel% neq 0 (
    echo   [!!] Docker Compose failed. Check docker/docker-compose.yml for errors.
    pause
    exit /b 1
)
echo   [OK] All containers started.

:: Wait a moment for PostgreSQL and Redis to fully initialize
echo   [..] Waiting 8 seconds for databases to initialize...
timeout /t 8 /nobreak >nul

:: ────────────────────────────────────────────────────────────────
:: STEP 3: Initialize Database Schema
:: ────────────────────────────────────────────────────────────────
echo.
echo [3/5] Initializing database schema...
python scratch/init_db.py
if %errorlevel% neq 0 (
    echo   [WARN] Database schema init returned an error (tables may already exist - this is OK).
)
echo   [OK] Database schema ready.

:: ────────────────────────────────────────────────────────────────
:: STEP 4: Clean Slate (Reset Counters)
:: ────────────────────────────────────────────────────────────────
echo.
echo [4/5] Resetting databases to clean slate...
python "%~dp0..\clear_db.py"
if %errorlevel% neq 0 (
    echo   [WARN] Clean slate script returned an error (non-critical).
)
echo   [OK] Databases reset.

:: ────────────────────────────────────────────────────────────────
:: STEP 5: Launch PhantomFlow Services
:: ────────────────────────────────────────────────────────────────
echo.
echo [5/5] Launching PhantomFlow services (API + Orchestrator + Sniffer)...
echo.
echo  ============================================================
echo   Dashboard URL:   http://localhost:8000/dashboard/index.html
echo   API Docs:        http://localhost:8000/docs
echo   User Guide:      http://localhost:8000/dashboard/guide.html
echo  ============================================================
echo.
echo   Press Ctrl+C to stop all services.
echo.

python start_all.py

echo.
echo [*] PhantomFlow has stopped.
pause

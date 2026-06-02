@echo off
echo ===================================================
echo   Starting PhantomFlow Local Development Suite
echo ===================================================

:: Check if Docker daemon is responsive
docker ps >nul 2>&1
if %errorlevel% equ 0 (
    echo [System] Docker daemon is already running.
    goto run_containers
)

echo [System] Docker is not running. Launching Docker Desktop...
start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"

echo [System] Waiting for Docker daemon to become responsive (this may take up to a minute)...

:wait_docker
timeout /t 3 /nobreak >nul
docker ps >nul 2>&1
if %errorlevel% neq 0 (
    echo [System] Docker is still initializing, waiting...
    goto wait_docker
)
echo [System] Docker daemon is up and ready!

:run_containers
echo.
echo [System] Starting infrastructure containers (Postgres, Redis, Kafka)...
docker compose -f docker/docker-compose.yml up -d

echo.
echo [System] Resetting databases to clean slate (zero-mock counters)...
python clear_db.py

echo.
echo [System] Launching all PhantomFlow services (API, Orchestrator, Sniffer)...
python start_all.py

pause

# start_all.py
"""
Orchestrates and launches all PhantomFlow services (API, Orchestrator, and Sniffer) 
concurrently in a single terminal window. Handles clean teardown on Ctrl+C.
Includes automatic port cleanup and Kafka readiness checks.
"""
import sys
import subprocess
import time
import signal
import socket
import os

processes = []

def kill_process_on_port(port):
    """Scan and kill any process currently listening on the specified port (Windows specific)."""
    try:
        # Run netstat to find listening process on this port
        output = subprocess.check_output(
            f"netstat -ano | findstr LISTENING | findstr :{port}", 
            shell=True
        ).decode()
        
        pids_killed = set()
        for line in output.strip().split("\n"):
            parts = line.strip().split()
            if len(parts) >= 5:
                pid = parts[-1]
                if pid not in pids_killed and pid != "0":
                    print(f"[System] Port {port} is in use by PID {pid}. Terminating process...")
                    subprocess.run(
                        f"taskkill /PID {pid} /F", 
                        shell=True, 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL
                    )
                    pids_killed.add(pid)
        if pids_killed:
            time.sleep(1.5)  # Give OS a moment to free the socket
    except Exception:
        # Will raise exception if netstat returns no lines, which is normal when port is free
        pass

def wait_for_kafka(port=9092, timeout=60):
    """Wait for Kafka TCP port to be open and accepting connections."""
    print(f"[System] Waiting for Kafka message broker (port {port}) to be ready...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                # Try to connect to localhost port 9092
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    print("[System] Kafka is online and accepting connections!")
                    return True
        except Exception:
            pass
        time.sleep(1)
    print(f"[System] WARNING: Kafka (port {port}) did not become ready within {timeout} seconds.")
    return False

def cleanup_processes():
    print("\n[System] Stopping all PhantomFlow services...")
    for name, proc in processes:
        if proc.poll() is None:
            print(f"[System] Terminating {name} (PID: {proc.pid})...")
            proc.terminate()
    
    # Wait for processes to exit
    for name, proc in processes:
        try:
            proc.wait(timeout=5)
            print(f"[System] {name} stopped successfully.")
        except subprocess.TimeoutExpired:
            print(f"[System] {name} did not stop, killing...")
            proc.kill()

def signal_handler(sig, frame):
    cleanup_processes()
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    python_exe = sys.executable
    print(f"[System] Using Python executable: {python_exe}")

    # 1. Clean up orphaned sockets on port 8000 (API) and 8080 (Orchestrator Health)
    kill_process_on_port(8000)
    kill_process_on_port(8080)

    # 2. Wait for Kafka to fully boot up in its container
    wait_for_kafka(9092)

    # Define the services to start
    services = [
        ("FastAPI Server", [python_exe, "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]),
        ("Pipeline Orchestrator", [python_exe, "-m", "pipeline.orchestrator"]),
        ("Packet Sniffer", [python_exe, "capture/pcap_fallback.py"])
    ]

    # Start services
    for name, cmd in services:
        print(f"[System] Starting {name}...")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=None,  # Stream output directly to terminal
                stderr=None,
                bufsize=1,
                universal_newlines=True
            )
            processes.append((name, proc))
            # Wait briefly to let service start up
            time.sleep(1.5)
        except Exception as e:
            print(f"[System] Failed to start {name}: {e}")
            cleanup_processes()
            sys.exit(1)

    print("\n[System] All services started! Press Ctrl+C to stop all of them.")
    
    # Monitor processes
    while True:
        try:
            time.sleep(1)
            for name, proc in processes:
                exit_code = proc.poll()
                if exit_code is not None:
                    print(f"\n[System] WARNING: {name} exited with code {exit_code}!")
                    cleanup_processes()
                    sys.exit(exit_code)
        except KeyboardInterrupt:
            cleanup_processes()
            break

if __name__ == "__main__":
    main()

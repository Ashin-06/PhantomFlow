# start_all.py
"""
Orchestrates and launches all PhantomFlow services (API, Orchestrator, and Sniffer) 
concurrently in a single terminal window. Handles clean teardown on Ctrl+C.
"""
import sys
import subprocess
import time
import signal
import os

processes = []

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
            # On Windows, we can use CREATE_NEW_PROCESS_GROUP or just start it normal
            proc = subprocess.Popen(
                cmd,
                stdout=None,  # Inherit stdout to stream directly to terminal
                stderr=None,  # Inherit stderr
                bufsize=1,
                universal_newlines=True
            )
            processes.append((name, proc))
            # Give it a second to bind ports/initialize before starting next service
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

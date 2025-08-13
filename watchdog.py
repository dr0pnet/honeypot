import os
import time
import subprocess
import threading
from datetime import datetime
import sys

# ✅ Detect runtime base directory (for EXE or .py)
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
PYTHON_EXEC = sys.executable
LOG_DIR = os.path.join(BASE_DIR, "logs")
CHECK_INTERVAL = 10
HANG_TIMEOUT = 60
WATCHDOG_START_TIME_FILE = os.path.join(LOG_DIR, "watchdog_start_time.txt")

# ✅ Full paths for trap scripts
TRAPS = {
    "SSH Trap": os.path.join(BASE_DIR, "modules", "ssh_trap.py"),
    "FTP Trap": os.path.join(BASE_DIR, "modules", "ftp_trap.py"),
    "Crypto Wallet": os.path.join(BASE_DIR, "modules", "wallet.py"),
    "WEB Login": os.path.join(BASE_DIR, "modules", "browser_trap.py"),
    "File Trap": os.path.join(BASE_DIR, "modules", "file_trap.py"),
    "IDS Scan": os.path.join(BASE_DIR, "modules", "scan_ids.py"),
    "ARP Monitor": os.path.join(BASE_DIR, "modules", "arp_monitor.py"),
    "Decoy Ports": os.path.join(BASE_DIR, "modules", "decoy_ports.py")
}

if not os.path.exists(WATCHDOG_START_TIME_FILE):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(WATCHDOG_START_TIME_FILE, "w") as f:
        f.write(datetime.now().isoformat())

class TrapWatchdog:
    def __init__(self):
        self.trap_processes = {}
        self.last_log_times = {}
        self.running = False

    def get_log_path(self, trap_name):
        return os.path.join(LOG_DIR, f"{trap_name}.log")

    def get_last_log_time(self, trap_name):
        path = self.get_log_path(trap_name)
        if not os.path.exists(path):
            return None
        timestamp = os.path.getmtime(path)
        return datetime.fromtimestamp(timestamp)

    def start_trap(self, trap_name, trap_path):
        if not os.path.exists(trap_path):
            print(f"[ERROR] Trap file not found: {trap_path}")
            return

        log_file = self.get_log_path(trap_name)
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        try:
            proc = subprocess.Popen(
                [PYTHON_EXEC, trap_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.trap_processes[trap_name] = proc
            self.last_log_times[trap_name] = datetime.now()
            print(f"[WATCHDOG] {trap_name} launched")
        except Exception as e:
            print(f"[WATCHDOG ERROR] Could not start {trap_name}: {e}")

    def stop_trap(self, trap_name):
        proc = self.trap_processes.get(trap_name)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            print(f"[WATCHDOG] Stopped {trap_name}")

    def restart_trap(self, trap_name, trap_path):
        print(f"[WATCHDOG] Restarting {trap_name}...")
        self.stop_trap(trap_name)
        self.start_trap(trap_name, trap_path)

    def monitor_traps(self):
        while self.running:
            for trap_name, trap_path in TRAPS.items():
                proc = self.trap_processes.get(trap_name)
                if not proc or proc.poll() is not None:
                    print(f"[WATCHDOG] Trap {trap_name} is down. Restarting...")
                    self.start_trap(trap_name, trap_path)
                    continue

                last_time = self.get_last_log_time(trap_name)
                if last_time:
                    seconds_since = (datetime.now() - last_time).total_seconds()
                    if seconds_since > HANG_TIMEOUT:
                        print(f"[WATCHDOG] {trap_name} log stale ({int(seconds_since)}s). Restarting...")
                        self.restart_trap(trap_name, trap_path)
            time.sleep(CHECK_INTERVAL)

    def start_all(self):
        print("[WATCHDOG] Initializing all traps...")
        for trap_name, trap_path in TRAPS.items():
            self.start_trap(trap_name, trap_path)
        self.running = True
        threading.Thread(target=self.monitor_traps, daemon=True).start()

    def stop_all(self):
        print("[WATCHDOG] Stopping all traps...")
        self.running = False
        for trap_name in list(self.trap_processes):
            self.stop_trap(trap_name)

    def get_trap_status_summary(self):
        status = {}
        for trap_name, proc in self.trap_processes.items():
            status[trap_name] = {
                "active": proc.poll() is None
            }
        return status

    def is_running(self):
        return self.running

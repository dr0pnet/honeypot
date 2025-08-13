import os
import sys
import json
import socket
import datetime
import subprocess
import threading
import signal

MODULE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, ".."))
sys.path.append(PROJECT_ROOT)

from utils.alert_handler import trigger_alert

# ─── Configuration ─────────────────────────────────────────────────────────────
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config.json")
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

host = config.get("ftp_host", "0.0.0.0")
port = config.get("ftp_port", 2121)

# Ensure logs directory exists
FTP_LOG_DIR = os.path.join(PROJECT_ROOT, "logs", "ftp_trap")
os.makedirs(FTP_LOG_DIR, exist_ok=True)
FTP_LOG_FILE = os.path.join(FTP_LOG_DIR, "ftp_trap.log")

PYTHON_CMD = sys.executable

# ─── Signal Handling for Graceful Shutdown ─────────────────────────────────────
child_processes = []
server_socket = None

def handle_termination(signum, frame):
    print("[INFO] Shutting down FTP trap...")
    if server_socket:
        server_socket.close()
    for p in child_processes:
        try:
            p.terminate()
        except Exception:
            pass
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGTERM, handle_termination)
if sys.platform == "win32":
    signal.signal(signal.SIGBREAK, handle_termination)

# ─── Handle Client Connections ─────────────────────────────────────────────────
def handle_client(conn, addr):
    attacker_ip = addr[0]
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"[+] FTP connection from {attacker_ip}")
    with open(FTP_LOG_FILE, "a") as log:
        log.write(f"[{timestamp}] FTP connection from {attacker_ip}\n")

    try:
        conn.send(b'220 FTP server ready\r\n')
    except Exception as e:
        print(f"[DEBUG] Failed to send FTP banner: {e}")
    finally:
        conn.close()

    # Trigger passive intel modules
    try:
        ip_geo_path = os.path.join(PROJECT_ROOT, "modules", "ip_geo.py")
        reverse_dns_path = os.path.join(PROJECT_ROOT, "modules", "reverse_dns.py")
        passive_scan_path = os.path.join(PROJECT_ROOT, "modules", "passive_scan.py")

        for script in [ip_geo_path, reverse_dns_path, passive_scan_path]:
            p = subprocess.Popen([PYTHON_CMD, script, attacker_ip, FTP_LOG_DIR], cwd=PROJECT_ROOT)
            child_processes.append(p)

        trigger_alert(f"FTP trap hit from {attacker_ip}")
    except Exception as e:
        print(f"[Intel ERROR] Failed to run passive modules: {e}")

# ─── Run FTP Trap ──────────────────────────────────────────────────────────────
def run():
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"[dr0pnet] FTP trap listening on {host}:{port}...")
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except Exception as e:
        print(f"[Trap ERROR] {e}")
    finally:
        if server_socket:
            server_socket.close()
        print(f"[Trap] Port {port} closed.")

# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        handle_termination(None, None)
import socket
import threading
import os
import datetime
import sys
import time

# Path fix to access scan_ids alert logic
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.append(project_root)

from modules.scan_ids import log_event

FAKE_PORTS = [4444, 5555, 6666, 7777, 8888, 9999]
sockets = []

def fake_listener(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(5)
        sockets.append(sock)
        print(f"[FAKE PORT] Listening on port {port}")
        while True:
            try:
                conn, addr = sock.accept()
                ip = addr[0]
                log_event(ip, port, "Decoy connection")
                conn.close()
            except Exception:
                continue
    except Exception as e:
        print(f"[ERROR] Could not bind decoy port {port}: {e}")

def start_all_decoys():
    for port in FAKE_PORTS:
        threading.Thread(target=fake_listener, args=(port,), daemon=True).start()

def run_decoy_trap():
    print("[DECOY] Starting decoy trap")
    start_all_decoys()
    while True:
        time.sleep(60)

# 👇 Ensure this is at the bottom
if __name__ == "__main__":
    run_decoy_trap()

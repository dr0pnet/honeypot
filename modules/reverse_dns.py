import os
import sys
import socket
import datetime

# Set project paths
MODULE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, ".."))
sys.path.append(PROJECT_ROOT)

# Get IP and log directory
ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
if len(sys.argv) < 3:
    print("[ERROR] Log directory not provided. Exiting.")
    sys.exit(1)

log_dir = sys.argv[2]
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "reverse_dns.log")


# Timestamp
ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Perform reverse DNS lookup
try:
    hostname = socket.gethostbyaddr(ip)[0]
    log_line = f"[{ts}] Reverse DNS for {ip}: {hostname}"
except Exception as e:
    log_line = f"[{ts}] Reverse DNS for {ip} failed: {str(e)}"

# Write log
try:
    with open(log_file, "a") as f:
        f.write(log_line + "\n")
except Exception as e:
    print(f"[!] Failed to write to log file: {e}")

print(log_line)

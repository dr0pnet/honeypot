import os
import sys
import socket
import datetime

# Resolve paths
MODULE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, ".."))
sys.path.append(PROJECT_ROOT)

# Input params
ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
if len(sys.argv) < 3:
    print("[ERROR] Log directory not provided. Exiting.")
    sys.exit(1)

log_dir = sys.argv[2]
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "passive_scan.log")


# Timestamp
ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Ports to check
ports = [21, 22, 23, 80, 443, 8080, 3306, 3389]
results = []

for port in ports:
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        results.append(f"  Port {port}: OPEN — Banner: {banner}")
        s.close()
    except:
        results.append(f"  Port {port}: Closed")

# Final log entry
log_line = f"[{ts}] Passive scan for {ip}:\n" + "\n".join(results)

# Write to provided log dir only
try:
    with open(log_file, "a") as f:
        f.write(log_line + "\n")
except Exception as e:
    print(f"[!] Failed to write to log file: {e}")

print(log_line)

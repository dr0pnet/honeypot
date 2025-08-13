import os
import sys
import requests
import datetime

# Define paths
MODULE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, ".."))
sys.path.append(PROJECT_ROOT)

# Input IP and log directory
ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
if len(sys.argv) < 3:
    print("[ERROR] Log directory not provided. Exiting.")
    sys.exit(1)

log_dir = sys.argv[2]
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "ip_geo.log")


# Ensure log directory exists
os.makedirs(log_dir, exist_ok=True)

# Timestamp
ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Perform GeoIP lookup
try:
    res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
    if res.status_code == 200:
        data = res.json()
        country = data.get("country", "N/A")
        city = data.get("city", "N/A")
        org = data.get("org", "N/A")
        log_line = f"[{ts}] Geo for {ip}: {country}, {city} ({org})"
    else:
        log_line = f"[{ts}] Failed GeoIP lookup for {ip}: HTTP {res.status_code}"
except Exception as e:
    log_line = f"[{ts}] Geo for {ip} failed: {str(e)}"

# Write log
try:
    with open(log_file, "a") as log:
        log.write(log_line + "\n")
except Exception as e:
    print(f"[!] Failed to write to log file: {e}")

print(log_line)

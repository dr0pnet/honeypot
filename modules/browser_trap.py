import os, sys, json, datetime, subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import signal
import time
import argparse
import threading

# Paths
MODULE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, ".."))
sys.path.append(PROJECT_ROOT)

from utils.alert_handler import trigger_alert

# Config + Logging
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config.json")
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
except (FileNotFoundError, json.JSONDecodeError) as e:
    print(f"[ERROR] Failed to load config: {e}")
    sys.exit(1)

host = config.get("browser_host", "0.0.0.0")
port = config.get("browser_port", 8080)

LOG_DIR = os.path.join(PROJECT_ROOT, "logs", "browser_trap")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "browser_trap.log")

PYTHON_CMD = sys.executable
stop_event = threading.Event()

# Termination handler
def handle_termination(signum, frame):
    print("[INFO] Browser trap shutting down...")
    stop_event.set()
    server.shutdown()
    sys.exit(0)

# ──────────────────────────────────────────────
# Trap Handler
# ──────────────────────────────────────────────
class LoginTrapHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[DEBUG] Received GET request for {self.path}")
        
        if self.path == "/static/favicon.ico":
            try:
                icon_path = os.path.join(PROJECT_ROOT, "static", "favicon.ico")
                with open(icon_path, "rb") as f:
                    self.send_response(200)
                    self.send_header("Content-Type", "image/x-icon")
                    self.end_headers()
                    self.wfile.write(f.read())
                    print("[DEBUG] Served favicon.ico")
            except Exception as e:
                self.send_response(404)
                self.end_headers()
                print(f"[ERROR] Could not serve favicon.ico: {e}")
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
<html>
<head>
  <meta charset="UTF-8">
  <title>Login</title>
  <link rel="icon" href="/static/favicon.ico" type="image/x-icon">
</head>
<body style="background:#0a0a0a;color:#66B2FF;font-family:Helvetica;text-align:center;padding-top:20vh;">
    <div style="display:inline-block;padding:20px;border:2px solid #66B2FF;border-radius:10px;background:#111;">
        <h2>Admin Login</h2>
        <form method="POST">
            Username: <input name="username"><br><br>
            Password: <input name="password" type="password"><br><br>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
""")

    def do_POST(self):
        print("[DEBUG] Received POST request")
        ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        print(f"[DEBUG] POST request from {ip} — User-Agent: {user_agent}")

        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length).decode()
        data = parse_qs(post_data)
        print(f"[DEBUG] POST data: {post_data}")

        username = data.get("username", [""])[0]
        password = data.get("password", [""])[0]
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            with open(LOG_FILE, "a") as f:
                f.write(f"[{ts}] IP: {ip} — Username: {username} | Password: {password}\n")
        except IOError as e:
            print(f"[ERROR] Failed to write to log file: {e}")

        trigger_alert(f"Browser trap hit from {ip}")

        intel_scripts = ["ip_geo.py", "reverse_dns.py", "passive_scan.py"]
        intel_log_dir = os.path.join(PROJECT_ROOT, "logs", "browser_trap")
        os.makedirs(intel_log_dir, exist_ok=True)

        for script in intel_scripts:
            try:
                script_path = os.path.join(PROJECT_ROOT, "modules", script)
                log_file_name = f"{script.replace('.py', '')}.log"
                log_path = os.path.join(intel_log_dir, log_file_name)
                with open(log_path, "a") as outfile:
                    subprocess.Popen([PYTHON_CMD, script_path, ip, intel_log_dir], cwd=PROJECT_ROOT)
                print(f"[INFO] Launched {script} → {log_path}")
            except Exception as e:
                print(f"[ERROR] Failed to launch {script}: {e}")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
<html>
<head>
  <meta charset="UTF-8">
  <title>Access Denied</title>
  <link rel="icon" href="/static/favicon.ico" type="image/x-icon">
</head>
<body style="background:#0a0a0a;color:#FF1493;font-family:Helvetica;text-align:center;padding-top:20vh;">
    <div style="display:inline-block;padding:20px;border:2px solid #66B2FF;border-radius:10px;background:#111;">
        <h2>Access Denied</h2>
        <p>Invalid credentials.</p>
    </div>
</body>
</html>
""")

# ──────────────────────────────────────────────
# Main Entrypoint
# ──────────────────────────────────────────────
def main():
    global server
    parser = argparse.ArgumentParser(description="Browser Trap Module")
    parser.add_argument("attacker_ip", nargs="?", default="0.0.0.0", help="IP address of the attacker (default: 0.0.0.0)")
    args = parser.parse_args()

    print(f"[DEBUG] Parsed attacker IP: {args.attacker_ip}")
    print(f"[DEBUG] Starting HTTP server on {host}:{port}")

    signal.signal(signal.SIGTERM, handle_termination)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, handle_termination)

    try:
        server = HTTPServer((host, port), LoginTrapHandler)
        print(f"[dr0pnet] login trap active at http://{host}:{port}")
        server.serve_forever()
    except OSError as e:
        print(f"[ERROR] Failed to bind to {host}:{port} — {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        handle_termination(None, None)

if __name__ == "__main__":
    main()

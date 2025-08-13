from flask import Flask, jsonify, Response, request, redirect
import os
import json
import threading
from datetime import datetime, timedelta
import zipfile
from watchdog import TrapWatchdog
watchdog = TrapWatchdog()
import glob

app = Flask(__name__)

# Determine base directory reliably
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")

@app.route('/api/trap_status')
def trap_status_from_alerts():
    alerts_path = os.path.join(LOGS_DIR, "alerts.json")
    traps = []
    trap_names = ["SSH Trap", "FTP Trap", "Fake Wallet", "Scan IDS", "File Trap", "Browser Trap", "ARP Monitor"]
    now = datetime.now()

    # Load alerts
    try:
        with open(alerts_path, "r") as f:
            alerts = json.load(f)
    except:
        alerts = []

    # Build trap status
    for trap in trap_names:
        recent_alerts = [
            a for a in alerts
            if a.get("trap") == trap and
               "timestamp" in a and
               (now - datetime.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S")) <= timedelta(minutes=10)
        ]
        is_active = bool(recent_alerts)
        last_triggered = recent_alerts[-1]["timestamp"] if is_active else "Never"

        traps.append({
            "name": trap,
            "active": is_active,
            "last_triggered": last_triggered
        })

    return jsonify(traps)


@app.route('/api/terminal_output')
def terminal_output():
    path = os.path.join(LOGS_DIR, "terminal.log")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-100:]
                return Response("".join(lines), mimetype="text/plain")
        except Exception as e:
            return Response(f"[ERROR] Could not read terminal log: {e}", mimetype="text/plain")
    return Response("[INFO] No terminal output found.", mimetype="text/plain")



@app.route('/api/alerts')
def get_alerts():
    alert_log_path = os.path.join(LOGS_DIR, "alerts.json")
    if os.path.exists(alert_log_path):
        with open(alert_log_path, "r") as f:
            try:
                alerts = json.load(f)
                return jsonify(alerts)
            except Exception as e:
                print(f"[ERROR] Failed to parse alerts.json: {e}")
                return jsonify([])
    return jsonify([])



@app.route('/api/trap_log')
def get_trap_log():
    logs_by_file = {}

    # Recursively find all .log files inside logs/
    for root, _, files in os.walk(LOGS_DIR):
        for file in files:
            if file.endswith(".log"):
                full_path = os.path.join(root, file)
                rel_name = os.path.relpath(full_path, LOGS_DIR)

                try:
                    with open(full_path, "r") as f:
                        lines = f.readlines()
                        logs_by_file[rel_name] = lines[-20:]  # last 20 lines
                except Exception as e:
                    print(f"[ERROR] Failed to read {rel_name}: {e}")
                    logs_by_file[rel_name] = [f"[ERROR] Could not read log"]

    return jsonify(logs_by_file)





@app.route('/download_logs')
def download_logs():
    zip_path = os.path.join(LOGS_DIR, "logs.zip")
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for root, _, files in os.walk(LOGS_DIR):
            for file in files:
                if file != "logs.zip":
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, LOGS_DIR)
                    zipf.write(full_path, arcname)
    return send_file(zip_path, as_attachment=True)

@app.route('/')
def index():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>DR0PNET Monitor</title>
    <link rel="icon" href="/static/favicon.ico" type="image/x-icon">
    <style>
        body {
            background-color: #0a0a0a;
            color: #00ffcc;
            font-family: monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .terminal {
            background-color: #111;
            border: 2px solid #00ffcc;
            padding: 30px 40px;
            border-radius: 10px;
            box-shadow: 0 0 15px #00ffcc;
            min-width: 600px;
            font-size: 18px;
        }
        .line {
            margin: 10px 0;
        }
        .cursor {
            display: inline-block;
            width: 10px;
            height: 18px;
            background-color: #00ffcc;
            margin-left: 5px;
            animation: blink 0.8s infinite;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0; }
        }
    </style>
</head>
<body>
    <div class="terminal">
        <div class="line">admin@DR0PNET:~$ Honeypot Mobile API Active<span class="cursor"></span></div>
    </div>
</body>
</html>
"""

def start_api():
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(os.path.join(LOGS_DIR, "honeypot.log"), "a") as f:
        f.write(f"[{datetime.now()}] Honeypot API initialized.\n")

    # Don't auto-run app.run() unless this file is run directly
    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=5050, debug=False, use_reloader=False)



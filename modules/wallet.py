# modules/wallet.py

from flask import Flask, render_template, request, send_file, jsonify
import requests
import datetime
import os
import subprocess
import sys
import threading
import json

PYTHON_CMD = sys.executable

# Set project root relative to this module (once!)
MODULE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, ".."))

# Setup wallet trap log directory
INTEL_LOG_DIR = os.path.join(PROJECT_ROOT, "logs", "wallet_trap")
os.makedirs(INTEL_LOG_DIR, exist_ok=True)
WALLET_LOG_FILE = os.path.join(INTEL_LOG_DIR, "wallet.log")

# Add project root to sys.path
sys.path.append(PROJECT_ROOT)


from utils.alert_handler import trigger_alert

wallet_app = Flask(__name__, template_folder=os.path.join(PROJECT_ROOT, "templates"),
                   static_folder=os.path.join(PROJECT_ROOT, "static"))


def log_wallet_event(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(WALLET_LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
    print(f"[{timestamp}] {msg}")


def run_intel_modules(ip):
    try:
        for script in ["ip_geo.py", "reverse_dns.py", "passive_scan.py"]:
            path = os.path.join(PROJECT_ROOT, "modules", script)
            subprocess.Popen([PYTHON_CMD, path, ip, INTEL_LOG_DIR], cwd=PROJECT_ROOT)
    except Exception as e:
        print(f"[Intel ERROR] {e}")


@wallet_app.route('/')
def home():
    return render_template('wallet.html')


@wallet_app.route('/import', methods=['POST'])
def import_wallet():
    seed = request.form.get('seed')
    msg = f"Seed phrase captured: {seed}"
    trigger_alert(f"[Wallet Trap] {msg}")
    log_wallet_event(msg)
    run_intel_modules(request.remote_addr)
    return render_template('wallet.html')


@wallet_app.route('/export')
def export_seed():
    msg = "Seed export triggered"
    trigger_alert(f"[Wallet Trap] {msg}")
    log_wallet_event(msg)
    run_intel_modules(request.remote_addr)
    return send_file(os.path.join(PROJECT_ROOT, "static", "keys_seed.txt"), as_attachment=True)


@wallet_app.route('/api/prices')
def get_prices():
    try:
        res = requests.get("https://api.coingecko.com/api/v3/simple/price",
                           params={"ids": "bitcoin,ethereum,ripple", "vs_currencies": "usd"},
                           timeout=5)
        return jsonify(res.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def run():
    print("[dr0pnet] Wallet trap running on port 8081...")
    wallet_app.run(host="0.0.0.0", port=8081, debug=False, use_reloader=False)


if __name__ == "__main__":
    run()

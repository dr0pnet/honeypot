import scapy.all as scapy
import datetime
import os
import json
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox

# ─── Configuration ──────────────────────────────────────────────────
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.append(project_root)

from utils.alert_handler import trigger_alert
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_DIR = os.path.join(PROJECT_ROOT, "logs", "arp_monitor")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "arp_monitor.log")
BLOCKED_MACS_FILE = os.path.join(LOG_DIR, "blocked_macs.json")
INTEL_LOG_DIR = LOG_FILE  # reused
PYTHON_CMD = sys.executable

arp_table = {}

# ─── Load Blocked MACs ──────────────────────────────────

def load_blocked_macs():
    if os.path.exists(BLOCKED_MACS_FILE):
        with open(BLOCKED_MACS_FILE, "r") as f:
            return set(json.load(f))
    return set()

blocked_macs = load_blocked_macs()

# ─── Load Blocked IPs ──────────────────────────────────

BLOCKED_IPS_FILE = os.path.join(PROJECT_ROOT, "config", "blocked_ips.json")
if os.path.exists(BLOCKED_IPS_FILE):
    with open(BLOCKED_IPS_FILE, "r") as f:
        blocked_ips = set(json.load(f))
else:
    blocked_ips = set()



# ─── Intel Modules Trigger ──────────────────────────────

def run_intel_modules(event_text):
    ip_match = next((part for part in event_text.split() if part.count(".") == 3), None)
    if not ip_match:
        return
    try:
        ip_geo_path = os.path.join(PROJECT_ROOT, "modules", "ip_geo.py")
        reverse_dns_path = os.path.join(PROJECT_ROOT, "modules", "reverse_dns.py")
        passive_scan_path = os.path.join(PROJECT_ROOT, "modules", "passive_scan.py")

        for script in [ip_geo_path, reverse_dns_path, passive_scan_path]:
            subprocess.Popen([PYTHON_CMD, script, ip_match, LOG_DIR], cwd=PROJECT_ROOT)
        print(f"[INFO] Intel modules launched for {ip_match}")
    except Exception as e:
        print(f"[Intel ERROR] {e}")

# ─── Popup Alert ───────────────────────────────────

def show_popup(message):
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("dr0pnet Alert", message)
        root.destroy()
    except Exception as e:
        print(f"[Popup Error] {e}")

# ─── Logging Utility ──────────────────────────────

def log_event(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {msg}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_line)
    print(log_line.strip())
    trigger_alert(f"[ARP Monitor] {msg}")
    run_intel_modules(msg)
    show_popup(f"[ARP Monitor] {msg}")

# ─── Detection Logic ──────────────────────────────

def detect_arp(pkt):
    if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:  # ARP reply
        ip = pkt[scapy.ARP].psrc
        mac = pkt[scapy.ARP].hwsrc

        if ip in blocked_ips:
            log_event(f"BLOCKED IP: {ip} attempted access — ignored")
            return

        # 1. Suspicious MAC change
        if ip in arp_table and arp_table[ip] != mac:
            log_event(f"SUSPICIOUS ARP: IP {ip} changed from {arp_table[ip]} to {mac}")

        arp_table[ip] = mac

        # 2. Blocked MAC address detected
        if mac in blocked_macs:
            log_event(f"BLOCKED MAC: {mac} attempted IP spoofing ({ip})")

        # 3. Spoofing signature: unsolicited ARP reply
        if pkt[scapy.ARP].pdst != ip and pkt[scapy.ARP].hwdst == "00:00:00:00:00:00":
            log_event(f"ARP SPOOFING PATTERN: unsolicited reply from {mac} claiming {ip}")

# ─── Module Entry ──────────────────────────────

if __name__ == "__main__":
    print("[dr0pnet] ARP Monitor module running")
    try:
        scapy.sniff(store=False, prn=detect_arp, filter="arp")
    except KeyboardInterrupt:
        print("\n[INFO] ARP monitor stopped.")

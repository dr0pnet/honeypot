import scapy.all as scapy
import datetime
import os
import sys
import subprocess
import json
from tkinter import messagebox, Tk

# ─── Configuration ──────────────────────────────────────────────
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.append(project_root)

from utils.alert_handler import trigger_alert

MONITORED_PORTS = [4444, 5555, 6666, 7777, 8888, 9999]
LOG_DIR = os.path.join(project_root, "logs", "scan_ids")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "scan_ids.log")
INTEL_LOG_DIR = LOG_FILE
MODULES_DIR = os.path.join(project_root, "modules")
INTEL_SCRIPTS = ["ip_geo.py", "reverse_dns.py", "passive_scan.py"]
PYTHON_CMD = sys.executable

alerted_ips = {}

# ─── Load Blocklists ─────────────────────────────────────────────
BLOCKED_IPS_FILE = os.path.join(project_root, "config", "blocked_ips.json")
if os.path.exists(BLOCKED_IPS_FILE):
    with open(BLOCKED_IPS_FILE, "r") as f:
        blocked_ips = set(json.load(f))
else:
    blocked_ips = set()

BLOCKED_MACS_FILE = os.path.join(project_root, "logs", "arp_monitor", "blocked_macs.json")
if os.path.exists(BLOCKED_MACS_FILE):
    with open(BLOCKED_MACS_FILE, "r") as f:
        blocked_macs = set(json.load(f))
else:
    blocked_macs = set()

# ─── Popup ─────────────────────────────────────────────────────
def show_popup(message):
    try:
        root = Tk()
        root.withdraw()
        messagebox.showinfo("dr0pnet Alert", message)
        root.destroy()
    except Exception as e:
        print(f"[Popup Error] {e}")

# ─── Logging + Intel + Alert ───────────────────────────────────
def log_event(ip, port, scan_type):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {scan_type} detected from {ip} on port {port}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log_line)
    print(log_line.strip())

    key = f"{ip}:{port}"
    if key not in alerted_ips or (datetime.datetime.now() - alerted_ips[key]).seconds > 300:
        trigger_alert(f"Scan IDS: {scan_type} on port {port} from {ip}")
        show_popup(f"Scan IDS: {scan_type} on port {port} from {ip}")
        alerted_ips[key] = datetime.datetime.now()

        for script in INTEL_SCRIPTS:
            try:
                subprocess.Popen([PYTHON_CMD, os.path.join(MODULES_DIR, script), ip, INTEL_LOG_DIR], cwd=project_root)
                print(f"[INFO] Launched {script} for {ip}")
            except Exception as e:
                print(f"[ERROR] Failed to launch {script}: {e}")

# ─── Packet Detection ──────────────────────────────────────────
def detect_scan(pkt):
    if pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.TCP):
        ip_src = pkt[scapy.IP].src
        mac_src = pkt[scapy.Ether].src if pkt.haslayer(scapy.Ether) else None

        if ip_src in blocked_ips:
            print(f"[SCAN IDS] Blocked IP {ip_src} — ignoring")
            return

        if mac_src and mac_src in blocked_macs:
            print(f"[SCAN IDS] Blocked MAC {mac_src} — ignoring")
            return

        dport = pkt[scapy.TCP].dport
        flags = pkt[scapy.TCP].flags

        if dport in MONITORED_PORTS:
            print(f"[DEBUG] Hit monitored port {dport} from {ip_src} with flags: {flags}")
            if flags & 0x02:
                log_event(ip_src, dport, "SYN scan")
            elif flags == 0x00:
                log_event(ip_src, dport, "NULL scan")
            elif flags == 0x29:
                log_event(ip_src, dport, "XMAS scan")
            elif flags == 0x01:
                log_event(ip_src, dport, "FIN scan")

# ─── Main ──────────────────────────────────────────────────────
def start_scan_ids():
    print("[dr0pnet] Scan IDS Monitoring ports for scan attempts")
    scapy.sniff(filter="tcp", prn=detect_scan, store=0)

if __name__ == "__main__":
    start_scan_ids()


import os
import sys

# ─── Add local site-packages ───────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SITE_PACKAGES = os.path.join(BASE_DIR, "site-packages")
if os.path.isdir(SITE_PACKAGES) and SITE_PACKAGES not in sys.path:
    sys.path.insert(0, SITE_PACKAGES)


import tkinter as tk
from tkinter import scrolledtext
import platform
import json
import subprocess
import threading
import signal
import time
import datetime
import requests
from flask import Flask, render_template, request, send_file, redirect
from utils.alert_handler import trigger_alert
import zipfile
import psutil
from watchdog import TrapWatchdog
watchdog = TrapWatchdog()
from dr0pnet_api import app as api_app


import os
import sys

# ─── Admin / Root Privilege Check ───────────────────────────────
def check_admin_privileges():
    if os.name == "nt":
        # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[ERROR] This script must be run as Administrator.")
                print("Right-click the executable and select 'Run as administrator'.")
                input("Press Enter to exit...")
                sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Admin check failed: {e}")
            input("Press Enter to exit...")
            sys.exit(1)

    else:
        # Linux/macOS
        if os.geteuid() != 0:
            print("[ERROR] This script must be run as root (sudo).")
            print("Try running with: sudo python3 your_script.py")
            sys.exit(1)

            

# Run the check immediately
check_admin_privileges()


class DualLogger:
    def __init__(self, filename):
        self.terminal = sys.__stdout__
        self.log = open(filename, "a", buffering=1, encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

LOGS_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

sys.stdout = DualLogger(os.path.join(LOGS_DIR, "terminal.log"))
sys.stderr = sys.stdout


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "."))) # Ensure the current directory is in the path

def show_readme_popup():

    ascii_banner = r"""

  //============================\\  
 // ||101010101010101010101010|| \\ 
||  ||010101010100101010101010||  ||
||  ||101010101010101010101001||  ||
||  ||101001010101010101010100||  ||
||  ||010101010010101010101001||  ||
||  ||101010100101010100101010||  ||
||  ||010101001010101001010010||  ||
 \\ ||001010101010101010101011|| // 
  \\============================//  
             ||     /|| 1    0     1
1    0    1  ||    //||             
             ||   // || 0  1  0  1  
  0   1      ||  //  ||             
             || //   || 0    1  0   
0   1   1 0  || \\   ||             
             ||  \\  || 1   0    1  
1   0    1   ||   \\ ||             
             ||    \\|| 0  0  1    0
0    1   0   ||======||             
            //        \\    0    1  
0  1  0 1  ||          ||           
           |============|  0   1  0 

____________ ___________ _   _  _____ _____ 
|  _  \ ___ \  _  | ___ \ \ | ||  ___|_   _|
| | | | |_/ / |/' | |_/ /  \| || |__   | |  
| | | |    /|  /| |  __/| . ` ||  __|  | |  
| |/ /| |\ \\ |_/ / |   | |\  || |___  | |  
|___/ \_| \_|\___/\_|   \_| \_/\____/  \_/  
                                            
                                            

    """

    readme_text = f"""{ascii_banner}

Welcome to the DR0PNET Honeypot 

An advanced, user-friendly deception and intrusion detection platform. DR0PNET is a next-generation honeypot 
platform designed for home labs, research environments, or small networks. It simulates vulnerable services (like SSH, FTP, crypto wallets) 
to attract and analyze unauthorized access attempts. With advanced logging, alerting, blocking and trap modules, it offers both visibility and deception in one package.

## Features
-----------
- Modular trap system (SSH, FTP, File Upload, Crypto Wallet, ARP Monitor, Browser Exploits, and more)
- Fake crypto wallet trap with input and export seed phrase alerts
- Subprocess based execution for trap isolation
- Threaded watchdog system auto restarts failing modules
- Web dashboard with live trap status and logs
- Android / iOS Flutter app to view logs and live alerts remotely
- Real time alerts: desktop popups, mobile push notifications
- Passive scan detection, GeoIP, reverse DNS 
- IP and MAC Blocking

## Modules
----------
Each trap is self-contained and runs in its own subprocess. Major modules include:

| Module Name      | Description                       | Port                  |
|------------------|-----------------------------------|-----------------------|
| SSH Trap         | Simulated SSH login banner        | 2222                  |
| FTP Trap         | Fake file services                | 2121                  |
| Fake Wallet Trap | Crypto wallet with trap buttons   | 8081                  |
| ARP Monitor      | Detects spoofing or rogue devices | Running in Background |
| Browser Trap     | JS-based fingerprinting           | 8080                  |
| File Upload Trap | Captures uploaded payloads        | 9090                  |
| Scan IDS         | Detects SYN, XMAS, NULL scans     | Running in Background |
| Fake Ports       | 4444, 5555, 6666, 7777, 8888, 9999| Running in Background |

## Alerts / Logging
-------------------
- Tkinter popup on desktop
- Mobile push notifications
- Log files in /logs
- Alert files in /logs
- Intel files per trap /*.logs
- Blocked IP and MAC addresses in /logs

## Requirements
---------------

| Component               | Purpose                          | 
|-------------------------|----------------------------------|
| Python 3.6+             | Main interpreter                 |
| Flask                   | Flask Server                     |
| pip                     | Install helper (optional)        | 
| libpcap-dev (Linux)     | Raw packet sniffing for Scapy    | 
| Npcap (Windows)         | Raw packet sniffing for Scapy    |
| python3-tk              | Tkinter pop-up alerts            | 
| tcpdump (opt.)          | Useful for debugging scans       | 
| net-tools (opt.)        | Network utilities like `ifconfig`|


## Troubleshooting
------------------
- Make sure you extracted the full folder (don’t run from inside ZIP)
- Firewall prompts may appear — allow all access for local communication
- The TrapWatchdog class uses Python threads to monitor and restart modules that crash unexpectedly. It ensures all traps are always running unless intentionally stopped.
- Make sure site-packages are being used per OS, if not install them manually.


* * * * * * * * * * How to Use * * * * * * * * * *

## Launch the honeypot
----------------------
    - Run as administrator or root
    - Windows: Double-click Launcher.exe or python3 dr0pnet-honeypot.py 
    - Linux/macOS: Run: ./launcher.sh or python3 dr0pnet-honeypot.py 

## Open your browser and go to
------------------------------
    - http://localhost:5000
    - http://localhost:5050 is mobile api

## From there, you can
----------------------
    - Execute Honeypot ( Once executed, the honeypot will run in the background, with all traps and modules active. )
    - Change port settings ( /config.json )
    - Download Logs .Zip ( All logs are stored in the logs/ directory. )
    - Alerts ( Push notifications to your mobile device, and a desktop popup. )
    - Check for Updates (Gitub)
    - Help Window ( Currently, this is the README file. )

## Test honeypot traps
----------------------
    - File Upload test : curl -X POST --data-binary "@C:<directory-to-a-file>" http://<host-IP-running-honeypot>:9090
    - Scan IDS test: nmap -Pn -sT <host-IP-running-honeypot>
    - FTP test: ftp open <host-IP-running-honeypot> 2121
    - SSH test: ssh -p 2222 admin@<host-IP-running-honeypot>
    - ARP Monitoring test: python3 arp_test_trigger.py
    - Browser login test: http://localhost:8080
    - Cryptocurrency Wallet test: http://localhost:8081
    - Decoy Ports: 4444, 5555, 6666, 7777, 8888, 9999

## Mobile Configuration
-----------------------
    - Go to settings enter http://<honeypot-pc-ip>:5050
    - Hit save and enable the Auto-refresh switch to see current updates every 10 sec.

## Support
----------
    - For help, bug reports, or suggestions, contact:
    - Email: dr0pnethp@gmail.com 
    - Twitter: DR0PNET @dr0pnetHoneyPot
 
* * * * * * * * * * DR0PNET Honeypot Privacy Disclaimer * * * * * * * * * *

Last Updated
June 1, 2025

What We Collect:

This system may collect and log the following data from all incoming connections:
- IP address and associated metadata (GeoIP, ISP, etc.)
- Timestamps of activity
- User agent and HTTP headers
- Entered commands or credentials
- Uploaded files or payloads
- Behavioral patterns and interactions with simulated services

Why We Collect It:

The data collected is used solely for the following purposes:
- Cybersecurity research and education
- Threat detection and behavior analysis
- Improving the effectiveness of the honeypot system
- Alerting administrators of suspicious activity

Data Storage and Retention:

All data is stored locally and is not shared with third parties. Logs may be exported by the system owner for
private analysis or reporting purposes. No personal information is collected or processed beyond what is
transmitted by the connecting system.
Notice to Unauthorized Users
This system is not intended for public or authorized use. All access attempts are monitored and logged. Any
interaction with this system may be reported or disclosed in the event of malicious or illegal behavior.


* * * * * * * * * * DR0PNET Honeypot Privacy Disclaimer * * * * * * * * * * 


This application may optionally integrate with trusted APIs (such as GeoIP services) to enhance visibility into
the origin of unauthorized connections. No personal user data is sent to these services-only IP addresses.

Your Consent: 

By interacting with this application, you consent to monitoring and logging as described above. If you do not
consent, you should discontinue use immediately.


* * * * * * * * * * License * * * * * * * * * * 


DR0PNET Commercial License
Copyright (c) 2025 Joshua Marr

This software is licensed, not sold. Unauthorized distribution, copying, or reverse engineering is prohibited.

You may:
- Install and use the Software on personal or organizational devices

You may not:
- Modify, reverse-engineer, or redistribute the Software without written permission
- Use the Software to harm others or violate laws

This software is provided "as is" without warranty. The developer is not responsible for any damage caused by use or misuse of the software.

By installing or using this software, you agree to these terms.


* * * * * * * * * * Terms of Use  * * * * * * * * * * 


Terms of Use for DR0PNET Honeypot
Effective Date: June 2025

Please read these Terms of Use ("Terms") carefully before using the DR0PNET Honeypot software application ("Software") developed by Joshua Marr ("Developer").

1. Acceptance of Terms
By downloading, installing, or using the Software, you agree to be bound by these Terms. If you do not agree to these Terms, do not install or use the Software.

2. License Grant
You are granted a non-transferable, non-exclusive license to use the Software for personal, research, educational, or commercial use in accordance with the terms stated herein.

3. Restrictions
You may not:
- Reverse-engineer, decompile, or disassemble the Software.
- Modify or create derivative works based on the Software without express permission.
- Resell, sublicense, or redistribute the Software or its components.
- Use the Software for any unlawful or malicious purpose.

4. Ownership
All intellectual property rights in the Software are owned by the Developer. These Terms do not grant you any ownership interest in the Software.

5. Updates
The Developer may provide updates to the Software. These Terms apply to all updates unless otherwise specified.

6. Disclaimer of Warranty
The Software is provided “as is” without warranties of any kind. The Developer does not guarantee that the Software will be error-free, secure, or operate without interruption.

7. Limitation of Liability
In no event shall the Developer be liable for any direct, indirect, incidental, special, or consequential damages arising out of the use or inability to use the Software.

8. Termination
These Terms are effective until terminated. Your rights under these Terms will terminate automatically if you fail to comply with them.

9. Governing Law
These Terms shall be governed by and construed in accordance with the laws of the United States, without regard to its conflict of law provisions.

10. Contact
For questions regarding these Terms, please contact: dr0pnethp@gmail.com

By using the Software, you acknowledge that you have read, understood, and agreed to these Terms of Use.


© 2025 Joshua Marr. All rights reserved.  
“DR0PNET” is a trademark™ of Joshua Marr. Trademark registration pending.


"""

    window = tk.Tk()
    window.title("Welcome to DR0PNET Honeypot")
    window.configure(bg="#111")
    window.lift()
    window.attributes('-topmost', True)

    # Fullscreen cross-platform
   # if platform.system() == "Windows":
       # window.state("zoomed")
   # else:
    #    window.attributes('-zoomed', True)

    window.geometry("900x900")  # Or your preferred size


    # Text Area
    text_area = scrolledtext.ScrolledText(
        window, wrap=tk.WORD, font=("Consolas", 11), bg="#111", fg="#FF1493", insertbackground="black"
    )
    text_area.insert(tk.INSERT, readme_text)
    text_area.configure(state='disabled')
    text_area.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

    # Button
    ok_button = tk.Button(
        window,
        text="Launch Honeypot",
        command=window.destroy,
        bg="#66B2FF",
        fg="black",
        font=("Helvetica", 12, "bold")
    )
    ok_button.pack(pady=10)

    window.mainloop()


# Start the Flask API in a background thread / mobile app

def run_api():
    from waitress import serve
    serve(api_app, host="0.0.0.0", port=5050)

api_thread = threading.Thread(target=run_api)
api_thread.daemon = True
api_thread.start()
print("[+] DR0PNET Mobile API Running with Waitress (production WSGI server) http://localhost:5050")


# Determine the base path for bundled files
if getattr(sys, 'frozen', False):  # Check if running as a PyInstaller executable
    base_path = sys._MEIPASS
else:
    base_path = os.path.abspath(os.path.dirname(__file__))

app = Flask( # Create Flask app instance
    __name__,
    template_folder=os.path.join(base_path, "templates"),
    static_folder=os.path.join(base_path, "static")
)

os.makedirs("data", exist_ok=True) # Ensure the data directory exists

def load_settings(): # Load alert settings from JSON file
    path = os.path.join("data", "alert_settings.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}

def save_settings(data):
    path = os.path.join("data", "alert_settings.json")
    os.makedirs("data", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
WATCHDOG_START_TIME_FILE = os.path.join(LOG_DIR, "watchdog_start_time.txt")


@app.route("/api/monitor_stats")
def get_monitor_stats():
    # 1. Get PIDs of all trap processes
    trap_procs = list(watchdog.trap_processes.values())
    honeypot_pids = [p.pid for p in trap_procs if p.poll() is None]

    # 2. Include main Flask process
    honeypot_pids.append(os.getpid())

    total_cpu = 0.0
    total_ram = 0

    for pid in honeypot_pids:
        try:
            proc = psutil.Process(pid)
            total_cpu += proc.cpu_percent(interval=0.1)
            total_ram += proc.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # 3. Convert memory to GB
    total_ram_gb = round(total_ram / (1024 ** 3), 2)

    # 4. Uptime from watchdog start time
    if os.path.exists(WATCHDOG_START_TIME_FILE):
        with open(WATCHDOG_START_TIME_FILE, "r") as f:
            start_time = datetime.datetime.fromisoformat(f.read().strip())
        uptime = str(datetime.datetime.now() - start_time).split('.')[0]
    else:
        uptime = "unknown"

    # 5. Disk space used by logs/
    log_dir = "logs"
    total_log_size = 0
    for root, dirs, files in os.walk(log_dir):
        for file in files:
            try:
                total_log_size += os.path.getsize(os.path.join(root, file))
            except:
                continue
    log_size_mb = round(total_log_size / (1024 ** 2), 2)

    # 6. Count active and failed traps
    trap_summary = watchdog.get_trap_status_summary()
    active_count = sum(1 for s in trap_summary.values() if s["active"])
    failed_traps = [name for name, s in trap_summary.items() if not s["active"]]

    return {
        "cpu": round(total_cpu, 1),
        "ram_used": total_ram_gb,
        "ram_total": "honeypot only",
        "disk": f"logs/ = {log_size_mb} MB",
        "uptime": uptime,
        "active_traps": active_count,
        "failed_traps": failed_traps
    }


@app.route('/save-mac', methods=['POST'])
def save_mac():
    mac = request.form.get("mac_address", "").strip().upper()
    PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
    mac_file = os.path.join(PROJECT_ROOT, "logs", "blocked_macs.json")

    macs = []
    if os.path.exists(mac_file):
        try:
            with open(mac_file, "r") as f:
                content = f.read().strip()
                macs = json.loads(content) if content else []
        except json.JSONDecodeError:
            print("[ERROR] blocked_macs.json is empty or corrupt. Reinitializing.")
            macs = []
    else:
        print("[INFO] blocked_macs.json not found. Initializing new list.")

    # ✅ Add a default MAC if the list is empty
    if not macs:
        macs.append("AA:BB:CC:DD:EE:FF")  # Default placeholder MAC

    if mac and mac not in macs:
        macs.append(mac)
        with open(mac_file, "w") as f:
            json.dump(macs, f, indent=2)
        print(f"[MAC BLOCK] Added MAC: {mac}")
        return render_template("monitor.html", message="admin@DR0PNET:~$ MAC Added")
    elif mac:
        print(f"[MAC BLOCK] MAC already in list: {mac}")
        return render_template("monitor.html", message="admin@DR0PNETt:~$ MAC already in list")

    return redirect("/")



@app.route('/save-ip', methods=['POST'])
def save_ip():
    ip = request.form.get("ip_address", "").strip()
    PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
    ip_file = os.path.join(PROJECT_ROOT, "logs", "blocked_ips.json")

    ips = []
    if os.path.exists(ip_file):
        try:
            with open(ip_file, "r") as f:
                content = f.read().strip()
                ips = json.loads(content) if content else []
        except json.JSONDecodeError:
            print("[ERROR] blocked_ips.json is empty or corrupt. Reinitializing.")
            ips = []
    else:
        print("[INFO] blocked_ips.json not found. Initializing new list.")

    # ✅ Ensure there's always a default IP (you can change this)
    if not ips:
        ips.append("192.168.x.x")

    # Add new IP if it's valid and not already in the list
    if ip and ip not in ips:
        ips.append(ip)
        with open(ip_file, "w") as f:
            json.dump(ips, f, indent=2)
        print(f"[IP BLOCK] Added IP: {ip}")
        return render_template("monitor.html", message="admin@DR0PNET:~$ IP Added")
    elif ip:
        print(f"[IP BLOCK] IP already in list: {ip}")
        return render_template("monitor.html", message="admin@DR0PNET:~$ IP already in list")

    return redirect("/")



@app.route('/') # Main route for the dashboard
def index():
    settings = load_settings()
    return render_template("dashboard.html", settings=settings)

@app.route('/readme', methods=['POST']) # Route to open the README popup
def open_readme():
    threading.Thread(target=show_readme_popup).start()
    return redirect('/')

# Global stop event for thread control
stop_event = threading.Event()

# Function to kill all honeypot-related processes
def kill_all_honeypot_processes():
    print("[*] Killing all honeypot-related processes...")
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if "python" in proc.info['name'] and any(
                script in " ".join(proc.info['cmdline']) for script in [
                    "browser_trap.py", "ssh_trap.py", "ftp_trap.py", "file_trap.py",
                    "scan_ids.py", "ip_geo.py", "reverse_dns.py", "decoy_ports.py", "passive_scan.py"
                ]
            ):
                print(f"[INFO] Killing process {proc.info['pid']} ({proc.info['cmdline']})...")
                proc.terminate()
                proc.wait(timeout=3)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            print(f"[WARNING] Failed to kill process {proc.info['pid']}: {e}")

# Function to simulate activity
def simulate_activity(attacker_ip):
    print(f"[INFO] Starting simulation for IP: {attacker_ip}")
    try:
        while not stop_event.is_set():  # Check if the stop signal is set
            print(f"[INFO] Simulating activity for IP: {attacker_ip}")
            time.sleep(5)  # Replace with actual trap logic
    except KeyboardInterrupt:
        print("[INFO] Simulation stopped.")
    finally:
        print("[INFO] Simulation loop exited.")


@app.route('/start', methods=['POST'])
def start():
    if watchdog.is_running():
        return render_template("monitor.html", message="admin@DR0PNET:~$ Honeypot already running")


    watchdog.start_all()
    return render_template("monitor.html", message="admin@DR0PNET:~$ Honeypot Active")


"""
<!DOCTYPE html>
<html>
<head>
    <title>DR0PNET Monitor</title>
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
        <div class="line">admin@DR0PNET:~$ Honeypot Active<span class="cursor"></span></div>
    </div>
</body>
</html>
"""




@app.route('/stop', methods=['POST']) # Stop the honeypot
def stop_honeypot():
    print("[INFO] Stopping all honeypot processes immediately...")

    def stop_operations():
        stop_event.set()
        watchdog.stop_all()
        kill_all_honeypot_processes()

    threading.Thread(target=stop_operations, daemon=True).start()
    return render_template("monitor.html", message='admin@DR0PNET:~$ Honeypot stopped')


@app.route('/reset', methods=['POST']) # Reset the honeypot
def reset_honeypot():
    print("[INFO] Resetting honeypot...")

    def reset_operations():
        stop_event.set()
        watchdog.stop_all()
        stop_event.clear()
        watchdog.start_all()

    threading.Thread(target=reset_operations, daemon=True).start()
    return render_template("monitor.html", message='admin@DR0PNET:~$ Honeypot resetting')


@app.route('/download_logs')
def download_logs():
    zip_path = "logs.zip"
    added_files = set()

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk("logs"):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, start="logs")
                if arcname not in added_files:
                    zipf.write(file_path, os.path.join("logs", arcname))
                    added_files.add(arcname)

    return send_file(zip_path, as_attachment=True)

@app.route("/update", methods=["POST"]) # Update the honeypot by downloading the latest release from GitHub
def update():
    # 1. Get latest release info from GitHub
    api_url = "https://api.github.com/repos/dr0pnet/honeypot/releases/latest"
    r = requests.get(api_url)
    if r.status_code != 200:
        return render_template("monitor.html", message='admin@DR0PNET:~$ Failed to fetch release info')
# 2. Get the first asset (you can refine this to pick a specific file type)
    release = r.json()
    assets = release.get("assets", [])
    if not assets:
        return render_template("monitor.html", message='admin@DR0PNET:~$ No assets found in latest release')

    asset = assets[0]
    download_url = asset["browser_download_url"]
    filename = asset["name"]

    # 3. Download the asset
    with requests.get(download_url, stream=True) as dl:
        dl.raise_for_status()
        with open(filename, "wb") as f:
            for chunk in dl.iter_content(chunk_size=8192):
                f.write(chunk)

    return render_template("monitor.html", message=f"admin@DR0PNET:~$ Downloaded latest release: {filename}") 





@app.route('/uninstall') # Uninstall the honeypot by running the uninstall script
def uninstall():
 
    if platform.system().lower() == "windows":
        subprocess.Popen(["cmd", "/c", "start", "modules\\uninstall_windows.bat"], shell=True)
    else:
        subprocess.Popen(["bash", "modules/uninstall_linux.sh"])

    return """
<!DOCTYPE html>
<html>
<head>
    <title>DR0PNET Monitor</title>
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
        <div class="line">admin@DR0PNET:~$ Uninstalling dr0pnet Honeypot<span class="cursor"></span></div>
    </div>
</body>
</html>
"""


if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        marker_file = os.path.join("logs", "readme_shown.flag")
        if not os.path.exists(marker_file):
            if platform.system() != "Linux" or os.environ.get("DISPLAY"):
                show_readme_popup()
                with open(marker_file, "w") as f:
                    f.write("shown")
            else:
                print("[INFO] GUI not available — skipping welcome popup.")

    if platform.system().lower() == "windows":
        from waitress import serve
        print("[+] DR0PNET Running with Waitress (production WSGI server) http://localhost:5000")
        serve(app, host="0.0.0.0", port=5000)
    else:
        print("[INFO] Flask app running in development (use gunicorn in prod).")
        app.run(host="0.0.0.0", port=5000)



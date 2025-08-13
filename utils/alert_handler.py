import os
import json
import datetime
import tkinter as tk
import sys

# ─── Get Base Directory for Logs ──────────────────────────────
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "alerts.json")


def trigger_alert(message):
    try:
        print(f"[Alert] {message}")
        save_alert_to_file(message)

        try:
            show_custom_popup(f"[dr0pnet Alert]\n\n{message}")
        except Exception as e:
            print(f"[Popup Error] {e}")
    except Exception as e:
        print(f"[trigger_alert error] {e}")


def show_custom_popup(message):
    try:
        window = tk.Tk()
        window.title("dr0pnet Alert")
        window.configure(bg="black")
        window.attributes('-topmost', True)
        window.geometry("400x180+600+300")
        window.resizable(False, False)

        label = tk.Label(
            window,
            text="dr0pnet Alert",
            font=("Helvetica", 20, "bold"),
            bg="black",
            fg="#FF1493"
        )
        label.pack(pady=(20, 5))

        msg_label = tk.Label(
            window,
            text=message,
            font=("Helvetica", 13),
            bg="black",
            fg="white",
            wraplength=360,
            justify="center"
        )
        msg_label.pack(pady=(0, 10))

        # Pulse effect
        pulse_state = True

        def pulse():
            nonlocal pulse_state
            label.config(fg="#FF1493" if pulse_state else "#FFFFFF")
            pulse_state = not pulse_state
            window.after(500, pulse)

        pulse()

        ok_btn = tk.Button(
            window,
            text="OK",
            command=window.destroy,
            bg="#222",
            fg="#FF1493",
            font=("Helvetica", 12, "bold"),
            width=10
        )
        ok_btn.pack(pady=(0, 10))

        window.lift()
        window.after(100, lambda: window.focus_force())
        window.mainloop()
    except Exception as e:
        print(f"[Popup Exception] {e}")


def save_alert_to_file(message):
    os.makedirs(LOG_DIR, exist_ok=True)

    try:
        # Load existing alerts or initialize list
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                try:
                    content = f.read().strip()
                    data = json.loads(content) if content else []
                except json.JSONDecodeError:
                    print("[WARNING] alerts.json is corrupt or empty. Resetting.")
                    data = []
        else:
            data = []

        # ✅ Ensure at least one default entry always exists
        if not data:
            data.append({
                "timestamp": "N/A",
                "trap": "System",
                "message": "No alerts yet. Honeypot initialized."
            })

        # Add new alert
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Detect trap name
        trap_name = None
        if "SSH" in message:
            trap_name = "SSH Trap"
        elif "FTP" in message:
            trap_name = "FTP Trap"
        elif "wallet" in message.lower():
            trap_name = "Fake Wallet"
        elif "scan" in message.lower():
            trap_name = "Scan IDS"
        elif "file" in message.lower():
            trap_name = "File Trap"
        elif "browser" in message.lower():
            trap_name = "Browser Trap"
        elif "ARP" in message.lower():
            trap_name = "ARP Monitor"

        data.append({
            "timestamp": timestamp,
            "trap": trap_name,
            "message": message
        })

        # Save only the last 50 alerts
        with open(LOG_FILE, "w") as f:
            json.dump(data[-50:], f, indent=2)

    except Exception as e:
        print(f"[Log File Error] {e}")


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

| Component               | Purpose                             | 
|-------------------------|-------------------------------------|
| Python 3.6+             | Main interpreter                    |
| Flask                   | Flask Server                        |
| pip                     | Install helper (optional)           | 
| libpcap-dev (Linux)     | Raw packet sniffing for Scapy       | 
| Npcap (Windows)         | Raw packet sniffing for Scapy       |
| python3-tk              | Tkinter pop-up alerts               | 
| tcpdump (opt.)          | Useful for debugging scans          | 
| net-tools (opt.)        | Network utilities like `ifconfig`   |
| site-packages           | All site-packages must be installed |


## Troubleshooting
------------------
- Make sure you extracted the full folder (don’t run from inside ZIP)
- Firewall prompts may appear — allow all access for local communication
- The TrapWatchdog class uses Python threads to monitor and restart modules that crash unexpectedly. It ensures all traps are always running unless intentionally stopped.
- Make sure site-packages are being used per OS, if not install them manually.



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

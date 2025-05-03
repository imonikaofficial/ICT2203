📡 Wi-Fi Deauthentication Attack & Detection Tool
This project provides two Python scripts:

wifideauth.py — Scan for Wi-Fi access points and optionally launch deauthentication attacks.

detection.py — Detect ongoing deauthentication attacks against a wireless network.

⚠️ Legal Notice
This tool is intended only for educational and authorized security testing. Performing deauthentication attacks on networks without explicit permission is illegal and unethical.

📁 Files

File	Description
wifideauth.py	Wi-Fi scanner and deauthentication attack tool
detection.py	Sniffer for detecting deauthentication attacks

🔧 Requirements
Operating System: Linux (Kali, Ubuntu, or any with wireless support)

Python: Version 3.x

Privileges: Root access required

Hardware: Wireless adapter that supports monitor mode

📦 Python Dependencies
Install dependencies with:

pip install scapy mac-vendor-lookup
🛠 Setup & Usage
1️⃣ Deauthentication Tool (wifideauth.py)
✅ Basic Usage

sudo python wifideauth.py -c <channel> -a <target>
📄 Arguments

Option	Description
-v	Verbose mode
-h, --help	Show help message
-c, --channel	Set the Wi-Fi channel to monitor
-a, --attack	Set to * for all clients or specify a MAC address
📌 Examples
Scan clients on channel 6:
sudo python wifideauth.py -c 6
Attack all clients on channel 8:
sudo python wifideauth.py -c 8 -a *
Attack a specific MAC address on channel 11:
sudo python wifideauth.py -c 11 -a 2C:D0:66:A3:6E:39
2️⃣ Deauthentication Detection (detection.py)
This functionality is also embedded in wifideauth.py.

▶️ Run the Script
sudo python detection.py
🧭 Workflow
Choose your wireless interface.

Put the interface in monitor mode.

The script will sniff for Dot11Deauth packets.

Upon detecting 30 deauth packets, you'll receive a warning.

The interface is restored to managed mode after detection.

🧠 Features
Automatic interface selection

Monitor mode and managed mode switching

Deauthentication packet injection (attack mode)

Real-time deauthentication detection and alerting

MAC vendor lookup for clarity in logs

Robust error handling and recovery for interface issues

🛑 Disclaimer
This software is intended solely for educational, research, and authorized penetration testing purposes.
Misuse of this tool may result in violations of local laws and organizational policies.
You are responsible for your actions.


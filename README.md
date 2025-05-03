Wi-Fi Deauthentication Attack Tool & Detection Script
This project contains two Python scripts:

wifideauth.py — A tool for scanning Wi-Fi networks and launching deauthentication attacks against clients.

detection.py — A script for detecting deauthentication attacks by sniffing wireless packets in monitor mode.

⚠️ Legal Notice: This tool is intended for educational and authorized testing purposes only. Unauthorized use of deauthentication attacks on networks you do not own or have explicit permission to test is illegal and unethical.

📁 Files
wifideauth.py
A Python-based Wi-Fi deauthentication tool using Scapy.

detection.py 
Detects deauthentication attacks against a specific Access Point by sniffing Wi-Fi packets.

🔧 Requirements
Python 3

Linux (Kali, Ubuntu, or any Linux with wireless support)

Root privileges

Wireless interface that supports monitor mode

Python packages:

scapy

mac-vendor-lookup

Install dependencies with:

bash
Copy
Edit
pip install scapy mac-vendor-lookup
🛠 Setup & Usage
1. Wi-Fi Deauth Tool: wifideauth.py
Basic Usage
bash
Copy
Edit
sudo python wifideauth.py -c <channel> -a <mac>
Arguments
-v : Verbose mode

-h, --help : Show help

-c, --channel : Channel to monitor

-a, --attack : Attack mode

* — attack all clients

<MAC> — target specific client MAC address

Examples
Scan and detect clients:


sudo python wifideauth.py -c 6
Attack all clients on channel 8:
sudo python wifideauth.py -c 8 -a *
Attack a specific MAC address:
sudo python wifideauth.py -c 11 -a 2C:D0:66:A3:6E:39
2. Deauth Detection Script (also in wifideauth.py for convenience)
Run the detection:
sudo python wifideauth.py
Follow on-screen steps:

Choose an interface and enter monitor mode.

The script will sniff for deauthentication packets.

After 30 detections, an alert will be shown.

Interface will be reset to managed mode.

🧠 Features
Automatic interface selection

Channel setting and reset handling

MAC address vendor lookup

Deauthentication packet injection (for attack mode)

Live detection and alerting on potential deauth attacks

🛑 Disclaimer
This tool is meant strictly for research, education, and authorized penetration testing. Misuse may violate local laws and network policies.

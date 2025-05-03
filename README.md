# 📡 Wi-Fi Deauthentication Attack & Detection Tool

This project includes two Python scripts for Wi-Fi network security testing:

- **`wifideauth.py`** — Scan nearby Wi-Fi access points and optionally launch deauthentication attacks.
- **`detection.py`** — Monitor and detect deauthentication attacks in real time.

> ⚠️ **Legal Notice**  
> This tool is intended **only for educational and authorized security testing**.  
> Performing deauthentication attacks on networks without **explicit permission** is **illegal** and **unethical**.

---

## 📁 Files

| File            | Description                                                  |
|-----------------|--------------------------------------------------------------|
| `wifideauth.py` | Wi-Fi scanner and deauthentication attack tool               |
| `detection.py`  | Sniffer to detect ongoing deauthentication attacks           |

---

## 🔧 Requirements

- **OS**: Linux (Kali, Ubuntu, or other with wireless support)
- **Python**: Version 3.x
- **Privileges**: Requires root access
- **Hardware**: Wireless adapter that supports **monitor mode**

## 🛠 Setup & Usage

### 1️⃣ Deauthentication Tool — `wifideauth.py`

#### ✅ Basic Syntax
```bash
sudo python wifideauth.py -c <channel> -a <target>
Option | Description
-v | Enable verbose mode
-h, --help | Show help message
-c, --channel | Set the Wi-Fi channel to scan/attack
-a, --attack | Set to * for all clients or specify a target MAC address

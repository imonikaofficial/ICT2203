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

### ✅ Basic Syntax
```bash
sudo python wifideauth.py -c <channel> -a <target>
```

| Option            | Description                                                        |
|-------------------|--------------------------------------------------------------------|
| `-v`              | Enable verbose mode                                                |
| `-h`, `--help`    | Show help message                                                  |
| `-c`, `--channel` | Set the Wi-Fi channel to scan/attack                               |
| `-a`, `--attack`  | Set to `*` for all clients or specify a target MAC address         |

### 📌 Examples

- **Scan for clients on channel 6:**
```bash
sudo python wifideauth.py -c 6
```

- **Deauth all clients on channel 8:**
```bash
sudo python wifideauth.py -c 8 -a *
```

- **Deauth a specific client:**
```bash
sudo python wifideauth.py -c 11 -a 2C:D0:66:A3:6E:39
```

---

## 2️⃣ Deauthentication Detection — detection.py

> Detection logic is also included in `wifideauth.py`.

### ▶️ Run the Script
```bash
sudo python detection.py
```

---

# 🧭 Workflow

1. Choose a wireless interface from the list.
2. The script places it into monitor mode.
3. It begins sniffing for Dot11Deauth packets.
4. After 30 detections, a warning is displayed.
5. The interface is restored to managed mode.

---

# 🧠 Features

- Automatic interface detection and channel management
- Deauthentication packet injection using Scapy
- Live MAC vendor identification using `mac-vendor-lookup`
- Deauthentication detection with real-time alerts
- Error handling for interface management (monitor ↔ managed)

---

# 🔄 Flowchart

Here’s a visual representation of how the tool works:

```
                    ┌───────────────────────┐
                    │   Start the Script    │
                    └──────────┬────────────┘
                               │
                     Select Wireless Interface
                               │
                  ┌───────────▼────────────┐
                  │  Switch to Monitor Mode│
                  └───────────┬────────────┘
                               │
        ┌──────────────────────┴──────────────────────┐
        │                                             │
┌───────▼────────┐                         ┌──────────▼─────────┐
│ Scan Networks  │                         │   Sniff for        │
│ and Clients    │                         │ Deauth Packets     │
└──────┬─────────┘                         └──────────┬─────────┘
       │                                             │
       ▼                                             ▼
 [Launch Deauth]                             [Count Packets ≥ 30?]
       │                                             │
       ▼                                             ▼
[Inject Deauth Frames]                      [Display Alert if Yes]
       │                                             │
       ▼                                             ▼
[Return to Managed Mode] <─────────────── [Return to Managed Mode]
```

---

# 🛑 Disclaimer

This software is intended solely for:

- Educational use
- Research
- Authorized penetration testing

⚠️ **Misuse is illegal and may violate network policies or local laws.**  
You are fully responsible for your actions.

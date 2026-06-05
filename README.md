# ◈ NetWatch
> Network connection monitor with real-time threat detection

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

NetWatch is a desktop application that monitors all active network connections on your machine in real time, geolocates remote IPs, and flags suspicious activity such as crypto mining, Tor usage, and botnet-related ports.

![NetWatch Screenshot](https://i.imgur.com/placeholder.png)

---

## Features

- **Real-time monitoring** — refreshes every 10 seconds automatically
- **IP geolocation** — country, flag, and organization for every remote connection
- **Threat detection** — flags suspicious ports (mining, Tor, IRC botnets) and known mining pool organizations
- **Risk levels** — ALTO / MEDIO / BAJO / LOCAL with color-coded rows
- **Simple / Technical mode** — toggle between a beginner-friendly view and a full technical view
- **System notifications** — native OS alerts when a high-risk connection is detected (with cooldown to avoid spam)
- **Bandwidth monitor** — real-time upload/download speed per network interface
- **Persistent geo cache** — saves IP lookups to disk so they aren't re-fetched on restart
- **Filter & sort** — search by process name or IP, filter by risk level, sort any column

---

## Installation

### Requirements
```
Python 3.10+
```

### Install dependencies
```bash
pip install customtkinter psutil requests plyer
```

### Run
```bash
python netwatch_v2.py
```

> **Linux / macOS:** may require `sudo` to see all processes
> ```bash
> sudo python netwatch_v2.py
> ```

---

## Build as standalone executable

Requires [PyInstaller](https://pyinstaller.org):
```bash
pip install pyinstaller
```

**Windows:**
```bash
pyinstaller --onefile --windowed --name NetWatch netwatch_v2.py
```

**macOS:**
```bash
pyinstaller --onefile --windowed --name NetWatch netwatch_v2.py
```

**Linux:**
```bash
pyinstaller --onefile --name NetWatch netwatch_v2.py
```

Output will be in the `dist/` folder.

---

## Suspicious ports detected

| Port | Reason |
|------|--------|
| 3333, 4444, 5555, 7777 | Crypto mining pools |
| 8333 | Bitcoin P2P |
| 9050, 9051 | Tor network |
| 1080 | SOCKS proxy |
| 6666, 6667, 6668 | IRC (commonly used by botnets) |
| 8080 | Alternative HTTP proxy |

---

## Risk levels

| Level | Color | Meaning |
|-------|-------|---------|
| ⚠ ALTO | 🔴 Red | Suspicious port or known mining organization |
| ⚡ MEDIO | 🟡 Yellow | IP could not be identified |
| ✓ BAJO | 🟢 Green | Connection appears normal |
| 🏠 LOCAL | ⚪ Gray | Private network / LAN |

---

## Tech stack

- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) — modern dark UI
- [psutil](https://github.com/giampaolo/psutil) — process and network stats
- [requests](https://github.com/psf/requests) — HTTP for IP geolocation
- [plyer](https://github.com/kivy/plyer) — cross-platform system notifications
- [ip-api.com](http://ip-api.com) — free IP geolocation API

---

## Author

**TrinityBerserker**  
[github.com/TrinityBerserker](https://github.com/TrinityBerserker)
# NetScanner — Signal Cartography

A feature-rich, **web-based** network scanner and discovery tool. It finds every
device on your network, identifies what each one is, maps their open ports and
services, and gives you a **clickable URL** for anything running a web interface.
The UI is a polished dark "constellation atlas" dashboard with card, table, and
interactive topology-map views.

The engine is a single Python file with **zero external dependencies** (standard
library only). It runs a small local web server and serves the dashboard in your
browser. Nothing is sent to the cloud — all scanning and data stay on your machine.

---

## Files

| File | Purpose |
|------|---------|
| `netscanner.py` | The scanning engine + local web server |
| `ui.html` | The dashboard (served by the engine — **keep it next to `netscanner.py`**) |
| `run.bat` | Double-click launcher for Windows |
| `build.bat` | Builds a standalone `NetScanner.exe` (bundles `ui.html`) |
| `Dockerfile`, `docker-compose.yml`, `.dockerignore` | Run it as a container on a NAS/server |
| `DESIGN_PHILOSOPHY.md`, `signal_cartography.png/.pdf` | The visual design language behind the UI |

> `netscanner.py` and `ui.html` must live in the same folder. Everything else is optional.

---

## Why it's "a local web app" and not pure in-browser JavaScript

A scanner running *entirely* inside a browser tab physically cannot probe your
LAN — browsers sandbox raw network access for security (no ICMP ping, no ARP, no
arbitrary TCP scans). NetScanner uses the standard, capable design: a tiny local
engine does the real scanning and serves the web UI you open in your browser.

---

## Option A — run locally (easiest, no install)

1. Install **Python 3.8+** (https://www.python.org/downloads/ — tick *"Add Python to PATH"*).
2. Double-click **`run.bat`** (or run `python netscanner.py`).
3. Your browser opens at `http://127.0.0.1:8765`; your subnet is auto-detected — press **Scan network**.

```
python netscanner.py                # launch + open browser
python netscanner.py --port 9000    # choose a port
python netscanner.py --no-browser   # don't auto-open the browser
python netscanner.py --host 0.0.0.0 # listen on all interfaces (use with care)
```

## Option B — standalone Windows .exe (no Python on the target PC)

Run **`build.bat`** once on a Windows machine with Python. It uses PyInstaller to
produce `dist\NetScanner.exe` — a single file (the UI is bundled inside) you can
copy to any Windows PC and double-click. (A Windows `.exe` must be built on Windows.)

## Option C — Docker on your NAS / server

The app is container-ready. From this folder:

```
docker compose up -d --build
```

Then open **`http://<your-NAS-IP>:8765`** from any browser on your network.

**Host networking is required.** A bridged container sits on its own virtual
network and cannot see your real LAN — no device discovery, no ARP, no mDNS/SNMP.
The provided `docker-compose.yml` already sets `network_mode: host` and adds the
`NET_RAW`/`NET_ADMIN` capabilities needed for ICMP ping.

- On **Synology** (Container Manager) or **QNAP** (Container Station), import this
  project and make sure the container uses **host** network mode. If your NAS UI
  won't allow host mode, the app will still load but device discovery will be
  limited to the container's own network.
- Data (scan history, device names/notes, and the downloaded vendor DB) persists
  in `./netscanner-data` on the host via the mounted volume.
- Change the port with the `NETSCANNER_PORT` env var if 8765 is taken.

Plain `docker` equivalent:

```
docker build -t netscanner .
docker run -d --name netscanner --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -e NETSCANNER_PORT=8765 -v "$PWD/netscanner-data:/data" \
  --restart unless-stopped netscanner
```

---

## Features

**Discovery & identification**
- Auto-detects your subnet (editable — scan any CIDR, e.g. `10.0.0.0/24`)
- Concurrent ping sweep **plus a TCP fallback**, so it finds devices that block ping
- MAC address resolution from the ARP table
- Vendor lookup from the MAC, with a **one-click "Download full" button** that
  fetches the complete IEEE OUI database for exhaustive vendor names
- Reverse-DNS hostnames
- **mDNS / Bonjour** discovery — surfaces Chromecasts, AirPlay, printers, Apple
  devices, Sonos, HomeKit, etc., with friendly names and service types
- **SNMP** (v2c) queries managed switches, printers and access points for their
  system name and description
- OS guess (TTL) and device-type guess (ports + vendor + mDNS + SNMP)
- Round-trip latency

**Ports & services**
- Parallel TCP connect scanning — **Quick** (~90 ports), **Extended** (1–1024),
  **Full** (1–65535) — with service names and banner grabbing
- **Web URL detection** — HTTP/HTTPS ports become clickable links that open the
  device's web UI (80 → `http://ip`, 443 → `https://ip`, plus 8080/8443/8123/…)

**Views & workflow**
- **Cards**, dense **Table**, and an interactive **Topology map** (radial
  constellation with the gateway at the center; node size = open ports)
- Search, filter (web-only / open-ports / new / named), and sort
- **Live monitoring**: auto re-scan on a timer with **new-device detection** and
  **desktop notifications** (browser Notification API)
- **Scan history + change detection** — every scan is saved; reload and compare
- **Wake-on-LAN**, **custom names/notes** per device, **CSV/JSON export**

---

## Notes & tips

- **Run as Administrator / root** for the most complete ARP and discovery results.
- **Allow it through your firewall** on private networks the first time.
- The local launcher binds to `127.0.0.1` only. The Docker/`--host 0.0.0.0` modes
  expose it to your whole LAN — appropriate for a NAS, but don't expose it to the
  internet.
- **Full** port scans (65,535 ports/host) are thorough but slow — best used on a
  single host v
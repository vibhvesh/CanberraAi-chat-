# CanberraAI Chat + Sentinel

A self-hosted bridge for sharing clipboard text and files between a Linux server and browsers on PC or Android, with a central forensic activity dashboard for authorized Linux hosts.

## Features
- Authenticated browser dashboard for clipboard and file transfer.
- Live clipboard relay over WebSockets.
- Authenticated file upload, download and deletion.
- Sentinel dashboard for network connection metadata, process starts, package-manager changes, filesystem activity and host heartbeats.
- Enroll additional Linux desktops/servers into the same Sentinel dashboard.
- 90-day event retention by default; older events are pruned during ingestion.
- Separate dashboard access token and Sentinel agent enrollment token.

## Install on Ubuntu/Debian

```bash
curl -fsSL https://raw.githubusercontent.com/vibhvesh/CanberraAi-chat-/main/install.sh | sudo bash
```

The installer generates two private tokens:
- **Dashboard token**: sign in to the web app and use Chat & Files.
- **Sentinel agent token**: enroll other Linux hosts. Retrieve it later with `sudo cbridge sentinel-token`.

Open `http://SERVER-IP:8765`. Configure HTTPS before using this over the public internet.

## Enroll another Linux desktop/server

On another authorized Ubuntu/Debian machine:

```bash
curl -fsSLO https://raw.githubusercontent.com/vibhvesh/CanberraAi-chat-/main/agent/install-sentinel.sh
sudo bash install-sentinel.sh --server https://YOUR-DOMAIN --token YOUR_SENTINEL_AGENT_TOKEN
```

Optional custom watch paths:

```bash
sudo bash install-sentinel.sh --server https://YOUR-DOMAIN --token YOUR_SENTINEL_AGENT_TOKEN --paths /etc,/usr/local,/usr/bin,/usr/sbin,/opt,/var/lib,/home,/media,/mnt
```

The agent connects outbound to the central server. No inbound port is needed on the monitored desktop. Check with `sudo systemctl status canberra-sentinel`.

## What Sentinel collects

- **Network**: observed TCP/UDP connection metadata, local/remote IP and port, direction estimate, connection state, and process name/executable when available. Public/private/loopback classification is based on IP address ranges, not geolocation.
- **Processes**: newly observed process starts, PID, process name, executable path, user and parent PID/name when available.
- **Filesystem**: create/modify/delete/rename events under configured watch paths, with labels such as SYSTEM_FILE, USER_FILE, APPLICATION_DATA, TEMPORARY_FILE and EXTERNAL_STORAGE.
- **Installations**: apt/dpkg install, upgrade, remove and purge log entries.
- **Host health**: agent heartbeats and watched-path inventory.

This is metadata monitoring, not full packet capture or byte-volume accounting. Network sockets are sampled every 15 seconds, so very short-lived connections can be missed. It does not collect packet payloads, passwords, keystrokes, browser history or file contents. Filesystem monitoring is best-effort; events can be missed while the agent is stopped or if Linux watch limits are exhausted. Inbound/outbound labels are inferred from socket endpoints and should be treated as indicators, not definitive attribution. Some process/network details may be unavailable without root privileges.

## Commands

- `cbridge status`
- `cbridge logs`
- `cbridge sentinel-status`
- `cbridge sentinel-logs`
- `cbridge sentinel-token`
- `cbridge update`

## Security

- Dashboard API uses the dashboard token; telemetry ingestion uses a separate agent token.
- Anyone with the dashboard token can access clipboard and transferred files. Anyone with the agent token can submit telemetry to the instance.
- Keep both tokens private and use HTTPS on public networks.
- Sentinel agents run with elevated privileges to observe system-wide metadata. Install only on machines you own or are authorized to administer.
- Event history can include IP addresses, usernames, process names and file paths. Restrict access and consider local privacy/legal requirements.
- SQLite event storage is local at `/var/lib/cbridge/sentinel.sqlite3`; retention is 90 days by default.
- This is an initial monitoring MVP, not a certified forensic acquisition system. It does not provide tamper-proof evidence or packet-level capture.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
CBRIDGE_TOKEN=dev-token SENTINEL_AGENT_TOKEN=agent-dev-token CBRIDGE_DATA_DIR=./data uvicorn server.main:app --host 127.0.0.1 --port 8765
```

MIT licensed.
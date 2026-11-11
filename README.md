# CanberraAI Chat

A self-hosted bridge for sharing clipboard text and files between a Linux server and browsers on PC or Android.

## Features
- Token-authenticated web dashboard.
- Clipboard text relay over WebSockets.
- Authenticated file upload, download and deletion.
- Optional Linux desktop clipboard agent for Wayland (wl-clipboard) and X11 (xclip).
- Ubuntu/Debian installer and the short `cbridge` service command.

## Install

On a fresh Ubuntu/Debian server:

```bash
curl -fsSL https://raw.githubusercontent.com/vibhvesh/CanberraAi-chat-/main/install.sh | sudo bash
```

The installer generates a private access token and prints it. Save it. Then visit `http://SERVER-IP:8765`.

Commands: `cbridge status`, `cbridge logs`, `cbridge restart`, `cbridge token`, `cbridge update`.

## Linux desktop clipboard agent

Install the agent on the Linux desktop whose clipboard should sync:

```bash
curl -fsSL https://raw.githubusercontent.com/vibhvesh/CanberraAi-chat-/main/agent/install-agent.sh | bash
cbridge-agent --server ws://SERVER-IP:8765 --token YOUR_TOKEN
```

Install `wl-clipboard` on Wayland or `xclip` on X11. Run it in the logged-in desktop user's session. Clipboard synchronization is text-only.

## Security

- API and WebSocket endpoints require the instance token.
- Files are stored in `/var/lib/cbridge/files`; access requires the token.
- Anyone with the token can access that instance's files and clipboard. Keep it private.
- The basic installer uses HTTP on port 8765. For public internet use, put the service behind HTTPS (for example, Caddy with a domain) and configure the firewall. Do not transmit sensitive clipboard data over untrusted networks without HTTPS.
- This is a first MVP. Do not expose it to untrusted users.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
CBRIDGE_TOKEN=dev-token CBRIDGE_DATA_DIR=./data uvicorn server.main:app --host 127.0.0.1 --port 8765
```

MIT licensed.
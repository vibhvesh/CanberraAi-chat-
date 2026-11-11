#!/usr/bin/env bash
set -euo pipefail
DEST="$HOME/.local/bin"
mkdir -p "$DEST"
URL="https://raw.githubusercontent.com/vibhvesh/CanberraAi-chat-/main/agent/cbridge-agent.py"
curl -fsSL "$URL" -o "$DEST/cbridge-agent"
chmod 755 "$DEST/cbridge-agent"
python3 -m pip install --user 'websockets>=12,<16'
echo "Installed: $DEST/cbridge-agent"
echo "Run: $DEST/cbridge-agent --server ws://SERVER-IP:8765 --token YOUR_TOKEN"
echo "Install wl-clipboard (Wayland) or xclip (X11) for desktop clipboard access."

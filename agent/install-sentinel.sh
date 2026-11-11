#!/usr/bin/env bash
set -euo pipefail
SERVER="" TOKEN="" PATHS="/etc,/usr/local,/usr/bin,/usr/sbin,/usr/lib/systemd/system,/opt,/var/lib,/home,/media,/mnt"
while [[ $# -gt 0 ]]; do
 case "$1" in
  --server) SERVER="$2"; shift 2;;
  --token) TOKEN="$2"; shift 2;;
  --paths) PATHS="$2"; shift 2;;
  *) echo "Unknown argument: $1"; exit 2;;
 esac
done
if [[ $EUID -ne 0 ]]; then echo "Run with sudo."; exit 1; fi
if [[ -z "$SERVER" || -z "$TOKEN" ]]; then
 echo "Usage: sudo bash install-sentinel.sh --server https://YOUR-HOST --token YOUR_TOKEN"; exit 2
fi
apt-get update
apt-get install -y python3 python3-venv
mkdir -p /opt/canberra-sentinel
curl -fsSL https://raw.githubusercontent.com/vibhvesh/CanberraAi-chat-/main/agent/sentinel-agent.py -o /opt/canberra-sentinel/sentinel-agent.py
python3 -m venv /opt/canberra-sentinel/venv
/opt/canberra-sentinel/venv/bin/pip install --upgrade pip psutil watchdog
umask 077
cat >/etc/canberra-sentinel.env <<EOF
SENTINEL_SERVER=$SERVER
SENTINEL_TOKEN=$TOKEN
SENTINEL_PATHS=$PATHS
EOF
cat >/etc/systemd/system/canberra-sentinel.service <<'EOF'
[Unit]
Description=CanberraAI Sentinel host monitor
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
EnvironmentFile=/etc/canberra-sentinel.env
ExecStart=/opt/canberra-sentinel/venv/bin/python /opt/canberra-sentinel/sentinel-agent.py --server ${SENTINEL_SERVER} --token ${SENTINEL_TOKEN} --paths ${SENTINEL_PATHS}
Restart=always
RestartSec=5
User=root
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/var/log
[Install]
WantedBy=multi-user.target
EOF
chmod 600 /etc/canberra-sentinel.env
systemctl daemon-reload
systemctl enable --now canberra-sentinel
echo "Sentinel agent installed and enrolled. Check: systemctl status canberra-sentinel"

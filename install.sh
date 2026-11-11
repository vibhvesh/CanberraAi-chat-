#!/usr/bin/env bash
set -euo pipefail
APP=/opt/canberraai-chat
DATA=/var/lib/cbridge
ENV_FILE=/etc/cbridge.env
SERVICE=/etc/systemd/system/cbridge.service
SENTINEL_SERVICE=/etc/systemd/system/canberra-sentinel.service
REPO=https://github.com/vibhvesh/CanberraAi-chat-.git
if [[ $EUID -ne 0 ]]; then echo "Run with sudo."; exit 1; fi
if ! command -v apt-get >/dev/null 2>&1; then echo "Ubuntu/Debian only for this installer."; exit 1; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip git
mkdir -p "$APP" "$DATA/files"
if [[ -d "$APP/.git" ]]; then git -C "$APP" pull --ff-only; else
  if [[ -n "$(ls -A "$APP" 2>/dev/null || true)" ]]; then echo "$APP exists and is not a git checkout"; exit 1; fi
  git clone --depth 1 "$REPO" "$APP"
fi
python3 -m venv "$APP/.venv"
"$APP/.venv/bin/pip" install --upgrade pip
"$APP/.venv/bin/pip" install -r "$APP/requirements.txt"
if [[ ! -f "$ENV_FILE" ]]; then
  TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')
  printf 'CBRIDGE_TOKEN=%s\nCBRIDGE_DATA_DIR=%s\nSENTINEL_RETENTION_DAYS=90\n' "$TOKEN" "$DATA" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "SAVE THIS ACCESS TOKEN:"
  echo "$TOKEN"
else
  grep -q '^SENTINEL_RETENTION_DAYS=' "$ENV_FILE" || echo 'SENTINEL_RETENTION_DAYS=90' >> "$ENV_FILE"
  echo "Existing access token retained."
fi
cat > "$SERVICE" <<EOF
[Unit]
Description=CanberraAI Chat
After=network.target
[Service]
Type=simple
WorkingDirectory=$APP
EnvironmentFile=$ENV_FILE
ExecStart=$APP/.venv/bin/uvicorn server.main:app --host 0.0.0.0 --port 8765
Restart=always
RestartSec=3
User=root
[Install]
WantedBy=multi-user.target
EOF
cat > "$SENTINEL_SERVICE" <<EOF
[Unit]
Description=CanberraAI Sentinel local host monitor
After=network-online.target cbridge.service
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=$APP
EnvironmentFile=$ENV_FILE
Environment=SENTINEL_SERVER=http://127.0.0.1:8765
Environment=SENTINEL_PATHS=/etc,/usr/local,/usr/bin,/usr/sbin,/usr/lib/systemd/system,/opt,/var/lib,/home,/media,/mnt
ExecStart=$APP/.venv/bin/python $APP/agent/sentinel-agent.py --server ${SENTINEL_SERVER} --token ${CBRIDGE_TOKEN} --paths ${SENTINEL_PATHS}
Restart=always
RestartSec=5
User=root
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
[Install]
WantedBy=multi-user.target
EOF
cat > /usr/local/bin/cbridge <<'EOF'
#!/usr/bin/env bash
set -e
case "${1:-status}" in
 status) systemctl status cbridge --no-pager;;
 start|stop|restart) systemctl "${1}" cbridge;;
 logs) journalctl -u cbridge -f;;
 sentinel-status) systemctl status canberra-sentinel --no-pager;;
 sentinel-logs) journalctl -u canberra-sentinel -f;;
 sentinel-restart) systemctl restart canberra-sentinel;;
 token) sed -n 's/^CBRIDGE_TOKEN=//p' /etc/cbridge.env;;
 update) git -C /opt/canberraai-chat pull --ff-only; /opt/canberraai-chat/.venv/bin/pip install -r /opt/canberraai-chat/requirements.txt; systemctl restart cbridge canberra-sentinel;;
 uninstall) systemctl disable --now canberra-sentinel cbridge || true; rm -f /etc/systemd/system/cbridge.service /etc/systemd/system/canberra-sentinel.service /usr/local/bin/cbridge; systemctl daemon-reload; echo "Data retained in /var/lib/cbridge and config in /etc/cbridge.env.";;
 *) echo "Usage: cbridge {status|start|stop|restart|logs|sentinel-status|sentinel-logs|sentinel-restart|token|update|uninstall}";exit 2;;
esac
EOF
chmod 755 /usr/local/bin/cbridge
systemctl daemon-reload
systemctl enable --now cbridge
systemctl enable --now canberra-sentinel
echo "CanberraAI Chat + Sentinel installed."
echo "Open http://YOUR_SERVER_IP:8765"
echo "Commands: cbridge status | logs | sentinel-status | sentinel-logs | token | update"
echo "For public internet use, configure HTTPS before sending sensitive data."

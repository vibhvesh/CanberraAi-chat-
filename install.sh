#!/usr/bin/env bash
set -euo pipefail
APP=/opt/canberraai-chat
DATA=/var/lib/cbridge
ENV_FILE=/etc/cbridge.env
SERVICE=/etc/systemd/system/cbridge.service
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
  printf 'CBRIDGE_TOKEN=%s\nCBRIDGE_DATA_DIR=%s\n' "$TOKEN" "$DATA" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "SAVE THIS ACCESS TOKEN:"
  echo "$TOKEN"
else echo "Existing access token retained."; fi
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
cat > /usr/local/bin/cbridge <<'EOF'
#!/usr/bin/env bash
set -e
case "${1:-status}" in
 status) systemctl status cbridge --no-pager;;
 start|stop|restart) systemctl "${1}" cbridge;;
 logs) journalctl -u cbridge -f;;
 token) sed -n 's/^CBRIDGE_TOKEN=//p' /etc/cbridge.env;;
 update) git -C /opt/canberraai-chat pull --ff-only; /opt/canberraai-chat/.venv/bin/pip install -r /opt/canberraai-chat/requirements.txt; systemctl restart cbridge;;
 uninstall) systemctl disable --now cbridge || true; rm -f /etc/systemd/system/cbridge.service /usr/local/bin/cbridge; systemctl daemon-reload; echo "Data retained in /var/lib/cbridge and config in /etc/cbridge.env.";;
 *) echo "Usage: cbridge {status|start|stop|restart|logs|token|update|uninstall}";exit 2;;
esac
EOF
chmod 755 /usr/local/bin/cbridge
systemctl daemon-reload
systemctl enable --now cbridge
echo "Installed. Open http://YOUR_SERVER_IP:8765"
echo "Commands: cbridge status | logs | token | update"
echo "Use HTTPS before sending sensitive data over the public internet."

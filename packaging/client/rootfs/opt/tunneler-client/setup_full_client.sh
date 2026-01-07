#!/usr/bin/env bash
set -euo pipefail

SERVER=""; SSL="false"; SUBDOMAIN=""; TOKEN=""; HTTP=""; TCP=""; UDP=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --ssl)    SSL="$2"; shift 2 ;;
    --subdomain) SUBDOMAIN="$2"; shift 2 ;;
    --token)     TOKEN="$2"; shift 2 ;;
    --http)      HTTP="$2"; shift 2 ;;
    --tcp)       TCP="$2"; shift 2 ;;
    --udp)       UDP="$2"; shift 2 ;;
    *) shift ;;
  esac
done

[[ "$SSL" == "true" ]] && WS_URL="wss://${SERVER}/_ws" || WS_URL="ws://${SERVER}/_ws"

EXTRA_ARGS=""
[[ -n "$HTTP" ]] && EXTRA_ARGS+=" --http $HTTP"
IFS=',' read -ra TARR <<< "$TCP"
for x in "${TARR[@]}"; do [[ -n "$x" ]] && EXTRA_ARGS+=" --tcp $x"; done
IFS=',' read -ra UARR <<< "$UDP"
for x in "${UARR[@]}"; do [[ -n "$x" ]] && EXTRA_ARGS+=" --udp $x"; done

# 환경 파일 생성 (따옴표 제거)
ENV_FILE="/etc/default/tunneler-client"
cat > "$ENV_FILE" <<EOF
WS_URL=${WS_URL}
SUBDOMAIN=${SUBDOMAIN}
TOKEN=${TOKEN}
EXTRA_ARGS=$(echo "$EXTRA_ARGS" | xargs)
EOF
chmod 600 "$ENV_FILE"

INSTALL_DIR="/opt/tunneler-client"
python3 -m venv "$INSTALL_DIR/.venv" || true
"$INSTALL_DIR/.venv/bin/pip" install -U pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# 서비스 파일 생성 (중괄호 {} 제거)
SERVICE_FILE="/etc/systemd/system/tunneler-client.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Tunneler Client Service
After=network-online.target

[Service]
EnvironmentFile=/etc/default/tunneler-client
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/client.py \$WS_URL \$SUBDOMAIN \$TOKEN \$EXTRA_ARGS
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now tunneler-client
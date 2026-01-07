#!/usr/bin/env bash
# Tunneler Client Full Setup Script (Wrapper Version)
set -euo pipefail

# 1. 인자 초기화 및 파싱
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

# 2. WebSocket URL 생성
[[ "$SSL" == "true" ]] && WS_URL="wss://${SERVER}/_ws" || WS_URL="ws://${SERVER}/_ws"

# 3. 추가 매핑 인자(EXTRA_ARGS) 정리
EXTRA_ARGS=""
[[ -n "$HTTP" ]] && EXTRA_ARGS+=" --http $HTTP"
IFS=',' read -ra TARR <<< "$TCP"
for x in "${TARR[@]}"; do [[ -n "$x" ]] && EXTRA_ARGS+=" --tcp $x"; done
IFS=',' read -ra UARR <<< "$UDP"
for x in "${UARR[@]}"; do [[ -n "$x" ]] && EXTRA_ARGS+=" --udp $x"; done

# 4. 환경 변수 파일 생성 (/etc/default/tunneler-client)
ENV_FILE="/etc/default/tunneler-client"
cat > "$ENV_FILE" <<EOF
WS_URL=${WS_URL}
SUBDOMAIN=${SUBDOMAIN}
TOKEN=${TOKEN}
EXTRA_ARGS="$(echo "$EXTRA_ARGS" | xargs)"
EOF
chmod 600 "$ENV_FILE"

# 5. 가상환경(venv) 및 패키지 설치
INSTALL_DIR="/opt/tunneler-client"
echo "[INFO] 가상환경 설정 중..."
python3 -m venv "$INSTALL_DIR/.venv" || true
"$INSTALL_DIR/.venv/bin/pip" install -U pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# 6. ✅ 핵심: start.sh 실행 래퍼 스크립트 생성
# systemd 변수 확장 문제를 해결하기 위해 큰따옴표("")로 인자를 보호합니다.
echo "[INFO] 실행 래퍼(start.sh) 생성 중..."
cat > "${INSTALL_DIR}/start.sh" <<'EOF'
#!/bin/bash
# 설정값 로드
if [ -f /etc/default/tunneler-client ]; then
    source /etc/default/tunneler-client
fi
# 파이썬 실행 (따옴표를 사용하여 빈 값이라도 자리를 유지하게 함)
exec /opt/tunneler-client/.venv/bin/python /opt/tunneler-client/client.py \
    "$WS_URL" \
    "$SUBDOMAIN" \
    "$TOKEN" \
    $EXTRA_ARGS
EOF
chmod +x "${INSTALL_DIR}/start.sh"

# 7. ✅ 핵심: Systemd 서비스 파일 생성
# ExecStart가 파이썬이 아닌 start.sh를 바라보게 설정합니다.
echo "[INFO] Systemd 서비스 등록 중..."
SERVICE_FILE="/etc/systemd/system/tunneler-client.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Tunneler Client Service
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/start.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 8. 서비스 적용 및 시작
systemctl daemon-reload
systemctl enable --now tunneler-client

echo "[SUCCESS] Tunneler 클라이언트 설치 및 서비스 시작 완료!"

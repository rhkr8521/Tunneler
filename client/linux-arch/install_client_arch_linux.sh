#!/usr/bin/env bash
set -euo pipefail

echo "=== Tunneler 클라이언트(Arch / PiKVM) 설치 ==="

# PiKVM은 보통 읽기 전용이므로 패키지 설치 전 rw
if command -v rw >/dev/null 2>&1; then
  rw
fi

pacman -Syy --noconfirm
pacman -S --noconfirm python python-pip python-virtualenv curl jq

INSTALL_DIR="/root/.tunneler"
mkdir -p "$INSTALL_DIR"

cp -f client.py requirements.txt "$INSTALL_DIR/"

python -m venv "$INSTALL_DIR/.venv"
source "$INSTALL_DIR/.venv/bin/activate"
python -m pip install -U pip
python -m pip install -r "$INSTALL_DIR/requirements.txt"
deactivate

read -rp "서버 주소 (예: example.com): " SERVER_HOST
read -rp "SSL 인증서(HTTPS) 사용 중인가요? [y/N]: " USE_SSL
USE_SSL=${USE_SSL:-N}

if [[ "${USE_SSL^^}" == "Y" ]]; then
  WS_URL="wss://${SERVER_HOST}/_ws"
else
  WS_URL="ws://${SERVER_HOST}/_ws"
fi

read -rp "서브도메인 (예: mybox): " SUBDOMAIN
read -rp "토큰(화이트리스트; 없으면 Enter): " TOKEN
read -rp "HTTP 로컬 베이스(예: http://127.0.0.1:8000 없으면 Enter): " HTTPBASE
read -rp "TCP 매핑(예: ssh=127.0.0.1:22,db=127.0.0.1:5432) 없으면 Enter: " TCPMAPS
read -rp "UDP 매핑(예: dns=127.0.0.1:53) 없으면 Enter: " UDPMAPS

ARGS=()
[[ -n "${HTTPBASE}" ]] && ARGS+=(--http "${HTTPBASE}")

IFS=',' read -ra TARR <<< "${TCPMAPS}"
for x in "${TARR[@]}"; do
  [[ -z "$x" ]] && continue
  ARGS+=(--tcp "$x")
done

IFS=',' read -ra UARR <<< "${UDPMAPS}"
for x in "${UARR[@]}"; do
  [[ -z "$x" ]] && continue
  ARGS+=(--udp "$x")
done

RUN_SH="${INSTALL_DIR}/run_client.sh"
cat > "$RUN_SH" <<EOF
#!/usr/bin/env bash
source "${INSTALL_DIR}/.venv/bin/activate"
exec python "${INSTALL_DIR}/client.py" "${WS_URL}" "${SUBDOMAIN}" "${TOKEN}" $(printf '"%s" ' "${ARGS[@]}")
EOF
chmod +x "$RUN_SH"

UNIT="/etc/systemd/system/tunneler-client.service"
cat > "$UNIT" <<EOF
[Unit]
Description=Tunneler Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${RUN_SH}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now tunneler-client.service

# 작업 끝나면 다시 ro
if command -v ro >/dev/null 2>&1; then
  ro
fi

echo
echo "=== 설치 완료 ==="
echo "서비스 상태 확인:"
echo "  systemctl status tunneler-client.service"
echo
echo "로그 확인:"
echo "  journalctl -u tunneler-client.service -f"
echo
echo "대시보드 예: http(s)://${SERVER_HOST}/dashboard"

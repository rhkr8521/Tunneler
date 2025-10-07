#!/usr/bin/env bash
set -euo pipefail

echo "=== Tunneler 클라이언트(Ubuntu) 설치 ==="
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip curl jq

INSTALL_DIR="${HOME}/.tunneler"
mkdir -p "$INSTALL_DIR"
cp -f client.py requirements.txt "$INSTALL_DIR"

python3 -m venv "$INSTALL_DIR/.venv"
source "$INSTALL_DIR/.venv/bin/activate"
pip install -U pip
pip install -r "$INSTALL_DIR/requirements.txt"
deactivate

# 서버주소만 입력 → SSL 사용 여부 질문 → WS URL 자동 생성
read -rp "서버 주소 (예: example.com): " SERVER_HOST
read -rp "SSL 인증서(HTTPS) 사용 중인가요? [y/N]: " USE_SSL; USE_SSL=${USE_SSL:-N}
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

ARGS=""
[[ -n "${HTTPBASE}" ]] && ARGS+=" --http ${HTTPBASE}"

IFS=',' read -ra TARR <<< "${TCPMAPS}"
for x in "${TARR[@]}"; do [[ -z "$x" ]] && continue; ARGS+=" --tcp ${x}"; done
IFS=',' read -ra UARR <<< "${UDPMAPS}"
for x in "${UARR[@]}"; do [[ -z "$x" ]] && continue; ARGS+=" --udp ${x}"; done

RUN_SH="${INSTALL_DIR}/run_client.sh"
cat > "$RUN_SH" <<EOF
#!/usr/bin/env bash
source "${INSTALL_DIR}/.venv/bin/activate"
exec python "${INSTALL_DIR}/client.py" "${WS_URL}" "${SUBDOMAIN}" "${TOKEN}" ${ARGS}
EOF
chmod +x "$RUN_SH"

UNIT="${HOME}/.config/systemd/user/tunneler-client.service"
mkdir -p "$(dirname "$UNIT")"
cat > "$UNIT" <<EOF
[Unit]
Description=Tunneler Client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${RUN_SH}
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

#linger 활성화 → 로그아웃해도 유지
sudo loginctl enable-linger "$(whoami)" >/dev/null
systemctl --user daemon-reload
systemctl --user enable --now tunneler-client

echo
echo "=== 설치 완료 ==="
echo "관리자 대시보드에서 현재 할당 포트를 확인하세요."
echo "대시보드 예: http(s)://${SERVER_HOST}/dashboard"


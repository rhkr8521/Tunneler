#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "root로 실행하세요. 예) sudo bash $0"
  exit 1
fi

echo "=== Tunneler 서버 설치 ==="

# OS 정보
ID=""; VERSION_ID=""
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
fi
UBU_MAJOR="${VERSION_ID%%.*}"

apt-get update -y

# 기본 패키지
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  nginx python3 python3-venv python3-pip ufw curl jq

# Ubuntu 24.04+ 에서는 ufw와 iptables-persistent가 충돌하므로 스킵
INSTALL_PERSISTENT_PKGS=1
if [[ "${ID}" == "ubuntu" && -n "${UBU_MAJOR}" && "${UBU_MAJOR}" -ge 24 ]]; then
  if dpkg -s ufw >/dev/null 2>&1; then
    INSTALL_PERSISTENT_PKGS=0
    echo "[INFO] Ubuntu ${VERSION_ID} + UFW 환경: iptables-persistent/netfilter-persistent 설치를 건너뜀"
  fi
fi

if [[ $INSTALL_PERSISTENT_PKGS -eq 1 ]]; then
  set +e
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent
  RC=$?
  set -e
  if [[ $RC -ne 0 ]]; then
    echo "[WARN] iptables-persistent/netfilter-persistent 설치 실패: 계속 진행합니다(방화벽 영구 저장은 스킵)."
  fi
fi

INSTALL_DIR="/opt/tunneler"
mkdir -p "$INSTALL_DIR"
[[ -f server.py && -f requirements.txt ]] || { echo "[오류] server.py/requirements.txt 가 현재 디렉토리에 필요합니다"; exit 1; }
cp -f server.py requirements.txt "$INSTALL_DIR"
chown -R root:root "$INSTALL_DIR"

# 로그 디렉터리 생성/권한 (실시간/회전 로그를 위해)
mkdir -p /var/log/tunneler
chown root:root /var/log/tunneler
chmod 755 /var/log/tunneler

python3 -m venv "$INSTALL_DIR/.venv"
source "$INSTALL_DIR/.venv/bin/activate"
pip install -U pip
pip install -r "$INSTALL_DIR/requirements.txt"
deactivate

read -rp "서버 도메인 (예: example.com): " DOMAIN
read -rp "와일드카드 서브도메인 사용? (*.${DOMAIN}) [Y/n]: " WCSUB; WCSUB=${WCSUB:-Y}
read -rp "서버 실행 포트(기본 8080): " APP_PORT; APP_PORT=${APP_PORT:-8080}
read -rp "TCP 포트 범위(기본 20000-20100): " TCP_RANGE; TCP_RANGE=${TCP_RANGE:-20000-20100}
read -rp "UDP 포트 범위(기본 21000-21100): " UDP_RANGE; UDP_RANGE=${UDP_RANGE:-21000-21100}
read -rp "초기 토큰 화이트리스트(쉼표, 비우면 무인증 허용): " TOKENS; TOKENS=${TOKENS:-}
read -rp "관리자 대시보드 아이디: " ADMIN_ID
read -rp "관리자 대시보드 비밀번호: " ADMIN_PW
read -rp "Let’s Encrypt로 HTTPS 설정? [y/N]: " USE_LE; USE_LE=${USE_LE:-N}

# 토큰/관리 상태 파일
echo "${TOKENS}" > /opt/tunneler/tokens.txt
chmod 600 /opt/tunneler/tokens.txt
mkdir -p /opt/tunneler
cat > /opt/tunneler/admin_state.json <<'JSON'
{"admin_ip_allow":[]}
JSON
chmod 600 /opt/tunneler/admin_state.json

# 환경파일
ENV_FILE="/etc/default/tunneler-server"
cat > "$ENV_FILE" <<EOF
BIND=0.0.0.0
PORT=${APP_PORT}
TCP_PORT_RANGE=${TCP_RANGE}
UDP_PORT_RANGE=${UDP_RANGE}
ADMIN_USERNAME=${ADMIN_ID}
ADMIN_PASSWORD=${ADMIN_PW}
TOK_FILE=/opt/tunneler/tokens.txt
ADMIN_STATE_FILE=/opt/tunneler/admin_state.json
LOG_LEVEL=INFO
EOF
chmod 600 "$ENV_FILE"

# systemd
cat > /etc/systemd/system/tunneler-server.service <<'EOF'
[Unit]
Description=Tunneler Server (Dashboard + WS)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/default/tunneler-server
WorkingDirectory=/opt/tunneler
ExecStart=/opt/tunneler/.venv/bin/python /opt/tunneler/server.py
Restart=always
RestartSec=3
User=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now tunneler-server

# Nginx
CONF="/etc/nginx/conf.d/tunneler.conf"

# 와일드카드 선택 시에도 루트 도메인 접근 허용되도록 둘 다 넣기
SERVER_NAME="${DOMAIN} .${DOMAIN}"
[[ "${WCSUB^^}" == "N" ]] && SERVER_NAME="${DOMAIN}"

# conf.d include 보장
if ! grep -q "conf.d/\*\.conf" /etc/nginx/nginx.conf; then
  sed -i 's@http {@http {\n    include /etc/nginx/conf.d/*.conf;@' /etc/nginx/nginx.conf
fi

# 프록시 표준 헤더 보강: X-Forwarded-For/Proto/Real-IP
cat > "$CONF" <<EOF
map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }
upstream tunnel_app { server 127.0.0.1:${APP_PORT}; }

server {
  listen 80;
  server_name ${SERVER_NAME};

  location /_ws {
    proxy_pass http://tunnel_app;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_read_timeout 3600s;
  }

  location /admin_ws  {
    proxy_pass http://tunnel_app/admin_ws;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Real-IP \$remote_addr;
  }

  location /dashboard { proxy_pass http://tunnel_app/dashboard; }
  location /api/      { proxy_pass http://tunnel_app/api/; }

  location / {
    proxy_pass http://tunnel_app;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_read_timeout 3600s;
    client_max_body_size 64m;
  }

  location = /_health { proxy_pass http://tunnel_app/_health; }
}
EOF

nginx -t && systemctl reload nginx

# 방화벽
TCP_START=${TCP_RANGE%-*}; TCP_END=${TCP_RANGE#*-}
UDP_START=${UDP_RANGE%-*};  UDP_END=${UDP_RANGE#*-}
echo "[FW] Open 80,443,${APP_PORT}; TCP ${TCP_START}-${TCP_END}; UDP ${UDP_START}-${UDP_END}"

# 즉시 반영(iptables)
if command -v iptables >/dev/null 2>&1; then
  iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT || true
  iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT || true
  iptables -I INPUT 1 -p tcp --dport ${APP_PORT} -j ACCEPT || true
  iptables -I INPUT 1 -p tcp --dport ${TCP_START}:${TCP_END} -j ACCEPT || true
  iptables -I INPUT 1 -p udp --dport ${UDP_START}:${UDP_END} -j ACCEPT || true

  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save || true
  else
    echo "[INFO] netfilter-persistent 없음: iptables 규칙은 재부팅 시 사라질 수 있습니다."
    echo "       지속성을 원하면 'ufw enable' 또는 netfilter-persistent 설치를 검토하세요."
  fi
fi

# UFW 규칙(활성화 상태이면 즉시 적용되고, 활성화하면 영구 유지됨)
if command -v ufw >/dev/null 2>&1; then
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
  ufw allow ${APP_PORT}/tcp || true
  ufw allow ${TCP_START}:${TCP_END}/tcp || true
  ufw allow ${UDP_START}:${UDP_END}/udp || true
  ufw reload || true
  echo "[INFO] UFW가 비활성화 상태라면 'ufw enable'로 켜야 재부팅 후에도 규칙이 유지됩니다."
fi

# HTTPS(선택)
if [[ "${USE_LE^^}" == "Y" ]]; then
  apt-get install -y certbot python3-certbot-nginx
  certbot --nginx -d "${DOMAIN}" --redirect || true
  systemctl reload nginx || true
fi

# 헬스 체크
echo "[CHECK] 백엔드 헬스 확인..."
if curl -fsS "http://${DOMAIN}/_health" >/dev/null 2>&1; then
  echo "[OK] 백엔드 응답 정상"
else
  echo "[WARN] 백엔드 200 응답 없음. 다음을 확인하세요:"
  echo "  - systemctl status tunneler-server -l"
  echo "  - journalctl -u tunneler-server -n 200"
fi

echo "=== 설치 완료 ==="
echo "- 관리자 대시보드: http://${DOMAIN}/dashboard  (또는 https)"
echo "- ID/비번: 설치 시 입력값 (브라우저 Basic Auth)"

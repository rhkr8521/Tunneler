#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "root로 실행하세요."
  exit 1
fi

DOMAIN=""
WCSUB="Y"
APP_PORT="8080"
TCP_RANGE="20000-20100"
UDP_RANGE="21000-21100"
TOKENS=""
ADMIN_ID=""
ADMIN_PW=""
USE_LE="N"
LE_EMAIL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)    DOMAIN="${2:-}"; shift 2 ;;
    --wildcard)  WCSUB="${2:-Y}"; shift 2 ;;
    --app-port)  APP_PORT="${2:-8080}"; shift 2 ;;
    --tcp-range) TCP_RANGE="${2:-20000-20100}"; shift 2 ;;
    --udp-range) UDP_RANGE="${2:-21000-21100}"; shift 2 ;;
    --tokens)    TOKENS="${2:-}"; shift 2 ;;
    --admin-id)  ADMIN_ID="${2:-}"; shift 2 ;;
    --admin-pw)  ADMIN_PW="${2:-}"; shift 2 ;;
    --use-le)    USE_LE="${2:-N}"; shift 2 ;;
    --le-email)  LE_EMAIL="${2:-}"; shift 2 ;;
    *)
      echo "[오류] 알 수 없는 인자: $1"
      exit 1
      ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  echo "[오류] --domain 이 필요합니다"
  exit 1
fi
if [[ -z "$ADMIN_ID" || -z "$ADMIN_PW" ]]; then
  echo "[오류] --admin-id / --admin-pw 가 필요합니다"
  exit 1
fi

# HTTPS 사용 시 이메일 필수 (setup_full.sh는 절대 입력창 띄우지 않음)
if [[ "${USE_LE^^}" == "Y" && -z "$LE_EMAIL" ]]; then
  echo "[오류] Let's Encrypt 사용 시 --le-email 이 필요합니다"
  exit 1
fi

if ! [[ "$APP_PORT" =~ ^[0-9]+$ ]]; then
  echo "[오류] app-port가 숫자가 아닙니다: $APP_PORT"
  exit 1
fi
if ! [[ "$TCP_RANGE" =~ ^[0-9]+-[0-9]+$ ]]; then
  echo "[오류] tcp-range 형식이 아닙니다(예: 20000-20100): $TCP_RANGE"
  exit 1
fi
if ! [[ "$UDP_RANGE" =~ ^[0-9]+-[0-9]+$ ]]; then
  echo "[오류] udp-range 형식이 아닙니다(예: 21000-21100): $UDP_RANGE"
  exit 1
fi

TCP_START="${TCP_RANGE%-*}"; TCP_END="${TCP_RANGE#*-}"
UDP_START="${UDP_RANGE%-*}"; UDP_END="${UDP_RANGE#*-}"

echo "=== Tunneler 서버 세팅 시작 ==="

INSTALL_DIR="/opt/tunneler"
mkdir -p "$INSTALL_DIR"

# 패키지에 반드시 포함돼 있어야 함
if [[ ! -f "$INSTALL_DIR/server.py" || ! -f "$INSTALL_DIR/requirements.txt" ]]; then
  echo "[오류] $INSTALL_DIR/server.py 및 requirements.txt가 없습니다. 패키지 설치 상태를 확인하세요."
  exit 1
fi

# 로그 디렉터리
install -d -m 0755 /var/log/tunneler

# 토큰 파일 (값 반영)
install -d -m 0755 /opt/tunneler
printf "%s\n" "${TOKENS}" > /opt/tunneler/tokens.txt
chmod 600 /opt/tunneler/tokens.txt

# admin_state.json (없을 때만 생성)
if [[ ! -f /opt/tunneler/admin_state.json ]]; then
  cat > /opt/tunneler/admin_state.json <<'JSON'
{"admin_ip_allow":[]}
JSON
  chmod 600 /opt/tunneler/admin_state.json
fi

# ==========================================================
#  /etc/default/tunneler-server는 "설치 입력값이 이김"
# - 기존 파일이 있더라도(예: 이전 테스트 설치) 이번 설치값으로 갱신
# - 대신 백업을 남겨서 사용자가 원하면 복구 가능
# ==========================================================
ENV_FILE="/etc/default/tunneler-server"
mkdir -p /etc/default

if [[ -f "$ENV_FILE" ]]; then
  TS="$(date +%Y%m%d-%H%M%S)"
  cp -a "$ENV_FILE" "${ENV_FILE}.bak.${TS}" || true
  echo "[INFO] 기존 $ENV_FILE 백업: ${ENV_FILE}.bak.${TS}"
fi

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

# systemd 서비스 파일(없으면 생성)
SERVICE_FILE="/etc/systemd/system/tunneler-server.service"
if [[ ! -f "$SERVICE_FILE" ]]; then
  cat > "$SERVICE_FILE" <<'EOF'
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
fi

# venv + deps
if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
  python3 -m venv "$INSTALL_DIR/.venv"
fi
source "$INSTALL_DIR/.venv/bin/activate"
pip install -U pip
pip install -r "$INSTALL_DIR/requirements.txt"
deactivate

systemctl daemon-reload
systemctl enable --now tunneler-server || true

# ===== Nginx =====
CONF="/etc/nginx/conf.d/tunneler.conf"

SERVER_NAME="${DOMAIN} .${DOMAIN}"
[[ "${WCSUB^^}" == "N" ]] && SERVER_NAME="${DOMAIN}"

# conf.d include 보장
if ! grep -q "conf.d/\*\.conf" /etc/nginx/nginx.conf; then
  sed -i 's@http {@http {\n    include /etc/nginx/conf.d/*.conf;@' /etc/nginx/nginx.conf
fi

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

nginx -t
systemctl reload nginx

# ==========================================================
# ===== 방화벽: UFW만 사용 + iptables "복원/관리" 서비스 끄기 =====
# ==========================================================
echo "[FW] 정책: UFW만 사용(iptables 직접 관리/복원 서비스 비활성화)"
echo "[FW] Open 80,443,${APP_PORT}; TCP ${TCP_START}-${TCP_END}; UDP ${UDP_START}-${UDP_END}"

if ! command -v ufw >/dev/null 2>&1; then
  echo "[WARN] ufw가 없습니다. 패키지 Depends에 ufw가 있어야 합니다."
  echo "       수동 설치: sudo apt-get update && sudo apt-get install -y ufw"
else
  # 1) iptables 규칙을 부팅 시 자동 복원하는 서비스 비활성화/마스킹(정석)
  if systemctl list-unit-files | grep -q '^netfilter-persistent\.service'; then
    systemctl stop netfilter-persistent.service || true
    systemctl disable netfilter-persistent.service || true
    systemctl mask netfilter-persistent.service || true
    echo "[FW] netfilter-persistent.service disabled/masked"
  fi
  if systemctl list-unit-files | grep -q '^iptables-persistent\.service'; then
    systemctl stop iptables-persistent.service || true
    systemctl disable iptables-persistent.service || true
    systemctl mask iptables-persistent.service || true
    echo "[FW] iptables-persistent.service disabled/masked"
  fi

  # 2) "외부가 안 들어오는" 꼬임이 있을 때만 정리 (무작정 flush 최소화)
  NEED_CLEAN="N"
  if command -v iptables >/dev/null 2>&1; then
    # policy DROP이거나, INPUT에 icmp-host-prohibited 류의 REJECT가 앞단에 박혀 있으면 정리 필요
    if iptables -S INPUT 2>/dev/null | head -n 1 | grep -q '\-P INPUT DROP'; then
      NEED_CLEAN="Y"
    fi
    if iptables -S INPUT 2>/dev/null | grep -q 'icmp-host-prohibited'; then
      NEED_CLEAN="Y"
    fi
  fi
  if command -v nft >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -q 'hook input priority filter; policy drop'; then
      NEED_CLEAN="Y"
    fi
  fi

  if [[ "$NEED_CLEAN" == "Y" ]]; then
    echo "[FW] 감지: iptables/nft 꼬임(정책 DROP/REJECT). UFW 적용을 위해 정리합니다."

    # nft policy drop 꼬임이면 flush ruleset (UFW가 다시 세팅)
    if command -v nft >/dev/null 2>&1; then
      if nft list ruleset 2>/dev/null | grep -q 'hook input priority filter; policy drop'; then
        nft flush ruleset || true
      fi
    fi

    # iptables 쪽 꼬임 정리 (iptables-nft 환경에서도 효과)
    if command -v iptables >/dev/null 2>&1; then
      iptables -F || true
      iptables -X || true
      iptables -t nat -F || true
      iptables -t nat -X || true
      iptables -t mangle -F || true
      iptables -t mangle -X || true
      iptables -P INPUT ACCEPT || true
      iptables -P FORWARD ACCEPT || true
      iptables -P OUTPUT ACCEPT || true
    fi
  else
    echo "[FW] iptables/nft 심각한 꼬임 미감지: flush 생략"
  fi

  # 3) UFW를 "UFW만" 상태로 재구성
  ufw --force reset || true
  ufw default deny incoming || true
  ufw default allow outgoing || true

  # 원격이면 SSH는 필수
  ufw allow 22/tcp || true

  # 요구 포트 오픈
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
  ufw allow "${APP_PORT}/tcp" || true
  ufw allow "${TCP_START}:${TCP_END}/tcp" || true
  ufw allow "${UDP_START}:${UDP_END}/udp" || true

  ufw --force enable || true
  ufw reload || true

  echo "[FW] UFW status:"
  ufw status verbose || true
fi

# ===== HTTPS(선택) =====
# - USE_LE=Y면 이메일은 필수(위에서 이미 검증)
# - certbot 없으면 설치하지 않고 경고만 (dpkg lock 방지)
if [[ "${USE_LE^^}" == "Y" ]]; then
  if ! command -v certbot >/dev/null 2>&1; then
    echo "[WARN] certbot이 설치되어 있지 않습니다. HTTPS 자동 설정을 건너뜁니다."
    echo "       (권장) sudo apt install certbot python3-certbot-nginx"
  else
    echo "[LE] 사전 점검: nginx 80 리스닝 확인"
    if ! ss -lntp | grep -q ':80 '; then
      echo "[ERROR] nginx가 80 포트를 리슨하지 않습니다. certbot을 진행할 수 없습니다."
      exit 1
    fi

    certbot --nginx \
      -d "${DOMAIN}" \
      -m "${LE_EMAIL}" \
      --agree-tos \
      --non-interactive \
      --redirect || true

    systemctl reload nginx || true
  fi
fi

# ===== 헬스 체크 =====
echo "[CHECK] 백엔드 헬스 확인..."
if curl -fsS "http://127.0.0.1:${APP_PORT}/_health" >/dev/null 2>&1; then
  echo "[OK] 백엔드 응답 정상"
else
  echo "[WARN] 백엔드 200 응답 없음. 다음을 확인:"
  echo "  - systemctl status tunneler-server -l"
  echo "  - journalctl -u tunneler-server -n 200"
fi

echo "=== Tunneler 서버 세팅 완료 ==="
echo "- 관리자 대시보드: http://${DOMAIN}/dashboard (또는 https) 로 접속하십시오."
echo "- 클라이언트 터널 접속 URI : ${DOMAIN}"

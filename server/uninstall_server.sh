#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "root 권한으로 실행하세요. 예) sudo bash $0"
  exit 1
fi

echo "=== Tunneler 서버  ==="

SERVICE_NAME="tunneler-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/default/${SERVICE_NAME}"
APP_DIR="/opt/tunneler"
NGX_CONF="/etc/nginx/conf.d/tunneler.conf"

# 1) 서비스 중지/비활성화
echo "[1/6] systemd 서비스 중지/비활성화"
set +e
systemctl stop "${SERVICE_NAME}"
systemctl disable "${SERVICE_NAME}"
set -e

# 2) 포트 범위/앱 포트 읽기 (있으면 방화벽에서 닫을 때 사용)
APP_PORT=""
TCP_RANGE=""
UDP_RANGE=""
if [[ -f "$ENV_FILE" ]]; then
  echo "[정보] ${ENV_FILE}에서 환경 변수 로드"
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a
  APP_PORT="${PORT:-${APP_PORT:-}}"
  TCP_RANGE="${TCP_PORT_RANGE:-}"
  UDP_RANGE="${UDP_PORT_RANGE:-}"
fi

# 3) Nginx 설정 제거 및 reload
echo "[2/6] Nginx 설정 제거 및 재로드"
if [[ -f "$NGX_CONF" ]]; then
  rm -f "$NGX_CONF"
  if nginx -t; then
    systemctl reload nginx
  else
    echo "[경고] nginx 설정 검증 실패(무시). 수동 확인 필요"
  fi
else
  echo "[정보] ${NGX_CONF} 없음(이미 제거되었을 수 있음)"
fi

# 4) 방화벽 규칙 회수(가능한 경우에 한해)
echo "[3/6] 방화벽 규칙 회수 시도(iptables/ufw)"

# iptables: 설치 때 넣었던 규칙 역삭제 (실패해도 계속)
if command -v iptables >/dev/null 2>&1; then
  echo " - iptables 규칙 제거 시도"
  # 단일 포트들
  for p in 80 443; do
    iptables -C INPUT -p tcp --dport $p -j ACCEPT 2>/dev/null && iptables -D INPUT -p tcp --dport $p -j ACCEPT || true
  done
  if [[ -n "${APP_PORT}" ]]; then
    iptables -C INPUT -p tcp --dport "${APP_PORT}" -j ACCEPT 2>/dev/null && iptables -D INPUT -p tcp --dport "${APP_PORT}" -j ACCEPT || true
  fi
  # 범위 포트들
  if [[ -n "${TCP_RANGE}" && "${TCP_RANGE}" == *"-"* ]]; then
    TCP_START=${TCP_RANGE%-*}; TCP_END=${TCP_RANGE#*-}
    iptables -C INPUT -p tcp --dport ${TCP_START}:${TCP_END} -j ACCEPT 2>/dev/null && iptables -D INPUT -p tcp --dport ${TCP_START}:${TCP_END} -j ACCEPT || true
  fi
  if [[ -n "${UDP_RANGE}" && "${UDP_RANGE}" == *"-"* ]]; then
    UDP_START=${UDP_RANGE%-*}; UDP_END=${UDP_RANGE#*-}
    iptables -C INPUT -p udp --dport ${UDP_START}:${UDP_END} -j ACCEPT 2>/dev/null && iptables -D INPUT -p udp --dport ${UDP_START}:${UDP_END} -j ACCEPT || true
  fi
  # iptables-persistent 저장
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save || true
  fi
fi

# ufw: 규칙 삭제 (존재하면)
if command -v ufw >/dev/null 2>&1; then
  echo " - ufw 규칙 제거 시도"
  ufw --force delete allow 80/tcp >/dev/null 2>&1 || true
  ufw --force delete allow 443/tcp >/dev/null 2>&1 || true
  if [[ -n "${APP_PORT}" ]]; then
    ufw --force delete allow "${APP_PORT}"/tcp >/dev/null 2>&1 || true
  fi
  if [[ -n "${TCP_RANGE}" && "${TCP_RANGE}" == *"-"* ]]; then
    ufw --force delete allow ${TCP_RANGE}/tcp >/dev/null 2>&1 || true
  fi
  if [[ -n "${UDP_RANGE}" && "${UDP_RANGE}" == *"-"* ]]; then
    ufw --force delete allow ${UDP_RANGE}/udp >/dev/null 2>&1 || true
  fi
  ufw reload >/dev/null 2>&1 || true
fi

# 5) 파일/디렉토리 정리
echo "[4/6] 파일/디렉토리 정리"

# systemd 유닛 제거
if [[ -f "$SERVICE_FILE" ]]; then
  rm -f "$SERVICE_FILE"
fi
systemctl daemon-reload || true

# 환경파일 제거
if [[ -f "$ENV_FILE" ]]; then
  rm -f "$ENV_FILE"
fi

# 애플리케이션 디렉토리 제거 여부 질의
if [[ -d "$APP_DIR" ]]; then
  read -rp "[질의] ${APP_DIR} 디렉토리를 삭제할까요? [y/N]: " DELAPP
  DELAPP=${DELAPP:-N}
  if [[ "${DELAPP^^}" == "Y" ]]; then
    rm -rf "$APP_DIR"
    echo " - ${APP_DIR} 삭제 완료"
  else
    echo " - ${APP_DIR} 유지함"
  fi
fi

# 6) 잔여 프로세스/포트 확인 안내
echo "[5/6] 잔여 프로세스/포트 확인(선택)"
echo "     - 필요 시: lsof -i :8080 등으로 포트 점유 확인"
echo "     - nginx는 그대로 유지됩니다."

echo "[6/6] 정리 완료"

echo "=== Tunneler 서버 제거 완료 ==="
echo "- 확인:"
echo "  systemctl status ${SERVICE_NAME}    # inactive 또는 not-found 여야 정상"
echo "  ls ${NGX_CONF}                      # 파일이 없어야 정상"
echo "  ls ${ENV_FILE}                      # 파일이 없어야 정상"


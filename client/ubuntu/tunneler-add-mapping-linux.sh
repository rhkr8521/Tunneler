#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${HOME}/.tunneler"
RUN_SH="${INSTALL_DIR}/run_client.sh"
USER_UNIT="${HOME}/.config/systemd/user/tunneler-client.service"
ROOT_UNIT="/etc/systemd/system/tunneler-client.service"

[[ -f "$RUN_SH" ]] || { echo "[에러] ${RUN_SH} 가 없습니다. 클라이언트를 먼저 설치하세요."; exit 1; }

# jq/curl 보조 도구
if ! command -v jq >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  echo "[알림] jq/curl 설치 중..."
  sudo apt-get update -y
  sudo apt-get install -y jq curl
fi

EXEC_LINE="$(grep -E '^exec python .*/client\.py' "$RUN_SH" || true)"
if [[ -z "$EXEC_LINE" ]]; then
  echo "[에러] run_client.sh 형식을 인식하지 못했습니다."; exit 1
fi

# 현재 설정 파싱
WS_URL="$(echo "$EXEC_LINE" | sed -E 's#.*client\.py" "([^"]+)".*#\1#')"
SUBDOMAIN="$(echo "$EXEC_LINE" | sed -E 's#.*client\.py" "[^"]+" "([^"]+)".*#\1#')"

list_current() {
  echo "=== 현재 매핑 ==="
  echo "WS_URL : $WS_URL"
  echo "SUBDOM : $SUBDOMAIN"
  echo "HTTP   : $(echo "$EXEC_LINE" | grep -oE ' --http [^ ]+' | sed 's/^ --http //')"
  echo "TCP    :"
  echo "$EXEC_LINE" | grep -oE ' --tcp [^ ]+' | sed 's/^ --tcp //;t;d' | sed 's/^/  - /' || true
  echo "UDP    :"
  echo "$EXEC_LINE" | grep -oE ' --udp [^ ]+' | sed 's/^ --udp //;t;d' | sed 's/^/  - /' || true
}

remove_flag_by_name () {
  local line="$1" kind="$2" name="$3"
  # name= 뒤에 오는 값 전체 제거
  echo "$line" | sed -E "s# --${kind} ${name}=[^ ]*##g"
}

echo "=== 새 포트 매핑 추가/삭제 ==="
list_current
echo

read -rp "추가할 TCP(예: web=127.0.0.1:8080,db=127.0.0.1:5432) 없으면 Enter: " TCP_ADD
read -rp "삭제할 TCP 이름(예: web,db) 없으면 Enter: " TCP_DEL
read -rp "추가할 UDP(예: dns=127.0.0.1:53) 없으면 Enter: " UDP_ADD
read -rp "삭제할 UDP 이름(예: dns) 없으면 Enter: " UDP_DEL

NEW_EXEC="$EXEC_LINE"

# 삭제부터 적용 (이름만으로 제거)
IFS=',' read -ra DARR <<< "${TCP_DEL}"
for name in "${DARR[@]}"; do
  name="$(echo "$name" | xargs)"; [[ -z "$name" ]] && continue
  NEW_EXEC="$(remove_flag_by_name "$NEW_EXEC" "tcp" "$name")"
done
IFS=',' read -ra DARR2 <<< "${UDP_DEL}"
for name in "${DARR2[@]}"; do
  name="$(echo "$name" | xargs)"; [[ -z "$name" ]] && continue
  NEW_EXEC="$(remove_flag_by_name "$NEW_EXEC" "udp" "$name")"
done

# 추가 적용 (name=host:port)
IFS=',' read -ra TARR <<< "${TCP_ADD}"
for kv in "${TARR[@]}"; do
  kv="$(echo "$kv" | xargs)"; [[ -z "$kv" ]] && continue
  if [[ "$kv" != *"="* || "$kv" != *":"* ]]; then
    echo "[경고] 잘못된 TCP: $kv  (예: web=127.0.0.1:8080)"; continue
  fi
  name="${kv%%=*}"
  NEW_EXEC="$(remove_flag_by_name "$NEW_EXEC" "tcp" "$name")"
  NEW_EXEC+=" --tcp ${kv}"
done
IFS=',' read -ra UARR <<< "${UDP_ADD}"
for kv in "${UARR[@]}"; do
  kv="$(echo "$kv" | xargs)"; [[ -z "$kv" ]] && continue
  if [[ "$kv" != *"="* || "$kv" != *":"* ]]; then
    echo "[경고] 잘못된 UDP: $kv  (예: dns=127.0.0.1:53)"; continue
  fi
  name="${kv%%=*}"
  NEW_EXEC="$(remove_flag_by_name "$NEW_EXEC" "udp" "$name")"
  NEW_EXEC+=" --udp ${kv}"
done

# 저장
if [[ "$NEW_EXEC" != "$EXEC_LINE" ]]; then
  tmp="$(mktemp)"
  sed -E "s#^exec python .*/client\.py.*#$(printf '%s\n' "$NEW_EXEC" | sed -e 's/[\/&]/\\&/g')#" "$RUN_SH" > "$tmp"
  mv "$tmp" "$RUN_SH"; chmod +x "$RUN_SH"
  echo "[OK] run_client.sh 업데이트 완료"
else
  echo "[정보] 변경 사항 없음"
fi

# 재시작
echo "[정보] 클라이언트 서비스 재시작..."
set +e
systemctl --user restart tunneler-client 2>/dev/null
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
  if [[ -f "$ROOT_UNIT" ]]; then
    sudo systemctl restart tunneler-client
  else
    echo "[경고] 재시작 실패. 'systemctl --user status tunneler-client -l' 로 확인하세요."
  fi
fi

# 결과 표시
echo
list_current
echo
echo "=== 서버에서 배정된 원격 포트 ==="
SCHEME="$(echo "${WS_URL}" | sed -E 's#^(ws|wss)://.*#\1#')"
HOSTPORT="$(echo "${WS_URL}" | sed -E 's#^(ws|wss)://##' | cut -d'/' -f1)"
[[ "$SCHEME" == "wss" ]] && BASE="https://${HOSTPORT}" || BASE="http://${HOSTPORT}"

set +e
HEALTH_JSON="$(curl -ksS --max-time 5 "${BASE}/_health")"
if [[ $? -eq 0 && -n "$HEALTH_JSON" ]]; then
  echo "$HEALTH_JSON" | jq -r --arg sd "$SUBDOMAIN" '
    .tunnels[$sd] as $t
    | if $t == null then
        "  (서브도메인 없음: 연결/토큰/WS URL 확인)"
      else
        "  TCP: " + ( ($t.tcp // {}) | to_entries | map(.key + "=" + (.value|tostring)) | join(", ") )
        + "\n  UDP: " + ( ($t.udp // {}) | to_entries | map(.key + "=" + (.value|tostring)) | join(", ") )
      end
  '
else
  echo "(헬스 조회 실패)"
fi
set -e


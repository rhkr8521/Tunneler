#!/usr/bin/env bash
# macOS Tunneler 클라이언트 설치 (안전한 LaunchAgent 방식 - 최종 수정판)
set -euo pipefail

die() { echo "[에러] $*" >&2; exit 1; }

echo "=== Tunneler 클라이언트(macOS) 설치 ==="

# ----- 사용자 경로 정의 -----
INSTALL_DIR="${HOME}/.tunneler"
PLIST_PATH="${HOME}/Library/LaunchAgents/com.tunneler.client.plist"

# ----- Homebrew 및 Python3 확인 -----
PYTHON3="$(command -v python3 || true)"
if [[ -z "${PYTHON3}" ]]; then
  echo "[알림] python3를 찾을 수 없습니다. Homebrew를 통해 설치를 시도합니다."
  if ! command -v brew >/dev/null 2&>1; then die "Homebrew가 설치되어 있지 않습니다."; fi
  brew update && brew install python3
  PYTHON3="$(command -v python3 || true)"
  [[ -n "${PYTHON3}" ]] || die "python3 설치에 실패했습니다."
fi

# ----- 파일 준비 -----
[[ -f "client.py" && -f "requirements.txt" ]] || die "현재 폴더에 client.py와 requirements.txt가 필요합니다."
echo "[1/4] 설치 디렉터리 생성 및 파일 복사..."
mkdir -p "${INSTALL_DIR}"
cp -f client.py requirements.txt "${INSTALL_DIR}/"

echo "[2/4] 파이썬 가상환경 설정..."
"${PYTHON3}" -m venv "${INSTALL_DIR}/.venv"
source "${INSTALL_DIR}/.venv/bin/activate"
pip install -U pip
pip install -r "${INSTALL_DIR}/requirements.txt"
deactivate

# ----- 사용자 입력 -----
echo "[3/4] 클라이언트 설정 입력..."
read -rp "서버 주소 (예: example.com): " SERVER_HOST
[[ -n "${SERVER_HOST}" ]] || die "서버 주소가 비었습니다."
read -rp "SSL 인증서(HTTPS) 사용? [y/N]: " USE_SSL; USE_SSL="${USE_SSL:-N}"
case "$USE_SSL" in y|Y) WS_URL="wss://${SERVER_HOST}/_ws" ;; *) WS_URL="ws://${SERVER_HOST}/_ws" ;; esac
read -rp "서브도메인 (예: mybox): " SUBDOMAIN
[[ -n "${SUBDOMAIN}" ]] || die "서브도메인이 비었습니다."
read -rp "토큰(화이트리스트; 없으면 Enter): " TOKEN
read -rp "HTTP 로컬 베이스(예: http://127.0.0.1:8000 없으면 Enter): " HTTPBASE
read -rp "TCP 매핑(예: ssh=127.0.0.1:22,db=127.0.0.1:5432) 없으면 Enter: " TCPMAPS
read -rp "UDP 매핑(예: dns=127.0.0.1:53) 없으면 Enter: " UDPMAPS

# ----- LaunchAgent plist 작성 -----
echo "[4/4] 사용자 서비스(LaunchAgent) 설정..."
VENV_PY="${INSTALL_DIR}/.venv/bin/python"
CLIENT_PY="${INSTALL_DIR}/client.py"

mkdir -p "$(dirname "${PLIST_PATH}")"

# ProgramArguments 배열 생성
PROGRAM_ARGS=("$VENV_PY" "$CLIENT_PY" "$WS_URL" "$SUBDOMAIN" "$TOKEN")
[[ -n "$HTTPBASE" ]] && PROGRAM_ARGS+=("--http" "$HTTPBASE")

# 쉼표로 구분된 여러 TCP 매핑을 처리하는 로직
if [[ -n "$TCPMAPS" ]]; then
    OLD_IFS="$IFS"; IFS=','
    read -ra TARR <<< "$TCPMAPS"
    IFS="$OLD_IFS"
    for x in "${TARR[@]:-}"; do
        x_trimmed="$(echo "$x" | xargs)"
        [[ -n "$x_trimmed" ]] && PROGRAM_ARGS+=("--tcp" "$x_trimmed")
    done
fi

# 쉼표로 구분된 여러 UDP 매핑을 처리하는 로직
if [[ -n "$UDPMAPS" ]]; then
    OLD_IFS="$IFS"; IFS=','
    read -ra UARR <<< "$UDPMAPS"
    IFS="$OLD_IFS"
    for x in "${UARR[@]:-}"; do
        x_trimmed="$(echo "$x" | xargs)"
        [[ -n "$x_trimmed" ]] && PROGRAM_ARGS+=("--udp" "$x_trimmed")
    done
fi

args_xml() { for tok in "$@"; do safe="${tok//&/&amp;}"; safe="${safe//</&lt;}"; safe="${safe//>/&gt;}"; printf '    <string>%s</string>\n' "$safe"; done; }
PROGRAM_ARGS_XML=$(args_xml "${PROGRAM_ARGS[@]}")

cat > "${PLIST_PATH}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.tunneler.client</string>
    <key>ProgramArguments</key>
    <array>
${PROGRAM_ARGS_XML}
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>${INSTALL_DIR}/client.out.log</string>
    <key>StandardErrorPath</key><string>${INSTALL_DIR}/client.err.log</string>
</dict>
</plist>

EOF

plutil -lint "${PLIST_PATH}" || die "plist 파일 생성 오류"

# ----- launchctl 사용자 서비스로 등록 -----
launchctl unload "${PLIST_PATH}" 2>/dev/null || true
launchctl load "${PLIST_PATH}"

echo
echo "=== 설치 완료 ==="
echo "관리자 대시보드에서 현재 할당 포트를 확인하세요."
echo "대시보드 예: http(s)://${SERVER_HOST}/dashboard"
echo " "
echo "이제부터 Mac에 로그인하면 클라이언트가 자동으로 시작됩니다."
echo "- 로그 확인: tail -f ${INSTALL_DIR}/client.out.log"

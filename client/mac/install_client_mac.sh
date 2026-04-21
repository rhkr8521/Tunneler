#!/usr/bin/env bash
# macOS Tunneler 클라이언트 설치 (안전한 LaunchAgent 방식 - 최종 수정판)
set -euo pipefail

detect_ui_lang() {
  local locale="${LC_ALL:-${LANG:-${LANGUAGE:-en}}}"
  locale="$(printf '%s' "$locale" | tr '[:upper:]' '[:lower:]')"
  [[ "$locale" == ko* ]] && printf 'ko' || printf 'en'
}
UI_LANG="$(detect_ui_lang)"
trmsg() {
  if [[ "$UI_LANG" == "ko" ]]; then
    printf '%s' "$1"
  else
    printf '%s' "$2"
  fi
}
die() { echo "$(trmsg "[에러] $*" "[ERROR] $*")" >&2; exit 1; }

echo "$(trmsg "=== Tunneler 클라이언트(macOS) 설치 ===" "=== Tunneler Client Installation (macOS) ===")"

# ----- 사용자 경로 정의 -----
INSTALL_DIR="${HOME}/.tunneler"
PLIST_PATH="${HOME}/Library/LaunchAgents/com.tunneler.client.plist"

# ----- Homebrew 및 Python3 확인 -----
PYTHON3="$(command -v python3 || true)"
if [[ -z "${PYTHON3}" ]]; then
  echo "$(trmsg "[알림] python3를 찾을 수 없습니다. Homebrew를 통해 설치를 시도합니다." "[INFO] python3 was not found. Attempting installation via Homebrew.")"
  if ! command -v brew >/dev/null 2&>1; then die "$(trmsg "Homebrew가 설치되어 있지 않습니다." "Homebrew is not installed.")"; fi
  brew update && brew install python3
  PYTHON3="$(command -v python3 || true)"
  [[ -n "${PYTHON3}" ]] || die "$(trmsg "python3 설치에 실패했습니다." "Failed to install python3.")"
fi

# ----- 파일 준비 -----
[[ -f "client.py" && -f "requirements.txt" ]] || die "$(trmsg "현재 폴더에 client.py와 requirements.txt가 필요합니다." "client.py and requirements.txt must exist in the current directory.")"
echo "$(trmsg "[1/4] 설치 디렉터리 생성 및 파일 복사..." "[1/4] Creating installation directory and copying files...")"
mkdir -p "${INSTALL_DIR}"
cp -f client.py requirements.txt "${INSTALL_DIR}/"

echo "$(trmsg "[2/4] 파이썬 가상환경 설정..." "[2/4] Preparing Python virtual environment...")"
"${PYTHON3}" -m venv "${INSTALL_DIR}/.venv"
source "${INSTALL_DIR}/.venv/bin/activate"
pip install -U pip
pip install -r "${INSTALL_DIR}/requirements.txt"
deactivate

# ----- 사용자 입력 -----
echo "$(trmsg "[3/4] 클라이언트 설정 입력..." "[3/4] Entering client configuration...")"
read -rp "$(trmsg "서버 주소 (예: example.com): " "Server address (e.g. example.com): ")" SERVER_HOST
[[ -n "${SERVER_HOST}" ]] || die "$(trmsg "서버 주소가 비었습니다." "Server address is empty.")"
read -rp "$(trmsg "SSL 인증서(HTTPS) 사용? [y/N]: " "Use an SSL certificate (HTTPS)? [y/N]: ")" USE_SSL; USE_SSL="${USE_SSL:-N}"
case "$USE_SSL" in y|Y) WS_URL="wss://${SERVER_HOST}/_ws" ;; *) WS_URL="ws://${SERVER_HOST}/_ws" ;; esac
read -rp "$(trmsg "서브도메인 (예: mybox): " "Subdomain (e.g. mybox): ")" SUBDOMAIN
[[ -n "${SUBDOMAIN}" ]] || die "$(trmsg "서브도메인이 비었습니다." "Subdomain is empty.")"
read -rp "$(trmsg "토큰(화이트리스트; 없으면 Enter): " "Token (whitelist; press Enter if unused): ")" TOKEN
read -rp "$(trmsg "HTTP 로컬 베이스(예: http://127.0.0.1:8000 없으면 Enter): " "Local HTTP base (e.g. http://127.0.0.1:8000, press Enter to skip): ")" HTTPBASE
read -rp "$(trmsg "TCP 매핑(예: ssh=127.0.0.1:22,db=127.0.0.1:5432) 없으면 Enter: " "TCP mappings (e.g. ssh=127.0.0.1:22,db=127.0.0.1:5432, press Enter to skip): ")" TCPMAPS
read -rp "$(trmsg "UDP 매핑(예: dns=127.0.0.1:53) 없으면 Enter: " "UDP mappings (e.g. dns=127.0.0.1:53, press Enter to skip): ")" UDPMAPS

# ----- LaunchAgent plist 작성 -----
echo "$(trmsg "[4/4] 사용자 서비스(LaunchAgent) 설정..." "[4/4] Configuring user service (LaunchAgent)...")"
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

plutil -lint "${PLIST_PATH}" || die "$(trmsg "plist 파일 생성 오류" "Failed to create the plist file.")"

# ----- launchctl 사용자 서비스로 등록 -----
launchctl unload "${PLIST_PATH}" 2>/dev/null || true
launchctl load "${PLIST_PATH}"

echo
echo "$(trmsg "=== 설치 완료 ===" "=== Installation Complete ===")"
echo "$(trmsg "관리자 대시보드에서 현재 할당 포트를 확인하세요." "Check the currently assigned ports in the admin dashboard.")"
echo "$(trmsg "대시보드 예: http(s)://${SERVER_HOST}/dashboard" "Dashboard example: http(s)://${SERVER_HOST}/dashboard")"
echo " "
echo "$(trmsg "이제부터 Mac에 로그인하면 클라이언트가 자동으로 시작됩니다." "The client will now start automatically when you log in to macOS.")"
echo "$(trmsg "- 로그 확인: tail -f ${INSTALL_DIR}/client.out.log" "- Log output: tail -f ${INSTALL_DIR}/client.out.log")"

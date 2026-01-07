#!/usr/bin/env bash
# macOS Tunneler 클라이언트 제거 (안전한 LaunchAgent 방식)
set -euo pipefail

echo "=== Tunneler 클라이언트(macOS) 제거 ==="

# ----- 사용자 경로 정의 -----
# 설치 스크립트와 동일한 경로를 타겟으로 합니다.
INSTALL_DIR="${HOME}/.tunneler"
PLIST_PATH="${HOME}/Library/LaunchAgents/com.tunneler.client.plist"

# 1. launchd에서 서비스 내리기 (unload)
echo "[1/2] 서비스 중지 및 해제..."
# 파일이 존재할 경우에만 unload를 시도하여 불필요한 에러 메시지를 방지합니다.
if [[ -f "$PLIST_PATH" ]]; then
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
fi

# 2. 관련 파일 및 디렉터리 전체 삭제
echo "[2/2] 관련 파일 및 디렉터리 삭제..."
rm -f "$PLIST_PATH"
rm -rf "$INSTALL_DIR"

echo
echo "=== 제거 완료 ==="

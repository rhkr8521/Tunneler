#!/usr/bin/env bash
set -euo pipefail

echo "=== Tunneler 클라이언트 제거 ==="
RUN_SH="${HOME}/.tunneler/run_client.sh"
USER_UNIT="${HOME}/.config/systemd/user/tunneler-client.service"
APP_DIR="${HOME}/.tunneler"

set +e
systemctl --user disable --now tunneler-client 2>/dev/null
set -e
[[ -f "$USER_UNIT" ]] && { rm -f "$USER_UNIT"; systemctl --user daemon-reload || true; }
rm -rf "$APP_DIR" || true
echo "=== 완료 ==="


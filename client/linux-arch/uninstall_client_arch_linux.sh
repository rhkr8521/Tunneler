#!/usr/bin/env bash
set -euo pipefail

echo "=== Tunneler 클라이언트 제거 (Arch / PiKVM) ==="

SERVICE_NAME="tunneler-client.service"
UNIT="/etc/systemd/system/${SERVICE_NAME}"
RUN_SH="/root/.tunneler/run_client.sh"
APP_DIR="/root/.tunneler"

if command -v rw >/dev/null 2>&1; then
  rw
fi

set +e
systemctl disable --now "${SERVICE_NAME}"
set -e

rm -f "$UNIT"
systemctl daemon-reload

rm -rf "$APP_DIR"

if command -v ro >/dev/null 2>&1; then
  ro
fi

echo "=== 완료 ==="

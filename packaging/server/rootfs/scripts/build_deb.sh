#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKGROOT="$ROOT/packaging/server/rootfs"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "usage: $0 <version>"
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

OUTDIR="$ROOT/dist"
mkdir -p "$OUTDIR"

cp -a "$PKGROOT" "$WORKDIR/pkg"

# control 버전 치환
sed -i "s/^Version: .*/Version: ${VERSION}/" "$WORKDIR/pkg/DEBIAN/control"

# conffiles에 있는 파일이 실제로 패키지에 존재해야 함
# => /etc/default/tunneler-server가 rootfs 안에 있어야 함
if [[ -f "$WORKDIR/pkg/DEBIAN/conffiles" ]]; then
  while read -r f; do
    [[ -z "$f" ]] && continue
    if [[ ! -e "$WORKDIR/pkg$f" ]]; then
      echo "[ERROR] conffile '$f' not found in package rootfs"
      echo "        => place it at: packaging/server/rootfs$f"
      exit 1
    fi
  done < "$WORKDIR/pkg/DEBIAN/conffiles"
fi

# 권한 정리(권장)
chmod 0755 "$WORKDIR/pkg/DEBIAN/postinst" "$WORKDIR/pkg/DEBIAN/preinst" 2>/dev/null || true
chmod 0755 "$WORKDIR/pkg/DEBIAN/prerm" 2>/dev/null || true
chmod 0644 "$WORKDIR/pkg/DEBIAN/control" "$WORKDIR/pkg/DEBIAN/templates" 2>/dev/null || true

DEBNAME="tunneler-server_${VERSION}_all.deb"
dpkg-deb --build "$WORKDIR/pkg" "$OUTDIR/$DEBNAME"

echo "[OK] built: $OUTDIR/$DEBNAME"


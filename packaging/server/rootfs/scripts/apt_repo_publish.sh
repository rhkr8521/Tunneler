#!/usr/bin/env bash
set -euo pipefail

# 사용법: ./apt_repo_publish.sh <dist_dir> <repo_dir>
DIST_DIR="${1:-}"
REPO_DIR="${2:-}"

if [[ -z "$DIST_DIR" || -z "$REPO_DIR" ]]; then
  echo "usage: $0 <dist_dir> <repo_dir>"
  exit 1
fi

CODENAME="stable"
COMPONENT="main"
ARCHES=("amd64" "arm64" "all")

# 1. 모든 패키지를 pool로 복사
mkdir -p "$REPO_DIR/pool/$COMPONENT"

for deb in "$DIST_DIR"/*.deb; do
  [ -e "$deb" ] || continue
  PKG="$(dpkg-deb -f "$deb" Package)"
  PKG_DIR="$REPO_DIR/pool/$COMPONENT/${PKG:0:1}/$PKG"
  mkdir -p "$PKG_DIR"
  cp -f "$deb" "$PKG_DIR/"
  echo "[INFO] Added to pool: $(basename "$deb")"
done

# 2. 아키텍처별 인덱스(Packages) 생성
for A in "${ARCHES[@]}"; do
  BD="$REPO_DIR/dists/$CODENAME/$COMPONENT/binary-$A"
  mkdir -p "$BD"
  echo "[INFO] Indexing architecture: $A"
  (
    cd "$REPO_DIR"
    dpkg-scanpackages -a "$A" "pool/$COMPONENT" /dev/null > "dists/$CODENAME/$COMPONENT/binary-$A/Packages"
  )
  gzip -kf "$BD/Packages"
done

# 3. Release 파일 생성 및 서명
pushd "$REPO_DIR" >/dev/null
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="Tunneler" \
  -o APT::FTPArchive::Release::Architectures="amd64 arm64 all" \
  -o APT::FTPArchive::Release::Codename="$CODENAME" \
  release "dists/$CODENAME" > "dists/$CODENAME/Release"

# GPG 서명 (InRelease 포함)
gpg --batch --yes --armor -abs -o "dists/$CODENAME/Release.gpg" "dists/$CODENAME/Release"
gpg --batch --yes --clearsign -o "dists/$CODENAME/InRelease" "dists/$CODENAME/Release"
popd >/dev/null

echo "[OK] APT repository updated with all packages."

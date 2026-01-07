#!/usr/bin/env bash
set -euo pipefail

# 사용:
#   ./scripts/apt_repo_publish.sh <deb_path> <repo_dir>
# 예:
#   ./scripts/apt_repo_publish.sh dist/tunneler-server_1.2.1_amd64.deb repo

DEB_PATH="${1:-}"
REPO_DIR="${2:-}"

if [[ -z "$DEB_PATH" || -z "$REPO_DIR" ]]; then
  echo "usage: $0 <deb_path> <repo_dir>"
  exit 1
fi

if [[ ! -f "$DEB_PATH" ]]; then
  echo "[ERROR] deb not found: $DEB_PATH"
  exit 1
fi

# APT repo 기본값
CODENAME="stable"
COMPONENT="main"
ARCHES="amd64 arm64 all"

# repo 루트 생성
mkdir -p "$REPO_DIR"

# pool 디렉터리
mkdir -p "$REPO_DIR/pool/$COMPONENT"

# deb를 pool로 복사 (패키지명 기반 하위 폴더로 정리)
PKG="$(dpkg-deb -f "$DEB_PATH" Package)"
PKGDIR="$REPO_DIR/pool/$COMPONENT/${PKG:0:1}/$PKG"
mkdir -p "$PKGDIR"
cp -f "$DEB_PATH" "$PKGDIR/"

# Packages 생성
# ✅ 중요: (cd "$REPO_DIR") 안에서 경로는 repo/로 시작하면 repo/repo가 된다.
# 그래서 BD는 repo 내부 상대경로로 만든다.
for A in $ARCHES; do
  BD="dists/$CODENAME/$COMPONENT/binary-$A"
  mkdir -p "$REPO_DIR/$BD"

  (
    cd "$REPO_DIR"
    dpkg-scanpackages -a "$A" "pool/$COMPONENT" /dev/null > "$BD/Packages" || true
    gzip -kf "$BD/Packages"
  )
done

# Release 생성(apt-ftparchive 사용)
cat > "$REPO_DIR/apt-ftparchive.conf" <<EOF
Dir {
  ArchiveDir ".";
};
Default {
  Packages::Compress ". gzip";
};
TreeDefault {
  BinCacheDB "packages-\$(ARCH).db";
};
BinDirectory "dists/$CODENAME/$COMPONENT/binary-amd64" {
  Packages "dists/$CODENAME/$COMPONENT/binary-amd64/Packages";
  Contents "dists/$CODENAME/$COMPONENT/Contents-amd64";
  Arch "amd64";
};
BinDirectory "dists/$CODENAME/$COMPONENT/binary-arm64" {
  Packages "dists/$CODENAME/$COMPONENT/binary-arm64/Packages";
  Contents "dists/$CODENAME/$COMPONENT/Contents-arm64";
  Arch "arm64";
};
BinDirectory "dists/$CODENAME/$COMPONENT/binary-all" {
  Packages "dists/$CODENAME/$COMPONENT/binary-all/Packages";
  Contents "dists/$CODENAME/$COMPONENT/Contents-all";
  Arch "all";
};
EOF

pushd "$REPO_DIR" >/dev/null
apt-ftparchive generate apt-ftparchive.conf

apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="Tunneler" \
  -o APT::FTPArchive::Release::Label="Tunneler" \
  -o APT::FTPArchive::Release::Suite="$CODENAME" \
  -o APT::FTPArchive::Release::Codename="$CODENAME" \
  -o APT::FTPArchive::Release::Architectures="amd64 arm64 all" \
  -o APT::FTPArchive::Release::Components="$COMPONENT" \
  -o APT::FTPArchive::Release::Description="Tunneler APT Repository" \
  release "dists/$CODENAME" > "dists/$CODENAME/Release"

# 서명(키는 액션에서 import 되어 있어야 함)
gpg --batch --yes --armor -abs -o "dists/$CODENAME/Release.gpg" "dists/$CODENAME/Release"
gpg --batch --yes --clearsign -o "dists/$CODENAME/InRelease" "dists/$CODENAME/Release"

popd >/dev/null

echo "[OK] apt repo updated in: $REPO_DIR"


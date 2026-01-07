#!/usr/bin/env bash
set -euo pipefail

# 사용:
#   ./apt_repo_publish.sh <deb_path> <repo_dir>
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

CODENAME="stable"
COMPONENT="main"

# ✅ A 방식: all만 인덱싱
ARCHES=("all")

mkdir -p "$REPO_DIR/pool/$COMPONENT"

# deb를 pool로 복사
PKG="$(dpkg-deb -f "$DEB_PATH" Package)"
PKGDIR="$REPO_DIR/pool/$COMPONENT/${PKG:0:1}/$PKG"
mkdir -p "$PKGDIR"
cp -f "$DEB_PATH" "$PKGDIR/"

echo "[INFO] copied: $DEB_PATH -> $PKGDIR/"
echo "[INFO] deb fields: $(dpkg-deb -f "$DEB_PATH" Package Version Architecture | tr '\n' ' ')"

# Packages 생성
for A in "${ARCHES[@]}"; do
  BD="$REPO_DIR/dists/$CODENAME/$COMPONENT/binary-$A"
  mkdir -p "$BD"

  echo "[INFO] generating Packages for arch=$A ..."
  (
    cd "$REPO_DIR"
    dpkg-scanpackages -a "$A" "pool/$COMPONENT" /dev/null > "dists/$CODENAME/$COMPONENT/binary-$A/Packages"
  )

  if [[ ! -s "$BD/Packages" ]]; then
    echo "[ERROR] Packages is empty: $BD/Packages (arch=$A)"
    exit 1
  fi

  gzip -kf "$BD/Packages"
done

# Release 생성(apt-ftparchive)
cat > "$REPO_DIR/apt-ftparchive.conf" <<EOF
Dir { ArchiveDir "."; };
Default { Packages::Compress ". gzip"; };
TreeDefault { BinCacheDB "packages-\$(ARCH).db"; };

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
  -o APT::FTPArchive::Release::Architectures="all" \
  -o APT::FTPArchive::Release::Components="$COMPONENT" \
  -o APT::FTPArchive::Release::Description="Tunneler APT Repository" \
  release "dists/$CODENAME" > "dists/$CODENAME/Release"

# 서명
gpg --batch --yes --armor -abs -o "dists/$CODENAME/Release.gpg" "dists/$CODENAME/Release"
gpg --batch --yes --clearsign -o "dists/$CODENAME/InRelease" "dists/$CODENAME/Release"
popd >/dev/null

echo "[OK] apt repo updated in: $REPO_DIR"


#!/usr/bin/env bash
set -euo pipefail

DEB_PATH="${1:-}"
REPO_DIR="${2:-}"

if [[ -z "$DEB_PATH" || -z "$REPO_DIR" ]]; then
  echo "usage: $0 <deb_path> <repo_dir>"
  exit 1
fi

CODENAME="stable"
COMPONENT="main"

# ✅ 수정 포인트 1: 지원할 실제 아키텍처들을 나열합니다.
ARCHES=("amd64" "arm64" "all")

mkdir -p "$REPO_DIR/pool/$COMPONENT"

# deb를 pool로 복사
PKG="$(dpkg-deb -f "$DEB_PATH" Package)"
PKGDIR="$REPO_DIR/pool/$COMPONENT/${PKG:0:1}/$PKG"
mkdir -p "$PKGDIR"
cp -f "$DEB_PATH" "$PKGDIR/"

# Packages 생성
for A in "${ARCHES[@]}"; do
  BD="$REPO_DIR/dists/$CODENAME/$COMPONENT/binary-$A"
  mkdir -p "$BD"

  echo "[INFO] generating Packages for arch=$A ..."
  (
    cd "$REPO_DIR"
    # dpkg-scanpackages가 pool 폴더를 훑으며 해당 아키텍처(A)에 맞는(또는 all인) 패키지를 인덱싱합니다.
    dpkg-scanpackages -a "$A" "pool/$COMPONENT" /dev/null > "dists/$CODENAME/$COMPONENT/binary-$A/Packages"
  )
  gzip -kf "$BD/Packages"
done

# ✅ 수정 포인트 2: apt-ftparchive 설정에 아키텍처들 추가
cat > "$REPO_DIR/apt-ftparchive.conf" <<EOF
Dir { ArchiveDir "."; };
Default { Packages::Compress ". gzip"; };
TreeDefault { BinCacheDB "packages-\$(ARCH).db"; };

$(for A in "${ARCHES[@]}"; do
cat <<EOT
BinDirectory "dists/$CODENAME/$COMPONENT/binary-$A" {
  Packages "dists/$CODENAME/$COMPONENT/binary-$A/Packages";
  Contents "dists/$CODENAME/$COMPONENT/Contents-$A";
  Arch "$A";
};
EOT
done)
EOF

pushd "$REPO_DIR" >/dev/null
apt-ftparchive generate apt-ftparchive.conf

# ✅ 수정 포인트 3: Release 파일의 Architectures 필드 업데이트
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="Tunneler" \
  -o APT::FTPArchive::Release::Label="Tunneler" \
  -o APT::FTPArchive::Release::Suite="$CODENAME" \
  -o APT::FTPArchive::Release::Codename="$CODENAME" \
  -o APT::FTPArchive::Release::Architectures="$(echo "${ARCHES[@]}")" \
  -o APT::FTPArchive::Release::Components="$COMPONENT" \
  -o APT::FTPArchive::Release::Description="Tunneler APT Repository" \
  release "dists/$CODENAME" > "dists/$CODENAME/Release"

# 서명
gpg --batch --yes --armor -abs -o "dists/$CODENAME/Release.gpg" "dists/$CODENAME/Release"
gpg --batch --yes --clearsign -o "dists/$CODENAME/InRelease" "dists/$CODENAME/Release"
popd >/dev/null

echo "[OK] apt repo updated in: $REPO_DIR"

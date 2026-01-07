#!/usr/bin/env bash
set -euo pipefail

# 사용법:
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

# ✅ 핵심 수정: 클라이언트(사용자 PC)가 어떤 아키텍처든 패키지를 찾을 수 있도록 
# amd64, arm64, all 인덱스를 모두 생성합니다.
ARCHES=("amd64" "arm64" "all")

# 1. pool 폴더 구조 생성 및 deb 복사
mkdir -p "$REPO_DIR/pool/$COMPONENT"

PKG="$(dpkg-deb -f "$DEB_PATH" Package)"
# 패키지 이름의 첫 글자를 따서 폴더 구조 생성 (표준 APT 구조)
PKGDIR="$REPO_DIR/pool/$COMPONENT/${PKG:0:1}/$PKG"
mkdir -p "$PKGDIR"
cp -f "$DEB_PATH" "$PKGDIR/"

echo "[INFO] copied: $DEB_PATH -> $PKGDIR/"
echo "[INFO] deb fields: $(dpkg-deb -f "$DEB_PATH" Package Version Architecture | tr '\n' ' ')"

# 2. 각 아키텍처별 Packages 파일 생성
# dpkg-scanpackages가 pool 폴더를 스캔하여 실제 패키지 목록을 만듭니다.
for A in "${ARCHES[@]}"; do
  BD="$REPO_DIR/dists/$CODENAME/$COMPONENT/binary-$A"
  mkdir -p "$BD"

  echo "[INFO] generating Packages for arch=$A ..."
  (
    cd "$REPO_DIR"
    # -a $A 옵션을 통해 해당 아키텍처에 맞는(all 포함) 패키지를 인덱싱합니다.
    dpkg-scanpackages -a "$A" "pool/$COMPONENT" /dev/null > "dists/$CODENAME/$COMPONENT/binary-$A/Packages"
  )

  if [[ ! -s "$BD/Packages" ]]; then
    echo "[ERROR] Packages is empty: $BD/Packages (arch=$A). Check pool directory."
    exit 1
  fi

  gzip -kf "$BD/Packages"
done

# 3. Release 파일 생성 (서명 전 메타데이터 통합)
# ✅ 중요: 'apt-ftparchive generate'는 파일을 덮어씌워 버리므로 생략하고 
# 바로 'release' 명령어를 사용하여 보증서를 만듭니다.
pushd "$REPO_DIR" >/dev/null

echo "[INFO] generating Release file..."
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="Tunneler" \
  -o APT::FTPArchive::Release::Label="Tunneler" \
  -o APT::FTPArchive::Release::Suite="$CODENAME" \
  -o APT::FTPArchive::Release::Codename="$CODENAME" \
  -o APT::FTPArchive::Release::Architectures="amd64 arm64 all" \
  -o APT::FTPArchive::Release::Components="$COMPONENT" \
  -o APT::FTPArchive::Release::Description="Tunneler APT Repository" \
  release "dists/$CODENAME" > "dists/$CODENAME/Release"

# 4. GPG 서명 (Release.gpg 및 InRelease 생성)
echo "[INFO] signing release..."
gpg --batch --yes --armor -abs -o "dists/$CODENAME/Release.gpg" "dists/$CODENAME/Release"
gpg --batch --yes --clearsign -o "dists/$CODENAME/InRelease" "dists/$CODENAME/Release"

popd >/dev/null

echo "[OK] apt repo updated successfully in: $REPO_DIR"

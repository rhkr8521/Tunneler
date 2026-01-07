#!/usr/bin/env bash
set -euo pipefail

# 사용법: ./build_deb.sh <version>
VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  echo "usage: $0 <version>"
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ROOTFS="${REPO_ROOT}/packaging/client/rootfs"
OUTDIR="${REPO_ROOT}/dist"
PKGNAME="tunneler-client"

mkdir -p "${OUTDIR}"

# 1. 빌드용 임시 디렉터리 생성
WORKDIR="$(mktemp -d)"
PKGDIR="${WORKDIR}/${PKGNAME}-pkg"
mkdir -p "${PKGDIR}"

# 2. 파일 복사
cp -a "${ROOTFS}/." "${PKGDIR}/"

# 3. Control 파일 수정 (버전 업데이트 및 개행 문자 강제 추가)
CONTROL="${PKGDIR}/DEBIAN/control"
sed -i "s/^Version: .*/Version: ${VERSION}/" "${CONTROL}"
printf "\n" >> "${CONTROL}"

# 4. 권한 설정 (에러 방지 핵심)
chmod 0755 "${PKGDIR}/DEBIAN/postinst" "${PKGDIR}/DEBIAN/config" "${PKGDIR}/DEBIAN/prerm" || true
chmod 0755 "${PKGDIR}/usr/bin/tunneler-map" || true
chmod 0755 "${PKGDIR}/opt/tunneler-client/setup_full_client.sh" || true

# 5. 빌드
OUTFILE="${OUTDIR}/${PKGNAME}_${VERSION}_all.deb"
dpkg-deb --build "${PKGDIR}" "${OUTFILE}"

echo "[OK] Built: ${OUTFILE}"
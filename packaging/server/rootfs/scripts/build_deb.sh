#!/usr/bin/env bash
set -euo pipefail

# usage:
#   build_deb.sh <version>
#
# 정책(A):
# - control의 Architecture 값을 그대로 사용한다. (Architecture: all 이어야 함)
# - 워크플로우에서도 arch를 넘기지 않는다.

VERSION="${1:-${VERSION:-}}"
if [[ -z "${VERSION}" ]]; then
  echo "usage: $0 <version>"
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ROOTFS="${REPO_ROOT}/packaging/server/rootfs"

if [[ ! -d "${ROOTFS}/DEBIAN" ]]; then
  echo "[ERROR] ROOTFS not found: ${ROOTFS}/DEBIAN"
  echo "       current: $(pwd)"
  exit 1
fi

PKGNAME="tunneler-server"
OUTDIR="${REPO_ROOT}/dist"
mkdir -p "${OUTDIR}"

WORKDIR="$(mktemp -d)"
PKGDIR="${WORKDIR}/${PKGNAME}-pkg"
mkdir -p "${PKGDIR}"

cp -a "${ROOTFS}/." "${PKGDIR}/"

CONTROL="${PKGDIR}/DEBIAN/control"
if [[ ! -f "${CONTROL}" ]]; then
  echo "[ERROR] control not found: ${CONTROL}"
  exit 1
fi

ARCH="$(awk -F': *' '/^Architecture:/ {print $2; exit}' "${CONTROL}")"
if [[ -z "${ARCH}" ]]; then
  echo "[ERROR] Architecture field missing in control"
  exit 1
fi

# ✅ A 방식 강제: 반드시 all이어야 함
if [[ "${ARCH}" != "all" ]]; then
  echo "[ERROR] control Architecture must be 'all' for A mode. current='${ARCH}'"
  exit 1
fi

# Version 반영
if grep -q '^Version:' "${CONTROL}"; then
  sed -i "s/^Version: .*/Version: ${VERSION}/" "${CONTROL}"
else
  echo "Version: ${VERSION}" >> "${CONTROL}"
fi

echo "[INFO] repo_root=${REPO_ROOT}"
echo "[INFO] rootfs=${ROOTFS}"
echo "[INFO] version=${VERSION}"
echo "[INFO] arch=${ARCH}"
echo "[INFO] workdir=${WORKDIR}"

chmod 0755 "${PKGDIR}/DEBIAN" || true
for f in postinst prerm preinst postrm config; do
  [[ -f "${PKGDIR}/DEBIAN/${f}" ]] && chmod 0755 "${PKGDIR}/DEBIAN/${f}" || true
done

# conffiles 검증
if [[ -f "${PKGDIR}/DEBIAN/conffiles" ]]; then
  while IFS= read -r cf; do
    [[ -z "${cf}" ]] && continue
    if [[ ! -e "${PKGDIR}${cf}" ]]; then
      echo "[ERROR] conffiles entry missing from package: ${cf}"
      echo "       (Fix: include it under rootfs${cf} or remove from DEBIAN/conffiles)"
      exit 1
    fi
  done < "${PKGDIR}/DEBIAN/conffiles"
fi

OUTFILE="${OUTDIR}/${PKGNAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --build "${PKGDIR}" "${OUTFILE}"

echo "[OK] built: ${OUTFILE}"


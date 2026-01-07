#!/usr/bin/env bash
set -euo pipefail

# usage: build_deb.sh <version> [arch]
VERSION="${1:-${VERSION:-}}"
ARCH_ARG="${2:-${ARCH:-}}"

if [[ -z "${VERSION}" ]]; then
  echo "usage: $0 <version> [arch]"
  exit 1
fi

# repo root 자동 탐지 (actions에서도 안정적)
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ROOTFS="${REPO_ROOT}/packaging/server/rootfs"

if [[ ! -d "${ROOTFS}/DEBIAN" ]]; then
  echo "[ERROR] ROOTFS not found: ${ROOTFS}/DEBIAN"
  echo "       current: $(pwd)"
  exit 1
fi

# arch 결정: 인자 > env > 시스템
if [[ -n "${ARCH_ARG}" ]]; then
  ARCH="${ARCH_ARG}"
else
  ARCH="$(dpkg --print-architecture)"
fi

PKGNAME="tunneler-server"
OUTDIR="${REPO_ROOT}/dist"
mkdir -p "${OUTDIR}"

WORKDIR="$(mktemp -d)"
PKGDIR="${WORKDIR}/${PKGNAME}-pkg"

echo "[INFO] repo_root=${REPO_ROOT}"
echo "[INFO] rootfs=${ROOTFS}"
echo "[INFO] version=${VERSION}"
echo "[INFO] arch=${ARCH}"
echo "[INFO] workdir=${WORKDIR}"

mkdir -p "${PKGDIR}"

# ✅ 여기서 핵심: rootfs를 "한 번만" 복사한다 (경로 중복 금지)
# rootfs 자체를 통째로 PKGDIR로 복사하는 게 아니라,
# rootfs 안의 내용(DEBIAN, opt, etc...)을 PKGDIR로 복사해야 dpkg-deb가 먹음.
cp -a "${ROOTFS}/." "${PKGDIR}/"

# control 수정 (Version / Architecture)
CONTROL="${PKGDIR}/DEBIAN/control"
if [[ ! -f "${CONTROL}" ]]; then
  echo "[ERROR] control not found: ${CONTROL}"
  exit 1
fi

# Version
if grep -q '^Version:' "${CONTROL}"; then
  sed -i "s/^Version: .*/Version: ${VERSION}/" "${CONTROL}"
else
  echo "Version: ${VERSION}" >> "${CONTROL}"
fi

# Architecture
if grep -q '^Architecture:' "${CONTROL}"; then
  sed -i "s/^Architecture: .*/Architecture: ${ARCH}/" "${CONTROL}"
else
  echo "Architecture: ${ARCH}" >> "${CONTROL}"
fi

# 권한 정리 (DEBIAN 스크립트)
chmod 0755 "${PKGDIR}/DEBIAN" || true
for f in postinst prerm preinst postrm config; do
  [[ -f "${PKGDIR}/DEBIAN/${f}" ]] && chmod 0755 "${PKGDIR}/DEBIAN/${f}" || true
done

# conffiles가 있으면 실제 파일이 패키지에 포함되는지 체크 (너가 예전에 걸렸던 그거 방지)
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


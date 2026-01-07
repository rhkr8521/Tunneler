#!/usr/bin/env bash
set -euo pipefail

# usage:
#   build_deb.sh <version> [arch]
#   build_deb.sh <version> --multi "amd64 arm64"
#
# 기본 정책:
# - control의 Architecture 값을 존중한다. (all이면 all로)
# - arch 인자를 주면 control의 Architecture를 해당 값으로 override 해서 빌드한다.

VERSION="${1:-${VERSION:-}}"
shift || true

if [[ -z "${VERSION}" ]]; then
  echo "usage: $0 <version> [arch] | $0 <version> --multi \"amd64 arm64\""
  exit 1
fi

MODE="single"
MULTI_ARCHES=""

if [[ "${1:-}" == "--multi" ]]; then
  MODE="multi"
  MULTI_ARCHES="${2:-}"
  if [[ -z "${MULTI_ARCHES}" ]]; then
    echo "usage: $0 <version> --multi \"amd64 arm64\""
    exit 1
  fi
  shift 2 || true
fi

ARCH_ARG="${1:-${ARCH:-}}"

# repo root 자동 탐지
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

build_one() {
  local version="$1"
  local arch_override="${2:-}"

  local workdir pkgdir control control_arch arch out
  workdir="$(mktemp -d)"
  pkgdir="${workdir}/${PKGNAME}-pkg"

  mkdir -p "${pkgdir}"
  cp -a "${ROOTFS}/." "${pkgdir}/"

  control="${pkgdir}/DEBIAN/control"
  if [[ ! -f "${control}" ]]; then
    echo "[ERROR] control not found: ${control}"
    exit 1
  fi

  # control에 있는 Architecture 읽기
  control_arch="$(awk -F': *' '/^Architecture:/ {print $2; exit}' "${control}")"
  if [[ -z "${control_arch}" ]]; then
    echo "[ERROR] Architecture field missing in control"
    exit 1
  fi

  # version 반영
  if grep -q '^Version:' "${control}"; then
    sed -i "s/^Version: .*/Version: ${version}/" "${control}"
  else
    echo "Version: ${version}" >> "${control}"
  fi

  # arch 결정: override 있으면 override, 없으면 control 값 그대로
  if [[ -n "${arch_override}" ]]; then
    arch="${arch_override}"
    if grep -q '^Architecture:' "${control}"; then
      sed -i "s/^Architecture: .*/Architecture: ${arch}/" "${control}"
    else
      echo "Architecture: ${arch}" >> "${control}"
    fi
  else
    arch="${control_arch}"
  fi

  echo "[INFO] repo_root=${REPO_ROOT}"
  echo "[INFO] rootfs=${ROOTFS}"
  echo "[INFO] version=${version}"
  echo "[INFO] arch=${arch}"
  echo "[INFO] workdir=${workdir}"

  # DEBIAN 스크립트 권한
  chmod 0755 "${pkgdir}/DEBIAN" || true
  for f in postinst prerm preinst postrm config; do
    [[ -f "${pkgdir}/DEBIAN/${f}" ]] && chmod 0755 "${pkgdir}/DEBIAN/${f}" || true
  done

  # conffiles 검증
  if [[ -f "${pkgdir}/DEBIAN/conffiles" ]]; then
    while IFS= read -r cf; do
      [[ -z "${cf}" ]] && continue
      if [[ ! -e "${pkgdir}${cf}" ]]; then
        echo "[ERROR] conffiles entry missing from package: ${cf}"
        echo "       (Fix: include it under rootfs${cf} or remove from DEBIAN/conffiles)"
        exit 1
      fi
    done < "${pkgdir}/DEBIAN/conffiles"
  fi

  out="${OUTDIR}/${PKGNAME}_${version}_${arch}.deb"
  dpkg-deb --build "${pkgdir}" "${out}"
  echo "[OK] built: ${out}"
}

if [[ "${MODE}" == "multi" ]]; then
  for a in ${MULTI_ARCHES}; do
    build_one "${VERSION}" "${a}"
  done
else
  # single: arch 인자 있으면 override, 없으면 control 값 그대로
  build_one "${VERSION}" "${ARCH_ARG:-}"
fi


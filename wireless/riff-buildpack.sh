#!/bin/sh
# riff-buildpack.sh: build the Riff wireless pack for the running WSL kernel
# on this PC - the fallback when no pack can be downloaded (riff-getpack.sh).
# Same recipe as the repository's CI (build/build-pack.sh): Microsoft's
# kernel source for exactly this kernel, OpenWrt backports, linux-firmware.
# Needs an Internet connection, about an hour and ~15 GB of disk while it
# runs; the build tree is removed afterwards. Started by Riff (Tools >
# Wireless Dongle); progress lines go to stdout.
set -u
R=$(uname -r)
KV=${R%%-microsoft-standard-WSL2}
if [ "$KV" = "$R" ]; then
  echo "RIFF_BUILD_ERROR not a Microsoft WSL kernel: $R"; exit 1
fi
if [ -f "/opt/riff/packs/riff-wifi-$R.tar.zst" ]; then
  echo "RIFF_BUILD_DONE kernel=$R (already there)"; exit 0
fi
# a pack may have been published since
sh /opt/riff/riff-getpack.sh "$R" && { echo "RIFF_BUILD_DONE kernel=$R (downloaded)"; exit 0; }

echo "RIFF_BUILD_STEP installing the build tools"
apk add -q --no-cache bash build-base bc bison flex perl python3 git curl zstd \
    tar xz cpio rsync findutils diffutils coreutils gawk sed grep kmod \
    elfutils-dev openssl-dev linux-headers pahole gettext-dev >/dev/null 2>&1 \
  || { echo "RIFF_BUILD_ERROR could not install the build tools (Internet connection?)"; exit 1; }

W=/var/tmp/riff-build
rm -rf "$W"; mkdir -p "$W"
cleanup() {
  rm -rf "$W"
  # the tools are only needed for this build
  apk del -q bash build-base bc bison flex perl python3 git curl xz cpio rsync \
      findutils diffutils coreutils gawk elfutils-dev openssl-dev linux-headers \
      pahole gettext-dev >/dev/null 2>&1 || true
}
# (explicit cleanup below: busybox sh loses the exit status in an EXIT trap)

build() {   # build [FAST=1]
  env "$@" WORK=$W OUT=/opt/riff/packs bash /opt/riff/build/build-pack.sh "$KV" 2>&1 \
    | while IFS= read -r l; do
        case "$l" in "== "*) echo "RIFF_BUILD_STEP ${l#== }";; *) echo "  $l";; esac
      done
}
# quick way first: symbol versions read from the running kernel (~10 min)
echo "RIFF_BUILD_STEP building the drivers for kernel $KV (about 10 minutes)"
build FAST=1
if [ ! -f "/opt/riff/packs/riff-wifi-$R.tar.zst" ]; then
  # else the full kernel build (about an hour)
  echo "RIFF_BUILD_STEP the quick way failed: full build (about an hour)"
  rm -rf "$W/kernel-$KV"
  build FAST=0
fi
cleanup
if [ -f "/opt/riff/packs/riff-wifi-$R.tar.zst" ]; then
  echo "RIFF_BUILD_DONE kernel=$R"
  exit 0
fi
echo "RIFF_BUILD_ERROR the build did not produce a pack (see the lines above)"
exit 1

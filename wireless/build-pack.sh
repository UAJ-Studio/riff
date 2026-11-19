#!/bin/bash
# Build a Riff wireless pack for one Microsoft WSL kernel release:
#   1. Microsoft's kernel tree at that tag, built once for Module.symvers
#      (symbol CRCs: modules must match the stock kernel exactly),
#   2. OpenWrt backports (cfg80211/mac80211 + drivers, newer than the stock
#      kernel's) + rtw89 from a newer backports for 8852AU/8852CU/8922AU USB,
#   3. firmware the modules declare (linux-firmware) + regulatory.db,
#   4. packs/riff-wifi-<release>.tar.zst  (modules/ firmware/ RELEASE DRIVERS loader)
# usage: build-pack.sh <WSL kernel version, e.g. 6.6.87.2>
# Runs in a Linux build box (WSL Ubuntu) as root. Needs: git curl zstd perl
# build-essential flex bison bc libelf-dev libssl-dev kmod.
set -euo pipefail
KV=${1:?kernel version, e.g. 6.6.87.2}
BPN=${BPN:-7.2}            # newer backports: rtw89 (USB) comes from here
# base backports (the wireless stack): backports build on kernels OLDER than
# themselves - 6.18.55 for the 6.6 kernel; from kernel 6.18 on (WSL 3.0) the
# newer one, whose compat code knows these kernels
kver() { echo "$1" | awk -F. '{printf "%d%03d\n", $1, $2}'; }
if [ -z "${BPV:-}" ]; then
  if [ "$(kver "$KV")" -ge "$(kver 6.18)" ]; then BPV=$BPN; else BPV=6.18.55; fi
fi
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-/opt/build/riff}
FWSRC=${FWSRC:-$WORK/linux-firmware}
OUT=${OUT:-$HERE/packs}
REL=$KV-microsoft-standard-WSL2
K=$WORK/kernel-$KV
JOBS=${JOBS:-$(nproc)}
mkdir -p "$WORK" "$OUT"

echo "== [1/4] kernel tree $REL"
# FAST=1 (building on the PC that runs this very kernel): no kernel build -
# only the build preparation, and Module.symvers (the CRC of every exported
# symbol) read from the running kernel and its modules (riff-symvers.py).
# About 10 minutes instead of most of an hour.
if [ "${FAST:-0}" = 1 ] && [ "$(uname -r)" = "$REL" ] && [ ! -f "$K/Module.symvers" ]; then
  [ -f "$K/Makefile" ] || git clone -q --depth 1 --branch "linux-msft-wsl-$KV" \
      https://github.com/microsoft/WSL2-Linux-Kernel.git "$K"
  cd "$K"
  # the running kernel's own configuration, else Microsoft's
  zcat /proc/config.gz > .config 2>/dev/null || cp Microsoft/config-wsl .config
  make olddefconfig >/dev/null
  make -j"$JOBS" modules_prepare >build.log 2>&1 || { tail -30 build.log; exit 1; }
  python3 "$HERE/riff-symvers.py" Module.symvers || { echo "reading the running kernel's symbol versions failed"; exit 1; }
fi
if [ ! -f "$K/Module.symvers" ]; then
  [ -d "$K/.git" ] || git clone -q --depth 1 --branch "linux-msft-wsl-$KV" \
      https://github.com/microsoft/WSL2-Linux-Kernel.git "$K"
  cd "$K"
  cp Microsoft/config-wsl .config
  make olddefconfig >/dev/null
  # vmlinux is only built for Module.symvers; it is never booted
  make -j"$JOBS" vmlinux modules >build.log 2>&1 || { tail -30 build.log; exit 1; }
  # keep only what building external modules needs (Module.symvers, config,
  # headers, scripts, objtool): a small tree CI can cache per kernel
  rm -rf .git
  find . \( -path ./scripts -o -path ./tools \) -prune -o -type f \
       \( -name '*.o' -o -name '*.ko' -o -name '*.a' -o -name '.*.cmd' \
          -o -name '*.mod.c' -o -name '*.mod' -o -name 'vmlinux.o' \) -print0 \
    | xargs -0 rm -f
fi
cd "$K"
# exactly the stock release string (git's "+" would break vermagic)
echo "$REL" > include/config/kernel.release
echo "#define UTS_RELEASE \"$REL\"" > include/generated/utsrelease.h

echo "== [2/4] backports $BPV (+ rtw89 from $BPN)"
cd "$WORK"; mkdir -p bp; cd bp
for v in $BPV $BPN; do
  [ -f backports-$v.tar.zst ] || curl -sSLf -o backports-$v.tar.zst \
      https://github.com/openwrt/backports/releases/download/backports-v$v/backports-$v.tar.zst
done
rm -rf src-$BPN && mkdir src-$BPN && tar --zstd -xf backports-$BPN.tar.zst -C src-$BPN
B7=$WORK/bp/src-$BPN/backports-$BPN
B=$WORK/bp/build-$KV
rm -rf "$B" && mkdir -p "$B" && tar --zstd -xf backports-$BPV.tar.zst -C "$B" --strip-components=1
cd "$B"
cp "$HERE/compat/riff-compat.h" backport-include/riff-compat.h
sed -i '0,/^#include/s//#include <riff-compat.h>\n&/' backport-include/backport/backport.h
mkdir -p backport-include/linux/soc/airoha
cp "$HERE/compat/airoha_offload.h" backport-include/linux/soc/airoha/
# before 6.15: NETIF_F_NETNS_LOCAL feature bit instead of netdev->netns_immutable
if ! grep -q netns_immutable "$K/include/linux/netdevice.h"; then
  sed -i -E 's/([a-z_>.-]+)->netns_immutable = true;/\1->features |= NETIF_F_NETNS_LOCAL;/; s/([a-z_>.-]+)->netns_immutable = false;/\1->features \&= ~NETIF_F_NETNS_LOCAL;/' net/wireless/core.c
fi
# Microsoft's stable kernels pick up newer APIs early; backports keys its
# copies on the mainline version and would define them twice. Drop a copy
# the kernel headers already have.
if grep -q '^struct sockaddr_unsized {' "$K/include/linux/socket.h" 2>/dev/null; then
  perl -0pi -e 's/#if LINUX_VERSION_IS_LESS\(6,19,0\)(\n\/\*\*\n \* struct sockaddr_unsized)/#if 0 \/* Riff: in this kernel already *\/$1/' \
      backport-include/linux/socket.h
fi
# objtool (6.18, IBT) seals the ENDBR of functions whose address is never
# taken, and refuses to do it for init_module/cleanup_module ("Magic
# init_module() function name is deprecated"). The kernel's module_init
# takes their address with ___ADDRESSABLE; backports uses __CFI_ADDRESSABLE,
# which is empty without CFI. Declare them the way the kernel does.
if [ "$(kver "$KV")" -ge "$(kver 6.18)" ]; then
  sed -i 's/__attribute__((cold,alias("__init_backport")))/__copy(__init_backport) __attribute__((alias("__init_backport")))/; s/__attribute__((cold,alias("__exit_compat")))/__copy(__exit_compat) __attribute__((alias("__exit_compat")))/; s/__CFI_ADDRESSABLE(init_module, __initdata)/___ADDRESSABLE(init_module, __initdata)/; s/__CFI_ADDRESSABLE(cleanup_module, __exitdata)/___ADDRESSABLE(cleanup_module, __exitdata)/' \
      backport-include/linux/module.h
  grep -q '___ADDRESSABLE(init_module' backport-include/linux/module.h \
    || { echo "module_init alias patch failed"; exit 1; }
fi
# The newer backports links its AES library copy (6.18 kernels lack the new
# CBC-MAC API) into compat.ko, which has its own module_init: two
# init_module. Its initcall only runs a FIPS self-test - drop the
# registration there.
if grep -q '^subsys_initcall(aes_mod_init);' compat/lib-crypto-aes.c 2>/dev/null; then
  sed -i 's/^subsys_initcall(aes_mod_init);/\/* Riff: linked into compat.ko, which has its own module_init *\//; s/^module_exit(aes_mod_exit);//; s/^static int __init aes_mod_init(void)/static int __init __maybe_unused aes_mod_init(void)/; s/^static void __exit aes_mod_exit(void)/static void __exit __maybe_unused aes_mod_exit(void)/' \
      compat/lib-crypto-aes.c
fi
# class->namespace returns the net namespace itself (const void *) before
# the ns_common rework the newer backports expects
if grep -q 'const void \*(\*namespace)(const struct device' "$K/include/linux/device/class.h" 2>/dev/null \
   && grep -q 'static const struct ns_common \*wiphy_namespace' net/wireless/sysfs.c; then
  sed -i 's/^static const struct ns_common \*wiphy_namespace(/static const void *wiphy_namespace(/; s/return to_ns_common(wiphy_net(wiphy));/return wiphy_net(wiphy);/' \
      net/wireless/sysfs.c
fi
bash "$HERE/compat/rtw89-apply.sh" "$B" "$B7"
# before 6.10: 2-argument __assign_str in trace headers
if ! grep -q 'define __assign_str(dst)' "$K/include/trace/stages/stage6_event_callback.h"; then
  for f in $(grep -rl "__assign_str" --include=*.h .); do perl -0pi "$HERE/compat/fix-trace.pl" "$f"; done
fi
cp "$HERE/riff.defconfig" defconfigs/riff
# musl (Alpine, building on the PC): gettext lives in a separate libintl
NLS=; [ -f /etc/alpine-release ] && NLS=LDLIBS=-lintl
make -s KLIB="$K" KLIB_BUILD="$K" $NLS defconfig-riff >defconfig.log 2>&1 || { tail -20 defconfig.log; exit 1; }
# objtool: warnings only (6.18 objtool rejects the init_module alias backports
# uses around module_init as "deprecated"; the alias itself works)
make KLIB="$K" KLIB_BUILD="$K" CONFIG_OBJTOOL_WERROR= -j"$JOBS" >build.log 2>&1 || { grep -E "error|Error|No such|missing" build.log | head -30; echo "--- last lines:"; tail -25 build.log; exit 1; }

echo "== [3/4] firmware"
if [ ! -f "$FWSRC/WHENCE" ]; then
  # kernel.org first, then its official GitLab mirror (kernel.org is not
  # always reachable, e.g. from GitHub Actions runners)
  for u in https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git \
           https://gitlab.com/kernel-firmware/linux-firmware.git; do
    rm -rf "$FWSRC"
    timeout 600 git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 \
        clone -q --depth 1 --filter=blob:none --sparse "$u" "$FWSRC" && break
    echo "   (could not clone $u)"
  done
  [ -f "$FWSRC/WHENCE" ] || { echo "linux-firmware: no source reachable"; exit 1; }
fi
# only what the modules ask for (+ regdb): keeps the clone small
need=$(for ko in $(find . -name "*.ko"); do modinfo -F firmware $ko; done | sed "s|/[^/]*$|/|; s|^[^/]*$|&|" | sort -u)
# cone mode takes directories only (top-level files are always there); newer
# git refuses the whole list when a plain file is in it
dirs=$(printf '%s\n' $need | sed -n 's|/$||p')
(cd "$FWSRC" && git sparse-checkout add $dirs >/dev/null 2>&1) \
  || { echo "linux-firmware: could not fetch $dirs"; exit 1; }
S=$WORK/stage-$KV; rm -rf "$S"; mkdir -p "$S/modules" "$S/firmware"
find . -name '*.ko' -exec cp {} "$S/modules/" \;
strip --strip-debug "$S"/modules/*.ko   # debug info only; symbol CRCs stay
declare -A link
while read -r l a t; do link[$l]="$(dirname "$l")/$t"; done < <(grep -E '^Link: ' "$FWSRC/WHENCE" | sed 's/^Link: //')
for ko in "$S"/modules/*.ko; do
  for f in $(modinfo -F firmware "$ko"); do
    case $f in regulatory.db*|*_bt.bin) continue;; esac  # regdb added below; BT not needed
    src=$FWSRC/$f; [ -e "$src" ] || src=$FWSRC/${link[$f]:-none}
    [ -e "$src" ] && { mkdir -p "$S/firmware/$(dirname "$f")"; cp -L "$src" "$S/firmware/$f"; } || echo "   (no firmware file: $f)"
  done
done
# regulatory database (+ signature, checked against the kernel's built-in keys)
REGDB=${REGDB:-$WORK/wireless-regdb}
[ -f "$REGDB/regulatory.db" ] || timeout 300 git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 \
    clone -q --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git "$REGDB" \
    || echo "   (wireless-regdb git not reachable: using the latest release tarball)"
if [ ! -f "$REGDB/regulatory.db" ]; then
  RU=https://mirrors.edge.kernel.org/pub/software/network/wireless-regdb
  RT=$(curl -sSLf "$RU/" | grep -o 'wireless-regdb-[0-9.]*\.tar\.xz' | sort -u | tail -1)
  [ -n "$RT" ] || { echo "wireless-regdb: no source reachable"; exit 1; }
  rm -rf "$REGDB"; mkdir -p "$REGDB"
  curl -sSLf "$RU/$RT" | tar -xJ -C "$REGDB" --strip-components=1
fi
cp "$REGDB/regulatory.db" "$REGDB/regulatory.db.p7s" "$S/firmware/"

echo "== [4/4] pack"
echo "$REL" > "$S/RELEASE"
grep -vE '^\s*(#|$)' "$HERE/drivers.list" > "$S/DRIVERS"
cp "$HERE/riff-wifi-load.sh" "$S/"
for m in $(cat "$S/DRIVERS"); do [ -f "$S/modules/$m.ko" ] || { echo "driver $m was not built"; exit 1; }; done
[ "$(modinfo -F vermagic "$S/modules/mac80211.ko" | cut -d' ' -f1)" = "$REL" ] || { echo "vermagic mismatch"; exit 1; }
# USB IDs the drivers bind to ("VVVV:PPPP driver"), so Riff can tell which
# attached USB devices are supported dongles
for m in $(cat "$S/DRIVERS"); do
  modinfo -F alias "$S/modules/$m.ko" | sed -n "s/^usb:v\([0-9A-F]\{4\}\)p\([0-9A-F]\{4\}\).*/\1:\2 $m/p"
done | sort -u > "$S/USBIDS"
echo "   $(wc -l < "$S/USBIDS") USB IDs"
tar --zstd -cf "$OUT/riff-wifi-$REL.tar.zst" -C "$S" .
echo "PACK_OK $OUT/riff-wifi-$REL.tar.zst ($(du -h "$OUT/riff-wifi-$REL.tar.zst" | cut -f1), $(ls "$S/modules" | wc -l) modules)"

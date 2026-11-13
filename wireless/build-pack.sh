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
BPV=${BPV:-6.18.55}        # base backports (wireless stack)
BPN=${BPN:-7.2}            # newer backports, only its rtw89 is used
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-/opt/build/riff}
FWSRC=${FWSRC:-$WORK/linux-firmware}
OUT=${OUT:-$HERE/packs}
REL=$KV-microsoft-standard-WSL2
K=$WORK/kernel-$KV
JOBS=${JOBS:-$(nproc)}
mkdir -p "$WORK" "$OUT"

echo "== [1/4] kernel tree $REL"
if [ ! -f "$K/Module.symvers" ]; then
  [ -d "$K/.git" ] || git clone -q --depth 1 --branch "linux-msft-wsl-$KV" \
      https://github.com/microsoft/WSL2-Linux-Kernel.git "$K"
  cd "$K"
  cp Microsoft/config-wsl .config
  make olddefconfig >/dev/null
  # vmlinux is only built for Module.symvers; it is never booted
  make -j"$JOBS" vmlinux modules >build.log 2>&1 || { tail -30 build.log; exit 1; }
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
bash "$HERE/compat/rtw89-apply.sh" "$B" "$B7"
# before 6.10: 2-argument __assign_str in trace headers
if ! grep -q 'define __assign_str(dst)' "$K/include/trace/stages/stage6_event_callback.h"; then
  for f in $(grep -rl "__assign_str" --include=*.h .); do perl -0pi "$HERE/compat/fix-trace.pl" "$f"; done
fi
cp "$HERE/riff.defconfig" defconfigs/riff
make -s KLIB="$K" KLIB_BUILD="$K" defconfig-riff >/dev/null 2>&1
make KLIB="$K" KLIB_BUILD="$K" -j"$JOBS" >build.log 2>&1 || { grep -E 'error' build.log | head -30; exit 1; }

echo "== [3/4] firmware"
if [ ! -f "$FWSRC/WHENCE" ]; then
  git clone -q --depth 1 --filter=blob:none --sparse https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git "$FWSRC"
fi
# only what the modules ask for (+ regdb): keeps the clone small
need=$(for ko in $(find . -name "*.ko"); do modinfo -F firmware $ko; done | sed "s|/[^/]*$|/|; s|^[^/]*$|&|" | sort -u)
(cd "$FWSRC" && git sparse-checkout add WHENCE $need >/dev/null 2>&1) || true
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
[ -f "$REGDB/regulatory.db" ] || git clone -q --depth 1 \
    https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git "$REGDB"
cp "$REGDB/regulatory.db" "$REGDB/regulatory.db.p7s" "$S/firmware/"

echo "== [4/4] pack"
echo "$REL" > "$S/RELEASE"
grep -vE '^\s*(#|$)' "$HERE/drivers.list" > "$S/DRIVERS"
cp "$HERE/riff-wifi-load.sh" "$S/"
for m in $(cat "$S/DRIVERS"); do [ -f "$S/modules/$m.ko" ] || { echo "driver $m was not built"; exit 1; }; done
[ "$(modinfo -F vermagic "$S/modules/mac80211.ko" | cut -d' ' -f1)" = "$REL" ] || { echo "vermagic mismatch"; exit 1; }
tar --zstd -cf "$OUT/riff-wifi-$REL.tar.zst" -C "$S" .
echo "PACK_OK $OUT/riff-wifi-$REL.tar.zst ($(du -h "$OUT/riff-wifi-$REL.tar.zst" | cut -f1), $(ls "$S/modules" | wc -l) modules)"

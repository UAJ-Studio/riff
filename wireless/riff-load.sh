#!/bin/sh
# riff-load.sh [country]: make the Wi-Fi drivers available in the WSL kernel.
#  - kernel with a built-in wireless stack (e.g. a custom kernel set in
#    .wslconfig): use it as it is;
#  - Microsoft's stock kernel: load the Riff wireless pack built for it.
# Used by riff-start.sh (Riff's transmit agent) and riff-capture (Wireshark
# live capture). Messages go to stdout; exit 3 = no pack for this kernel
# (WSL was updated: the drivers have to be rebuilt).
CC=${1:-JP}
# One loader at a time: captures and Riff's background preparation start
# together, and a second loader would delete the pack the first is loading
# from. The lock stays held through the exec below.
exec 9>/run/riff-load.lock
flock 9 2>/dev/null || true
R=$(uname -r)
PK=/opt/riff/packs/riff-wifi-$R.tar.zst
P=/run/riff-pack
if [ -d /sys/module/mac80211 ] && ! grep -q '^mac80211 ' /proc/modules; then
  echo "RIFF_WIFI_BUILTIN kernel=$R"
  [ "$CC" != "00" ] && iw reg set "$CC" 2>/dev/null
  exit 0
fi
if [ ! -f "$P/RELEASE" ] || [ "$(cat $P/RELEASE)" != "$R" ]; then
  if [ ! -f "$PK" ]; then echo "RIFF_NEED_REBUILD kernel=$R"; exit 3; fi
  rm -rf $P; mkdir -p $P
  tar --zstd -xf "$PK" -C $P || { echo "RIFF_ERROR pack extract"; exit 1; }
fi
exec sh $P/riff-wifi-load.sh $P "$CC"

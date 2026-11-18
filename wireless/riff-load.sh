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
# Microsoft's own cfg80211 (in-tree: no "O" taint) loaded before the pack -
# any program opening an nl80211 socket (e.g. iw) makes the kernel load it -
# leaves the pack's mac80211 with "disagrees about version of symbol":
# unload it (and an unused stock mac80211) while nothing uses it. Modules
# stay loaded across distro restarts until "wsl --shutdown".
if grep -q '^cfg80211 ' /proc/modules && ! grep -q O /sys/module/cfg80211/taint 2>/dev/null; then
  if grep -q '^mac80211 ' /proc/modules && ! grep -q O /sys/module/mac80211/taint 2>/dev/null; then
    rmmod mac80211 2>/dev/null
  fi
  if rmmod cfg80211 2>/dev/null; then echo "RIFF_WIFI_NOTE unloaded the stock cfg80211"
  else echo "RIFF_WIFI_WARN the stock cfg80211 is loaded and in use"; fi
fi
exec sh $P/riff-wifi-load.sh $P "$CC"

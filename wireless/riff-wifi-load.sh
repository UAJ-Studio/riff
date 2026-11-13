#!/bin/sh
# Riff wireless pack loader. Runs as root inside Riff's own WSL distro on
# Microsoft's STOCK WSL kernel (no .wslconfig change, no kernel swap):
# loads the pack's cfg80211/mac80211 + all USB Wi-Fi drivers from a private
# module tree, so any supported dongle binds as soon as usbipd attaches it.
# usage: riff-wifi-load.sh <pack dir> [country]
# exit: 0 ok, 3 pack built for another kernel (WSL was updated), 1 error
set -u
P=${1:?pack dir}; CC=${2:-JP}
R=$(uname -r)
PR=$(cat "$P/RELEASE")
if [ "$R" != "$PR" ]; then
  echo "RIFF_WIFI_KERNEL_MISMATCH running=$R pack=$PR"; exit 3
fi
if lsmod | grep -q '^mac80211 '; then
  if [ -e /sys/module/compat ]; then echo "RIFF_WIFI_ALREADY_LOADED"; iw reg set "$CC"; exit 0; fi
  echo "RIFF_WIFI_ERROR stock wireless stack already loaded"; exit 1
fi

T=/run/riff-wifi; D=$T/lib/modules/$R/riff
rm -rf $T; mkdir -p $D
cp "$P"/modules/*.ko $D/
depmod -b $T $R 2>/dev/null || { echo "RIFF_WIFI_ERROR depmod"; exit 1; }

# firmware: the VM kernel cannot see this distro's files, but /mnt/wsl is
# shared by every distro and the VM
rm -rf /mnt/wsl/riff-fw; mkdir -p /mnt/wsl/riff-fw
cp -r "$P"/firmware/. /mnt/wsl/riff-fw/
printf %s /mnt/wsl/riff-fw > /sys/module/firmware_class/parameters/path

# dependencies that come from Microsoft's own module set (led-class, libarc4...)
for dep in $(for k in $D/*.ko; do modinfo -F depends $k | tr , ' '; done | tr ' ' '\n' | sort -u); do
  [ -e "$D/$dep.ko" ] || modprobe "$dep" 2>/dev/null || true
done

ok=0; bad=""
for m in $(cat "$P/DRIVERS"); do
  if modprobe -d $T "$m" 2>/dev/null; then ok=$((ok+1)); else bad="$bad $m"; fi
done
# world regdomain "00" forbids initiating radiation on 5 GHz -> injected frames
# would be dropped; set the country the user configured in Riff
iw reg set "$CC" 2>/dev/null
echo "RIFF_WIFI_LOADED drivers=$ok failed=${bad:-none} country=$CC"
[ -z "$bad" ]

#!/bin/sh
# Started by Riff (Windows) inside the RiffWireless distro after usbipd has
# attached the dongle(s):  wsl -d RiffWireless -u root -- /opt/riff/riff-start.sh <country> <channel> [port]
# Loads the wireless pack for the running kernel, puts every Wi-Fi interface
# into monitor mode on <channel>, then runs riff-agent in the foreground (Riff
# connects to localhost:<port>; stopping the wsl.exe process stops the agent).
# Status lines start with RIFF_ so Riff can show them to the user.
set -u
CC=${1:-JP}; CH=${2:-1}; PORT=${3:-7879}
R=$(uname -r)
PK=/opt/riff/packs/riff-wifi-$R.tar.zst
P=/run/riff-pack
if [ ! -f "$P/RELEASE" ] || [ "$(cat $P/RELEASE)" != "$R" ]; then
  if [ ! -f "$PK" ]; then echo "RIFF_NEED_REBUILD kernel=$R"; exit 3; fi
  rm -rf $P; mkdir -p $P; tar --zstd -xf "$PK" -C $P || { echo "RIFF_ERROR pack extract"; exit 1; }
fi
sh $P/riff-wifi-load.sh $P "$CC" || exit $?

# wait for the attached dongle(s) to come up (firmware load takes a few s)
W=""
for i in $(seq 1 40); do
  W=$(iw dev 2>/dev/null | awk '/Interface/{print $2}')
  [ -n "$W" ] && break; sleep 0.5
done
[ -n "$W" ] || { echo "RIFF_NO_DONGLE"; exit 4; }
for w in $W; do
  ip link set "$w" down
  iw dev "$w" set type monitor || { echo "RIFF_ERROR monitor mode refused on $w"; exit 1; }
  ip link set "$w" up
  iw dev "$w" set channel "$CH" || echo "RIFF_WARN channel $CH refused on $w"
  echo "RIFF_DONGLE $w $(basename "$(readlink -f /sys/class/net/$w/device/driver)") $(cat /sys/class/net/$w/address)"
done
echo "RIFF_AGENT_START port=$PORT"
exec /usr/local/bin/riff-agent -p "$PORT"

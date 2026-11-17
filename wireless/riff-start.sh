#!/bin/sh
# Started by Riff (Windows) inside the RiffWireless distro after usbipd has
# attached the dongle(s):  wsl -d RiffWireless -u root -- /opt/riff/riff-start.sh <country> <channel> [port]
# Loads the wireless pack for the running kernel, puts every Wi-Fi interface
# into monitor mode on <channel> ("-": keep the current channel of an adapter
# Riff already prepared), then runs riff-agent in the foreground (Riff
# connects to localhost:<port>; stopping the wsl.exe process stops the agent).
# Status lines start with RIFF_ so Riff can show them to the user.
set -u
CC=${1:-JP}; CH=${2:-1}; PORT=${3:-7879}
sh /opt/riff/riff-load.sh "$CC" || exit $?

# wait for the attached dongle(s) to come up (firmware load takes a few s)
W=""
for i in $(seq 1 40); do
  W=$(iw dev 2>/dev/null | awk '/Interface/{print $2}')
  [ -n "$W" ] && break; sleep 0.5
done
[ -n "$W" ] || { echo "RIFF_NO_DONGLE"; exit 4; }

VHCI=/sys/devices/platform/vhci_hcd.0
# win_busid <iface>: the Windows bus id (e.g. 11-1) of the dongle behind an
# interface: usbipd attaches with devid = bus<<16 | port (vhci status table)
win_busid() {
  d=$(readlink -f "/sys/class/net/$1/device")
  while [ -n "$d" ] && [ "$d" != "/" ] && [ ! -f "$d/idVendor" ]; do d=$(dirname "$d"); done
  lb=$(basename "$d")
  dev=$(awk -v id="$lb" '$7 == id {print $5; exit}' $VHCI/status* 2>/dev/null)
  [ -n "$dev" ] && printf '%d-%d' $((0x$dev >> 16)) $((0x$dev & 0xffff))
}

for w in $W; do
  # adapters Riff prepared are already in monitor mode: no down/up (costs
  # seconds on USB) and, with channel "-", no retune
  if [ "$(iw dev "$w" info 2>/dev/null | awk '/type/ {print $2}')" != "monitor" ]; then
    ip link set "$w" down
    iw dev "$w" set type monitor || { echo "RIFF_ERROR monitor mode refused on $w"; exit 1; }
  fi
  ip link set "$w" up
  if [ "$CH" != "-" ]; then
    iw dev "$w" set channel "$CH" || echo "RIFF_WARN channel $CH refused on $w"
  fi
  drv=$(basename "$(readlink -f /sys/class/net/$w/device/driver)")
  wb=$(win_busid "$w")
  # shown as the port description in Riff
  if [ -n "$wb" ]; then
    printf 'USB Wi-Fi %s (USB %s, monitor)' "$drv" "$wb" > /sys/class/net/$w/ifalias 2>/dev/null
  else
    printf 'USB Wi-Fi %s (monitor)' "$drv" > /sys/class/net/$w/ifalias 2>/dev/null
  fi
  echo "RIFF_DONGLE $w $drv $(cat /sys/class/net/$w/address)"
done
# localhost forwarding from Windows is not reliable in NAT mode: also give
# Riff the VM's own address to connect to
echo "RIFF_ADDR $(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
echo "RIFF_AGENT_START port=$PORT"
exec /usr/local/bin/riff-agent -p "$PORT"

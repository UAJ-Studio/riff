#!/bin/sh
# riff-channel.sh <channel> [width e.g. HT20|HT40+|HT40-|80MHz]
#     retune all monitor interfaces
# riff-channel.sh -f <freq MHz> <width MHz> <center MHz> [interface]
#     retune one interface (or all) by frequency, width and center frequency
if [ "$1" = "-f" ]; then
  F=${2:?freq}; WD=${3:-20}; C=${4:-$2}; IF=${5:-}
  for w in ${IF:-$(iw dev | awk '/Interface/{print $2}')}; do
    if [ "$WD" = 20 ]; then
      iw dev "$w" set freq "$F" HT20 2>/dev/null || iw dev "$w" set freq "$F" 20 "$F" 2>/dev/null || iw dev "$w" set freq "$F"
    else
      iw dev "$w" set freq "$F" "$WD" "$C"
    fi && echo "RIFF_CHANNEL $w $F $WD" || echo "RIFF_WARN $F MHz / $WD MHz refused on $w"
  done
  exit 0
fi
CH=${1:?channel}; WD=${2:-}
for w in $(iw dev | awk '/Interface/{print $2}'); do
  iw dev "$w" set channel "$CH" $WD && echo "RIFF_CHANNEL $w $CH $WD" || echo "RIFF_WARN channel $CH $WD refused on $w"
done

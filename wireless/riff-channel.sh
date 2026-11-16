#!/bin/sh
# riff-channel.sh <channel> [width e.g. HT20|HT40+|HT40-|80MHz]: retune all monitor interfaces
CH=${1:?channel}; WD=${2:-}
for w in $(iw dev | awk '/Interface/{print $2}'); do
  iw dev "$w" set channel "$CH" $WD && echo "RIFF_CHANNEL $w $CH $WD" || echo "RIFF_WARN channel $CH $WD refused on $w"
done

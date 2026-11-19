#!/bin/sh
# riff-getpack.sh [kernel release]: fetch the Riff wireless pack for the
# running WSL kernel when the distro does not have it yet (WSL was updated).
# Packs are built automatically by the repository's GitHub Actions for every
# new Microsoft WSL kernel (.github/workflows/packs.yml) and published on
# the "wireless-packs" release, each with a .sha256 file.
# Prints RIFF_PACK_DOWNLOADED / RIFF_PACK_UNAVAILABLE; exit 0 = pack present.
R=${1:-$(uname -r)}
DIR=/opt/riff/packs
PK=$DIR/riff-wifi-$R.tar.zst
[ -f "$PK" ] && exit 0
BASE=${RIFF_PACK_URL:-https://github.com/UAJ-Studio/riff/releases/download/wireless-packs}
TMP=$(mktemp -d /tmp/riff-pack.XXXXXX) || exit 1
# explicit cleanup (busybox sh: an EXIT trap loses the exit status)
fail() { echo "RIFF_PACK_UNAVAILABLE kernel=$R ($1)"; rm -rf "$TMP"; exit 1; }
F=riff-wifi-$R.tar.zst
get() { wget -q -T 30 -t 2 -O "$2" "$1"; }
if ! get "$BASE/$F.sha256" "$TMP/sum" || ! get "$BASE/$F" "$TMP/$F"; then
  fail "no pack published for this kernel yet, or no Internet"
fi
want=$(cut -d' ' -f1 "$TMP/sum")
have=$(sha256sum "$TMP/$F" | cut -d' ' -f1)
if [ -z "$want" ] || [ "$want" != "$have" ]; then
  fail "checksum mismatch"
fi
# the pack must be for exactly this kernel
if [ "$(tar --zstd -xOf "$TMP/$F" ./RELEASE 2>/dev/null)" != "$R" ]; then
  fail "pack is for another kernel"
fi
mkdir -p "$DIR" && mv "$TMP/$F" "$PK.part" && mv "$PK.part" "$PK" || fail "cannot store the pack"
rm -rf "$TMP"
echo "RIFF_PACK_DOWNLOADED kernel=$R"

#!/bin/sh
# riff-getpack.sh [kernel release]: fetch the Riff wireless pack for the
# running WSL kernel when the distro does not have it yet (WSL was updated).
# Packs are built automatically by the repository's GitHub Actions for every
# new Microsoft WSL kernel (.github/workflows/packs.yml) and published on
# the "wireless-packs" pre-release of UAJ-Studio/riff, each with a .sha256.
#
# Only https, only that release; GitHub answers with a redirect to its
# download host, which must be one of GitHub's own. The checksum and the
# kernel release inside the pack are checked; anything wrong: the file is
# discarded (Riff then offers to build the pack on this PC).
# Prints RIFF_PACK_DOWNLOADED / RIFF_PACK_UNAVAILABLE; exit 0 = pack present.
R=${1:-$(uname -r)}
DIR=/opt/riff/packs
PK=$DIR/riff-wifi-$R.tar.zst
[ -f "$PK" ] && exit 0
BASE=https://github.com/UAJ-Studio/riff/releases/download/wireless-packs
F=riff-wifi-$R.tar.zst
TMP=$(mktemp -d /tmp/riff-pack.XXXXXX) || exit 1
# explicit cleanup (busybox sh: an EXIT trap loses the exit status)
fail() { echo "RIFF_PACK_UNAVAILABLE kernel=$R ($1)"; rm -rf "$TMP"; exit 1; }
command -v curl >/dev/null || fail "curl is missing"

# get <url> <file>: one redirect at most, and only to GitHub's download hosts
get() {
  r=$(curl -sS --proto =https --tlsv1.2 -m 30 -o /dev/null -w '%{http_code} %{redirect_url}' "$1") || return 1
  code=${r%% *}; to=${r#* }
  case "$code" in
    200) curl -sSf --proto =https --tlsv1.2 -m 300 -o "$2" "$1" ;;
    301|302|303|307|308)
      host=$(echo "$to" | sed -n 's#^https://\([^/:]*\)[/:].*#\1#p')
      case "$host" in
        objects.githubusercontent.com|release-assets.githubusercontent.com|github-releases.githubusercontent.com) ;;
        *) echo "   (refused redirect to: ${host:-$to})"; return 1 ;;
      esac
      curl -sSf --proto =https --tlsv1.2 --max-redirs 0 -m 300 -o "$2" "$to" ;;
    *) return 1 ;;
  esac
}

get "$BASE/$F.sha256" "$TMP/sum" || fail "no pack published for this kernel yet, or no Internet"
get "$BASE/$F" "$TMP/$F" || fail "download failed"
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

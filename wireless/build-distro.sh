#!/bin/bash
# Build the RiffWireless WSL distro rootfs (Alpine): Linux riff-agent +
# wireless pack(s) + loader. Riff imports it as its own distro
# (wsl --import RiffWireless ...), separate from the user's distros.
# usage: build-distro.sh        (run as root in a Linux build box)
# Output: wireless/dist/riffwireless-rootfs.tar.gz
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
WORK=${WORK:-/opt/build/riff/distro}
AV=${AV:-3.20.3}; AB=${AV%.*}
PBV=3.21.12
OUT=$HERE/dist
mkdir -p "$WORK" "$OUT"; cd "$WORK"

MR=alpine-minirootfs-$AV-x86_64.tar.gz
URL=https://dl-cdn.alpinelinux.org/alpine/v$AB/releases/x86_64
[ -f $MR ] || { curl -sSLf -o $MR $URL/$MR; curl -sSLf -o $MR.sha256 $URL/$MR.sha256; }
sha256sum -c $MR.sha256

mkroot() { rm -rf "$1"; mkdir -p "$1"; tar -xzf $MR -C "$1"; cp /etc/resolv.conf "$1/etc/"; }
inroot() { # inroot <root> <cmd...>: run in chroot with /proc,/dev mounted
  local r=$1; shift
  mount -t proc proc "$r/proc"; mount --bind /dev "$r/dev"
  trap "umount '$r/proc' '$r/dev' 2>/dev/null || true" RETURN
  chroot "$r" /bin/sh -c "$*"
}

echo "== [1/3] build root: protobuf $PBV + riff-agent"
B=$WORK/build-root; [ -x $B/bin/sh ] || mkroot $B
inroot $B "apk add -q --no-cache build-base cmake samurai curl linux-headers \
  qt5-qtbase-dev qt5-qtscript-dev libpcap-dev libnl3-dev"
# source: a tarball made by the caller with the repo owner's git, e.g.
#   git archive -o wireless/dist/src.tar $(git stash create || echo HEAD)
SRC_TAR=${SRC_TAR:-$OUT/src.tar}
[ -f "$SRC_TAR" ] || { echo "missing $SRC_TAR (see comment above)"; exit 1; }
# the agent only depends on common/ rpc/ server/ (+ .pri): reuse a previous
# build when those are unchanged
H=$(tar -xOf "$SRC_TAR" --wildcards 'common/*' 'rpc/*' 'server/*' '*.pri' | sha256sum | cut -c1-16)
AGENT=$WORK/agent-cache/riff-agent-$H
if [ -f "$AGENT" ]; then echo "   riff-agent unchanged (cache $H)"; else
rm -rf $B/src; mkdir -p $B/src && tar -xf "$SRC_TAR" -C $B/src
inroot $B "set -e; cd /tmp
  if [ ! -x /opt/pb/bin/protoc ]; then curl -sSLf -o pb.tgz https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protobuf-cpp-$PBV.tar.gz
  tar xzf pb.tgz
  cmake -S protobuf-$PBV -B pb -G Ninja -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF \
    -Dprotobuf_BUILD_SHARED_LIBS=OFF -Dprotobuf_WITH_ZLIB=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_CXX_FLAGS='-include cstdint' -DCMAKE_INSTALL_PREFIX=/opt/pb >/dev/null
  cmake --build pb -j\$(nproc) >/dev/null && cmake --install pb >/dev/null ; fi
  export PATH=/opt/pb/bin:\$PATH
  Q='INCLUDEPATH+=/opt/pb/include' L='LIBS+=-L/opt/pb/lib'
  for d in common rpc server; do
    cd /src/\$d
    pro=\$(ls *.pro | grep -E 'ostproto|pbrpc|drone' | head -1)
    qmake-qt5 \$pro CONFIG+=release \"\$Q\" \"\$L\" >/dev/null && make -s -j\$(nproc) >/dev/null
  done
  strip /src/server/riff-agent; ls -la /src/server/riff-agent"
mkdir -p "$(dirname "$AGENT")" && cp $B/src/server/riff-agent "$AGENT"
fi

echo "== [2/3] runtime root"
R=$WORK/riffwireless-root; mkroot $R
inroot $R "apk add -q --no-cache qt5-qtbase qt5-qtscript libpcap libnl3 iw kmod zstd tar && rm -rf /var/cache/apk/*"
install -m755 "$AGENT" $R/usr/local/bin/riff-agent
# portable-mode ini next to the binary: only show the Wi-Fi dongle(s) in Riff
cat > $R/usr/local/bin/riff-agent.ini <<'INI'
[PortList]
Include=wlan*
INI
install -d $R/opt/riff/packs
install -m755 "$HERE/riff-start.sh" "$HERE/riff-channel.sh" $R/opt/riff/
cp "$HERE"/packs/riff-wifi-*.tar.zst $R/opt/riff/packs/ 2>/dev/null || echo "   (no packs in $HERE/packs yet)"
# supported USB IDs for the Windows side (same driver set in every pack)
P1=$(ls "$HERE"/packs/riff-wifi-*.tar.zst 2>/dev/null | tail -1)
[ -n "$P1" ] && tar --zstd -xOf "$P1" ./USBIDS > "$OUT/riff-wifi-usbids.txt" && \
  echo "   $(wc -l < "$OUT/riff-wifi-usbids.txt") supported USB IDs -> dist/riff-wifi-usbids.txt"
cat > $R/etc/wsl.conf <<'CONF'
[automount]
enabled = false
[interop]
enabled = false
appendWindowsPath = false
CONF
inroot $R "ldd /usr/local/bin/riff-agent | grep 'not found' && exit 1; /usr/local/bin/riff-agent -h | head -2 || true"

echo "== [3/3] rootfs tarball"
rm -f $R/etc/resolv.conf
# content version: Riff compares the installed distro's /opt/riff/VERSION
# with the bundled one and offers to update the distro when they differ
V=$( (cat "$AGENT" "$HERE/riff-start.sh" "$HERE/riff-channel.sh"; \
      ls -l $R/opt/riff/packs; cat /dev/null) | sha256sum | cut -c1-12)
echo "$V" > $R/opt/riff/VERSION
echo "$V" > "$OUT/riffwireless-version.txt"
echo "   content version $V"
tar -czf "$OUT/riffwireless-rootfs.tar.gz" -C $R .
echo "DISTRO_OK $OUT/riffwireless-rootfs.tar.gz ($(du -h "$OUT/riffwireless-rootfs.tar.gz" | cut -f1))"

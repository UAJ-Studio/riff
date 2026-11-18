#!/bin/bash
# Collect riff.exe, riff-agent.exe (and, for a DYNAMIC=1 build, all non-system
# DLLs) into dist/Riff. Run inside an MSYS2 UCRT64 shell after win/build.sh.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/dist/Riff"
if [ "${DYNAMIC:-0}" = 1 ]; then BUILD=$ROOT; else BUILD=$ROOT/build-static; fi
rm -rf "$OUT" && mkdir -p "$OUT"
cp "$BUILD/client/release/riff.exe" "$BUILD/server/release/riff-agent.exe" "$OUT/"
strip "$OUT/riff.exe" "$OUT/riff-agent.exe"

# Qt plugins (platforms, styles, imageformats, ...) and Qt DLLs - only for a
# shared-Qt build; the static build has them inside riff.exe
if [ "${DYNAMIC:-0}" = 1 ]; then
    windeployqt-qt5 --release --no-translations --no-compiler-runtime --no-angle --no-opengl-sw \
        "$OUT/riff.exe" "$OUT/riff-agent.exe" >/dev/null
fi

# Qt's own translations (standard buttons, file dialogs) for the UI
# languages Riff ships; Riff's own .qm files are embedded in riff.exe
mkdir -p "$OUT/translations"
QT_TR=$MINGW_PREFIX/share/qt5/translations
[ "${DYNAMIC:-0}" = 1 ] || QT_TR=$MINGW_PREFIX/qt5-static/share/qt5/translations
for lang in ja; do
    cp "$QT_TR/qtbase_$lang.qm" "$OUT/translations/"
done

# Remaining MinGW runtime / third-party DLLs from the MSYS2 prefix.
# Npcap's wpcap.dll/Packet.dll are deliberately NOT bundled: they come from
# the Npcap driver install (C:\Windows\System32\Npcap).
# (objdump instead of ldd - MSYS2's ldd can hang on some binaries)
PREFIX_BIN="$MINGW_PREFIX/bin"
while :; do
    added=0
    for dll in $(find "$OUT" -name '*.exe' -o -name '*.dll' \
                 | xargs -d '\n' objdump -p 2>/dev/null \
                 | awk '/DLL Name:/ {print $3}' | sort -fu); do
        [ -f "$OUT/$dll" ] && continue
        if [ -f "$PREFIX_BIN/$dll" ]; then
            cp "$PREFIX_BIN/$dll" "$OUT/"
            added=1
        fi
    done
    [ $added -eq 0 ] && break
done
cp "$ROOT/COPYING" "$OUT/"
cp "$ROOT/win/README-windows.txt" "$OUT/README.txt" 2>/dev/null || true
# Wireless dongle support (optional): the RiffWireless WSL distro rootfs and
# the list of supported USB IDs, built by wireless/build-distro.sh
if [ -f "$ROOT/wireless/dist/riffwireless-rootfs.tar.gz" ]; then
    mkdir -p "$OUT/wireless"
    cp "$ROOT/wireless/dist/riffwireless-rootfs.tar.gz" "$ROOT/wireless/dist/riff-wifi-usbids.txt" "$ROOT/wireless/dist/riffwireless-version.txt" "$OUT/wireless/"
    cp "$ROOT/wireless/dist/riff-wifi-extcap.exe" "$OUT/wireless/" 2>/dev/null || true
fi
echo "Packaged into $OUT"

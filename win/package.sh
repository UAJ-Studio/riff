#!/bin/bash
# Collect riff.exe, riff-agent.exe and all non-system DLLs into dist/Riff.
# Run inside an MSYS2 UCRT64 shell after win/build.sh.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/dist/Riff"
rm -rf "$OUT" && mkdir -p "$OUT"
cp "$ROOT/client/release/riff.exe" "$ROOT/server/release/riff-agent.exe" "$OUT/"

# Qt plugins (platforms, styles, imageformats, ...) and Qt DLLs
windeployqt-qt5 --release --no-translations --no-compiler-runtime --no-angle --no-opengl-sw \
    "$OUT/riff.exe" "$OUT/riff-agent.exe" >/dev/null

# Qt's own translations (standard buttons, file dialogs) for the UI
# languages Riff ships; Riff's own .qm files are embedded in riff.exe
mkdir -p "$OUT/translations"
for lang in ja; do
    cp "$MINGW_PREFIX/share/qt5/translations/qtbase_$lang.qm" \
       "$OUT/translations/"
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
echo "Packaged into $OUT"

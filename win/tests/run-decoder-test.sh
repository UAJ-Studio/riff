#!/bin/bash
# Build and run the packet decoder checks (console only, no GUI).
# Run inside an MSYS2 UCRT64 shell.
set -e
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/win/tests/build"
mkdir -p "$OUT"
QTINC="$MINGW_PREFIX/include"
g++ -std=c++17 -O1 -DQT_NO_DEBUG \
    -I"$QTINC" -I"$QTINC/QtCore" -I"$QTINC/QtNetwork" \
    "$ROOT/win/tests/decoder_test.cpp" "$ROOT/client/packetdecoder.cpp" \
    -o "$OUT/decoder_test.exe" -lQt5Core -lQt5Network
"$OUT/decoder_test.exe"

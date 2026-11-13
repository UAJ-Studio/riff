#!/bin/bash
# Build and run the protocol engine checks (console only, no GUI).
# Run inside an MSYS2 UCRT64 shell after win/build.sh (needs
# common/release/libostproto.a and the generated *.pb.h files).
set -e
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DEPS=${DEPS:-$(cd "$ROOT/../deps" && pwd)}
OUT="$ROOT/win/tests/build"
mkdir -p "$OUT"
QTINC="$MINGW_PREFIX/include"
g++ -std=c++17 -O1 -DQT_NO_DEBUG \
    -I"$DEPS/protobuf/include" -I"$ROOT/common" \
    -I"$QTINC" -I"$QTINC/QtCore" -I"$QTINC/QtNetwork" -I"$QTINC/QtScript" \
    -I"$QTINC/QtXml" \
    "$ROOT/win/tests/protocol_test.cpp" "$ROOT/client/packetdecoder.cpp" \
    -o "$OUT/protocol_test.exe" \
    -L"$ROOT/common/release" -lostproto \
    -L"$DEPS/protobuf/lib" -lprotobuf \
    -lQt5Script -lQt5Xml -lQt5Network -lQt5Core
"$OUT/protocol_test.exe" "$@"

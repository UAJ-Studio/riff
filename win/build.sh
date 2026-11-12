#!/bin/bash
# Build Ostinato (GUI + drone) for Windows.
# Run inside an MSYS2 UCRT64 shell. Expects dependencies in ../deps:
#   deps/protobuf   - protobuf 3.21.12 installed prefix (see win/build-protobuf.sh)
#   deps/npcap-sdk  - Npcap SDK (Include/, Lib/x64/)
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEPS=${DEPS:-$(cd "$ROOT/../deps" && pwd)}
PB=$(cygpath -m "$DEPS/protobuf")
NPCAP=$(cygpath -m "$DEPS/npcap-sdk")
JOBS=${JOBS:-$(nproc)}

export PATH="$DEPS/protobuf/bin:$PATH"
cd "$ROOT"

qmake-qt5 ost.pro CONFIG+=release \
    "INCLUDEPATH+=$PB/include $NPCAP/Include" \
    "LIBS+=-L$PB/lib -L$NPCAP/Lib/x64"
mingw32-make -j"$JOBS"

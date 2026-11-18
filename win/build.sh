#!/bin/bash
# Build Riff (riff.exe GUI + riff-agent.exe) for Windows.
# Run inside an MSYS2 UCRT64 shell. Expects dependencies in ../deps:
#   deps/protobuf   - protobuf 3.21.12 installed prefix (see win/build-protobuf.sh)
#   deps/npcap-sdk  - Npcap SDK (Include/, Lib/x64/)
#
# Default: static build with Qt linked into the executables (needs the MSYS2
# package mingw-w64-ucrt-x86_64-qt5-static), built in ./build-static. The
# release executables then depend only on Windows system DLLs (and Npcap for
# riff-agent.exe), so only our own binaries need code signing.
# DYNAMIC=1: in-tree build against the shared Qt (mingw-w64-ucrt-x86_64-qt5),
# handy for development.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEPS=${DEPS:-$(cd "$ROOT/../deps" && pwd)}
PB=$(cygpath -m "$DEPS/protobuf")
NPCAP=$(cygpath -m "$DEPS/npcap-sdk")
JOBS=${JOBS:-$(nproc)}

export PATH="$DEPS/protobuf/bin:$PATH"
cd "$ROOT"

# Compile translations first - the .qm files are embedded via client/riff.qrc
LRELEASE=$(command -v lrelease-qt5 || echo "$MINGW_PREFIX/qt5-static/bin/lrelease")
for ts in i18n/*.ts; do
    "$LRELEASE" -silent "$ts" -qm "${ts%.ts}.qm"
done

ARGS=(CONFIG+=release
    "INCLUDEPATH+=$PB/include $NPCAP/Include"
    "LIBS+=-L$PB/lib -L$NPCAP/Lib/x64")
if [ "${DYNAMIC:-0}" = 1 ]; then
    qmake-qt5 ost.pro "${ARGS[@]}"
else
    QMAKE_STATIC="$MINGW_PREFIX/qt5-static/bin/qmake"
    [ -x "$QMAKE_STATIC" ] || { echo "missing $QMAKE_STATIC (pacman -S mingw-w64-ucrt-x86_64-qt5-static)"; exit 1; }
    mkdir -p "$ROOT/build-static" && cd "$ROOT/build-static"
    "$QMAKE_STATIC" ../ost.pro "${ARGS[@]}" "QMAKE_LFLAGS+=-static"
fi
mingw32-make -j"$JOBS"

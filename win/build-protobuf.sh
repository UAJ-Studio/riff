#!/bin/bash
# Fetch and build protobuf 3.21.12 (last release without abseil) as static libs
# into ../deps/protobuf. Run inside an MSYS2 UCRT64 shell.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEPS=${DEPS:-$ROOT/../deps}
mkdir -p "$DEPS" && cd "$DEPS"
[ -d protobuf-3.21.12 ] || {
    curl -sSL -o protobuf-3.21.12.tar.gz \
        https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protobuf-cpp-3.21.12.tar.gz
    tar xzf protobuf-3.21.12.tar.gz
}
cmake -S protobuf-3.21.12 -B pb-build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=OFF -Dprotobuf_WITH_ZLIB=OFF \
  -DCMAKE_CXX_FLAGS="-include cstdint" \
  -DCMAKE_INSTALL_PREFIX="$(pwd)/protobuf"
cmake --build pb-build -j"$(nproc)"
cmake --install pb-build

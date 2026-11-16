#!/bin/bash
# Build the Riff Wi-Fi extcap (Wireshark live capture through the
# RiffWireless distro) for Windows. Runs anywhere Go >= 1.22 is installed.
# Output: wireless/dist/riff-wifi-extcap.exe
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/../dist
VER=${VER:-$(cat "$HERE/VERSION" 2>/dev/null || echo dev)}
mkdir -p "$OUT"
cd "$HERE"
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOFLAGS="-trimpath -buildvcs=false"
go vet ./...
go build -ldflags "-s -w -X riffwifi/internal/common.Version=$VER" \
    -o "$OUT/riff-wifi-extcap.exe" ./cmd/extcap
ls -la "$OUT/riff-wifi-extcap.exe"

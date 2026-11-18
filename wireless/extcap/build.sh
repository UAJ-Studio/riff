#!/bin/bash
# Build the Riff Wi-Fi extcap (Wireshark live capture through the
# RiffWireless distro) for Windows. Runs anywhere Go >= 1.22 is installed.
# Output: wireless/dist/riff-wifi-extcap.exe
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=$HERE/../dist
VER=${VER:-$(cat "$HERE/VERSION" 2>/dev/null || echo dev)}
APP_VER=$(sed -n 's/^APP_VERSION *= *//p' "$REPO/version.pri" | head -1)
mkdir -p "$OUT"
cd "$HERE"

# Windows version resource: product name/version = Riff's (the same in every
# signed file), file version = the extcap's own
GVI=$(go env GOPATH)/bin/goversioninfo
[ -x "$GVI" ] || [ -x "$GVI.exe" ] || go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1
num() { local a b c; IFS=. read -r a b c <<< "$1"; echo "\"Major\": ${a:-0}, \"Minor\": ${b:-0}, \"Patch\": ${c:-0}, \"Build\": 0"; }
VI=$(mktemp)
cat > "$VI" <<JSON
{
  "FixedFileInfo": {
    "FileVersion":    {$(num "$VER")},
    "ProductVersion": {$(num "$APP_VER")},
    "FileFlagsMask": "3f", "FileFlags": "00", "FileOS": "040004", "FileType": "01", "FileSubType": "00"
  },
  "StringFileInfo": {
    "CompanyName": "UAJ-Studio",
    "FileDescription": "Riff Wi-Fi capture (Wireshark extcap)",
    "FileVersion": "$VER",
    "ProductName": "Riff",
    "ProductVersion": "$APP_VER.0",
    "OriginalFilename": "riff-wifi-extcap.exe",
    "InternalName": "riff-wifi-extcap",
    "LegalCopyright": "GPLv3. UAJ-Studio"
  },
  "VarFileInfo": {"Translation": {"LangID": "0409", "CharsetID": "04B0"}}
}
JSON
rm -f cmd/extcap/*.syso
(cd cmd/extcap && GOOS= GOARCH= "$GVI" -64 -icon "$REPO/client/icons/logo.ico" -o rsrc_windows_amd64.syso "$VI")
rm -f "$VI"

export GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOFLAGS="-trimpath -buildvcs=false"
go vet ./cmd/extcap ./internal/...   # cmd/setup embeds payload/, made later
go build -ldflags "-s -w -X riffwifi/internal/common.Version=$VER" \
    -o "$OUT/riff-wifi-extcap.exe" ./cmd/extcap
ls -la "$OUT/riff-wifi-extcap.exe"

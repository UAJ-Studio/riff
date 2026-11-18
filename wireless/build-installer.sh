#!/bin/bash
# Build the Riff installer: dist/Riff-<version>-setup.exe
#   - embeds the dist/Riff folder (as a zip) and the usbipd-win installer
#   - Windows resources: icon, version info, asInvoker manifest
# usage: build-installer.sh [path to usbipd-win .msi]
# Runs in a Linux build box (WSL Ubuntu) with Go >= 1.22 and python3.
# Code signing is not done here: sign dist/Riff-*-setup.exe (and ideally
# riff.exe / riff-agent.exe / riff-wifi-extcap.exe before packing) with
# signtool once a certificate is available.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
SRC=$HERE/extcap
P=$SRC/cmd/setup/payload
MSI=${1:-${USBIPD_MSI:-}}
VER=$(sed -n 's/^APP_VERSION *= *//p' "$REPO/version.pri" | head -1)
[ -n "$VER" ] || { echo "no APP_VERSION in version.pri"; exit 1; }
IFS=. read -r V1 V2 V3 <<< "$VER"
DIST=$REPO/dist
[ -x "$DIST/Riff/riff.exe" ] || [ -f "$DIST/Riff/riff.exe" ] || { echo "missing $DIST/Riff/riff.exe"; exit 1; }

mkdir -p "$P"
# usbipd-win: given path, or the copy from a previous build
if [ -n "$MSI" ]; then cp "$MSI" "$P/usbipd.msi"; fi
[ -f "$P/usbipd.msi" ] || { echo "usage: $0 <usbipd-win .msi> (first build)"; exit 1; }

echo "== zip dist/Riff ($(du -sh "$DIST/Riff" | cut -f1))"
rm -f "$P/riff.zip"
python3 - "$DIST/Riff" "$P/riff.zip" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
skip = {"riff.ini", "riff-agent.ini"}          # per-user settings, if any
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for root, dirs, files in os.walk(src):
        dirs.sort()
        for f in sorted(files):
            rel = os.path.relpath(os.path.join(root, f), src).replace(os.sep, "/")
            if rel in skip or rel.endswith(".log"):
                continue
            # already compressed: store
            ct = zipfile.ZIP_STORED if f.endswith((".gz", ".zst")) else zipfile.ZIP_DEFLATED
            z.write(os.path.join(root, f), rel, compress_type=ct)
PY
ls -la "$P/riff.zip"

echo "== resources"
GVI=$(GOOS= GOARCH= go env GOPATH)/bin/goversioninfo
[ -x "$GVI" ] || GOOS= GOARCH= go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1
cat > /tmp/riff-versioninfo.json <<EOF
{
  "FixedFileInfo": {
    "FileVersion":    {"Major": $V1, "Minor": $V2, "Patch": $V3, "Build": 0},
    "ProductVersion": {"Major": $V1, "Minor": $V2, "Patch": $V3, "Build": 0},
    "FileFlagsMask": "3f", "FileFlags": "00", "FileOS": "040004", "FileType": "01", "FileSubType": "00"
  },
  "StringFileInfo": {
    "FileDescription": "Riff installer",
    "FileVersion": "$VER",
    "ProductName": "Riff",
    "ProductVersion": "$VER",
    "OriginalFilename": "Riff-$VER-setup.exe",
    "InternalName": "Riff setup",
    "LegalCopyright": "GPLv3. Derived from Ostinato (c) 2007-2023 Srivats P."
  },
  "VarFileInfo": {"Translation": {"LangID": "0411", "CharsetID": "04B0"}}
}
EOF
rm -f "$SRC/cmd/setup/"*.syso
"$GVI" -64 -icon "$REPO/client/icons/logo.ico" -manifest "$SRC/cmd/setup/setup.manifest" \
    -o "$SRC/cmd/setup/rsrc_windows_amd64.syso" /tmp/riff-versioninfo.json

echo "== build"
cd "$SRC"
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOFLAGS="-trimpath -buildvcs=false"
go vet ./cmd/setup
go build -ldflags "-s -w -X main.Version=$VER" -o "$DIST/Riff-$VER-setup.exe" ./cmd/setup
ls -la "$DIST/Riff-$VER-setup.exe"

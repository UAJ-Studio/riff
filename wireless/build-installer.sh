#!/bin/bash
# Build the Riff installer dist/Riff-<version>-setup.exe with Inno Setup
# (win/riff.iss): the dist/Riff folder (win/package.sh), the installer's
# helper riff-maintenance.exe (built here) and the usbipd-win installer.
# usage: build-installer.sh [path to usbipd-win .msi]
#   (the .msi is kept as dist/usbipd.msi for later builds)
# Needs Go >= 1.22 and Inno Setup >= 6.3 (ISCC.exe). Runs in an MSYS2 / Git
# Bash shell on Windows, or in WSL (ISCC.exe through Windows interop).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
SRC=$HERE/extcap
DIST=$REPO/dist
MSI=${1:-${USBIPD_MSI:-}}
VER=$(sed -n 's/^APP_VERSION *= *//p' "$REPO/version.pri" | head -1)
[ -n "$VER" ] || { echo "no APP_VERSION in version.pri"; exit 1; }
[ -f "$DIST/Riff/riff.exe" ] || { echo "missing $DIST/Riff/riff.exe (run win/package.sh)"; exit 1; }
if [ -n "$MSI" ]; then cp "$MSI" "$DIST/usbipd.msi"; fi
[ -f "$DIST/usbipd.msi" ] || { echo "usage: $0 <usbipd-win .msi> (first build)"; exit 1; }

winpath() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else wslpath -w "$1"; fi; }

echo "== helper riff-maintenance.exe"
GVI=$(GOOS= GOARCH= go env GOPATH)/bin/goversioninfo
[ -x "$GVI" ] || [ -x "$GVI.exe" ] || GOOS= GOARCH= go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1
IFS=. read -r V1 V2 V3 <<< "$VER"
VI=$(mktemp)
cat > "$VI" <<JSON
{
  "FixedFileInfo": {
    "FileVersion":    {"Major": $V1, "Minor": $V2, "Patch": $V3, "Build": 0},
    "ProductVersion": {"Major": $V1, "Minor": $V2, "Patch": $V3, "Build": 0},
    "FileFlagsMask": "3f", "FileFlags": "00", "FileOS": "040004", "FileType": "01", "FileSubType": "00"
  },
  "StringFileInfo": {
    "CompanyName": "UAJ-Studio",
    "FileDescription": "Riff maintenance helper (used by the installer)",
    "FileVersion": "$VER.0",
    "ProductName": "Riff",
    "ProductVersion": "$VER.0",
    "OriginalFilename": "riff-maintenance.exe",
    "InternalName": "riff-maintenance",
    "LegalCopyright": "GPLv3. UAJ-Studio"
  },
  "VarFileInfo": {"Translation": {"LangID": "0409", "CharsetID": "04B0"}}
}
JSON
M=$SRC/cmd/maintenance
rm -f "$M"/*.syso
(cd "$M" && GOOS= GOARCH= "$GVI" -64 -icon "$REPO/client/icons/logo.ico" \
    -manifest maintenance.manifest -o rsrc_windows_amd64.syso "$VI")
rm -f "$VI"
(cd "$SRC" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOFLAGS="-trimpath -buildvcs=false" \
    go vet ./cmd/maintenance && \
 GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOFLAGS="-trimpath -buildvcs=false" \
    go build -ldflags "-s -w -H windowsgui -X main.Version=$VER" -o "$DIST/riff-maintenance.exe" ./cmd/maintenance)

echo "== Inno Setup"
ISCC=${ISCC:-}
if [ -z "$ISCC" ]; then
    for c in "$(command -v iscc || true)" "$(command -v ISCC.exe || true)" \
             "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" \
             "${LOCALAPPDATA:+$(cygpath -u "$LOCALAPPDATA" 2>/dev/null)/Programs/Inno Setup 6/ISCC.exe}" \
             /mnt/c/Program\ Files\ \(x86\)/Inno\ Setup\ 6/ISCC.exe \
             /mnt/c/Users/*/AppData/Local/Programs/Inno\ Setup\ 6/ISCC.exe; do
        [ -n "$c" ] && [ -f "$c" ] && { ISCC=$c; break; }
    done
fi
[ -n "$ISCC" ] || { echo "Inno Setup (ISCC.exe) not found: set ISCC=..."; exit 1; }
rm -f "$DIST/Riff-$VER-setup.exe"
# no MSYS argument conversion: /D... are ISCC options, not paths
MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1 "$ISCC" /Q \
    "/DAppVersion=$VER" \
    "/DDistDir=$(winpath "$DIST/Riff")" \
    "/DHelperExe=$(winpath "$DIST/riff-maintenance.exe")" \
    "/DUsbipdMsi=$(winpath "$DIST/usbipd.msi")" \
    "/DOutputDir=$(winpath "$DIST")" \
    "$(winpath "$REPO/win/riff.iss")"
ls -la "$DIST/Riff-$VER-setup.exe"

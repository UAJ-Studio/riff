// Package common holds names and paths shared by the Riff Wi-Fi extcap.
// (Derived from WiFiCap's extcap, adapted to Riff's RiffWireless distro.)
package common

import (
	"os"
	"path/filepath"
)

// Version is set at build time:
//
//	go build -ldflags "-X riffwifi/internal/common.Version=1.2.3"
var Version = "dev"

const (
	Product     = "Riff Wi-Fi Capture"
	DistroName  = "RiffWireless"
	ExtcapName  = "riff-wifi-extcap.exe"
	InterfaceID = "riffwifi"
	// script inside the distro that loads the drivers, tunes the dongle and
	// streams radiotap pcap to stdout
	CaptureScript = "/opt/riff/riff-capture"
)

// DataDir is the per-user directory for logs.
func DataDir() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "Riff")
}

// ExtcapDir is Wireshark's personal extcap folder.
func ExtcapDir() string {
	return filepath.Join(os.Getenv("APPDATA"), "Wireshark", "extcap")
}

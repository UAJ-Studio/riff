//go:build windows

package main

import (
	"embed"
	"io"
	"os"
	"path/filepath"
)

// payload/ is filled by wireless/build-installer.sh (not in git):
//
//	riff.zip     - the dist/Riff folder (riff.exe, riff-agent.exe, Qt, wireless/)
//	usbipd.msi   - usbipd-win installer (signed by its author)
//
//go:embed payload/*
var payload embed.FS

// extract writes payload/name to dst.
func extract(name, dst string) error {
	f, err := payload.Open("payload/" + name)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, f); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

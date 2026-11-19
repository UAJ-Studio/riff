//go:build windows

// riff-maintenance.exe: helper the Riff installer (Inno Setup, win/riff.iss)
// runs for the steps Inno Setup cannot do by itself. It has no window; the
// installer asks the questions and runs it with one action at a time:
//
//	--close-riff               close Riff (and its agent) before files change
//	--riff-dongles             print the bus ids of USB Wi-Fi dongles that are
//	                           registered for Riff (comma separated)
//	--elevated-unbind --busids=1-2,1-3
//	                           give those dongles back to Windows (run elevated)
//	--distro-exists            exit 0 if Riff's WSL distro is registered
//	--unregister-distro        remove Riff's WSL distro
//	--remove-extcap            remove Riff's extcap from Wireshark's folder
//	--remove-settings          remove Riff's settings (registry + data folder)
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"riffwifi/internal/common"
	"riffwifi/internal/usbip"
	"riffwifi/internal/winx"
)

// Version is set at build time (-X main.Version=...).
var Version = "dev"

const settingsKey = `HKCU\Software\Riff`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Printf("riff-maintenance %s (used by the Riff installer)\n", Version)
		return
	}
	code := 0
	switch strings.ToLower(args[0]) {
	case "--close-riff":
		closeRiff()
	case "--riff-dongles":
		fmt.Print(strings.Join(riffDongles(appDir()), ","))
	case "--elevated-unbind":
		elevatedUnbind(args[1:])
	case "--distro-exists":
		if !distroExists() {
			code = 1
		}
	case "--unregister-distro":
		if distroExists() {
			if _, err := winx.Run("wsl.exe", "--unregister", common.DistroName); err != nil {
				code = 1
			}
		}
	case "--remove-extcap":
		_ = os.Remove(filepath.Join(common.ExtcapDir(), common.ExtcapName))
	case "--remove-settings":
		_, _ = winx.Run("reg.exe", "delete", settingsKey, "/f")
		_ = os.RemoveAll(common.DataDir())
	case "--version":
		fmt.Print(Version)
	default:
		fmt.Fprintln(os.Stderr, "unknown action:", args[0])
		code = 2
	}
	os.Exit(code)
}

// appDir: the install folder (this helper is installed next to riff.exe)
func appDir() string {
	self, err := os.Executable()
	if err != nil {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Riff")
	}
	return filepath.Dir(self)
}

// closeRiff closes Riff normally first (it then hands USB dongles back to
// Windows cleanly), and forcibly only if it does not exit in time.
func closeRiff() {
	if !processRunning("riff.exe") && !processRunning("riff-agent.exe") {
		return
	}
	_, _ = winx.Run("taskkill.exe", "/im", "riff.exe")
	for i := 0; i < 60 && processRunning("riff.exe"); i++ {
		time.Sleep(time.Second)
	}
	if processRunning("riff.exe") {
		_, _ = winx.Run("taskkill.exe", "/f", "/im", "riff.exe")
	}
	_, _ = winx.Run("taskkill.exe", "/f", "/im", "riff-agent.exe")
	time.Sleep(time.Second)
}

func processRunning(image string) bool {
	out, _ := winx.Run("tasklist.exe", "/fi", "imagename eq "+image, "/fo", "csv", "/nh")
	return strings.Contains(strings.ToLower(out), strings.ToLower(image))
}

// riffDongles: bus ids of plugged-in dongles force-bound (registered for
// Riff) whose USB id is one Riff's drivers support
func riffDongles(dir string) []string {
	if usbip.Exe() == "" {
		return nil
	}
	supported := map[string]bool{}
	if b, err := os.ReadFile(filepath.Join(dir, "wireless", "riff-wifi-usbids.txt")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) > 0 {
				supported[strings.ToLower(f[0])] = true
			}
		}
	}
	// Riff (just closed) hands its dongles back to Windows: one may be
	// re-enumerating and missing from a single listing - look a few times
	var ids []string
	seen := map[string]bool{}
	for try := 0; try < 4; try++ {
		if try > 0 {
			time.Sleep(2 * time.Second)
		}
		list, err := usbip.List()
		if err != nil {
			continue
		}
		for _, d := range list {
			if d.IsForced && (len(supported) == 0 || supported[d.HWID()]) && !seen[d.BusId] {
				ids = append(ids, d.BusId)
				seen[d.BusId] = true
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func elevatedUnbind(args []string) {
	exe := usbip.Exe()
	if exe == "" {
		return
	}
	for _, a := range args {
		if !strings.HasPrefix(a, "--busids=") {
			continue
		}
		for _, id := range strings.Split(strings.TrimPrefix(a, "--busids="), ",") {
			if id = strings.TrimSpace(id); id == "" {
				continue
			}
			// bind first so unbind also clears a forced flag without a
			// share record (same as Riff's "give back to Windows")
			_, _ = winx.Run(exe, "detach", "--busid", id)
			_, _ = winx.Run(exe, "bind", "--busid", id)
			_, _ = winx.Run(exe, "unbind", "--busid", id)
		}
	}
}

func distroExists() bool {
	out, err := winx.Run("wsl.exe", "-l", "-q")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.EqualFold(strings.TrimSpace(l), common.DistroName) {
			return true
		}
	}
	return false
}

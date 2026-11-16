//go:build windows

// Package usbip wraps the usbipd-win command line.
package usbip

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"riffwifi/internal/devices"
	"riffwifi/internal/winx"
)

type Device struct {
	BusId           string
	ClientIPAddress *string
	Description     string
	InstanceId      string
	IsForced        bool
	PersistedGuid   *string
	StubInstanceId  *string
	VID, PID        string // filled in by us, lower-case hex
	Name            string // known adapter name, if any
}

func (d Device) Attached() bool { return d.ClientIPAddress != nil && *d.ClientIPAddress != "" }
func (d Device) Shared() bool   { return d.PersistedGuid != nil && *d.PersistedGuid != "" }
func (d Device) HWID() string   { return d.VID + ":" + d.PID }

// Serial is the last component of the Windows instance id (the USB serial
// number, or a port-derived id for devices without one).
func (d Device) Serial() string {
	if i := strings.LastIndex(d.InstanceId, `\`); i >= 0 {
		return strings.ToLower(d.InstanceId[i+1:])
	}
	return ""
}

// Exe returns the path to usbipd.exe, or "" if not installed.
func Exe() string {
	if p, err := exec.LookPath("usbipd.exe"); err == nil {
		return p
	}
	for _, env := range []string{"ProgramW6432", "ProgramFiles"} {
		p := filepath.Join(os.Getenv(env), "usbipd-win", "usbipd.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

var vidpid = regexp.MustCompile(`(?i)VID_([0-9A-F]{4})&PID_([0-9A-F]{4})`)

// List returns connected USB devices (devices that are plugged in).
func List() ([]Device, error) {
	exe := Exe()
	if exe == "" {
		return nil, fmt.Errorf("usbipd-win is not installed")
	}
	out, err := winx.Hidden(exe, "state").Output()
	if err != nil {
		return nil, fmt.Errorf("usbipd state failed: %v", err)
	}
	var st struct{ Devices []Device }
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, fmt.Errorf("cannot parse usbipd state: %v", err)
	}
	var res []Device
	for _, d := range st.Devices {
		if d.BusId == "" { // persisted but not plugged in
			continue
		}
		if m := vidpid.FindStringSubmatch(d.InstanceId); m != nil {
			d.VID, d.PID = strings.ToLower(m[1]), strings.ToLower(m[2])
		}
		d.Name = devices.Known[d.HWID()]
		res = append(res, d)
	}
	return res, nil
}

// WifiAdapters returns plugged-in devices that our kernel has a driver for.
func WifiAdapters() ([]Device, error) {
	all, err := List()
	if err != nil {
		return nil, err
	}
	var res []Device
	for _, d := range all {
		if d.Name != "" {
			res = append(res, d)
		}
	}
	return res, nil
}

// Attach attaches a device to WSL. If it is not shared yet and no policy
// allows it, a UAC prompt is shown to bind it once.
func Attach(d Device) error {
	exe := Exe()
	out, err := winx.Run(exe, "attach", "--wsl", "--busid", d.BusId)
	if err == nil {
		return nil
	}
	low := strings.ToLower(out)
	if strings.Contains(low, "already attached") {
		return nil
	}
	if strings.Contains(low, "not shared") || strings.Contains(low, "bind") || strings.Contains(low, "administrator") {
		code, eerr := winx.RunElevated(exe, "bind --busid "+d.BusId, false)
		if eerr != nil {
			return fmt.Errorf("binding the adapter needs administrator rights: %v", eerr)
		}
		if code != 0 {
			return fmt.Errorf("usbipd bind failed (exit %d)", code)
		}
		_, err = winx.Run(exe, "attach", "--wsl", "--busid", d.BusId)
	}
	return err
}

// StartAutoAttach runs "usbipd attach --auto-attach" in the background. Many
// adapters drop off the bus once while the Linux driver uploads firmware;
// auto-attach hands them back to WSL when they re-enumerate. The returned
// process keeps running until killed. If the device is not shared yet (and
// no policy allows it), it is bound once through a UAC prompt.
func StartAutoAttach(d Device, logf func(string, ...any)) (*exec.Cmd, error) {
	exe := Exe()
	start := func() (*exec.Cmd, *strings.Builder, error) {
		var out strings.Builder
		c := winx.Hidden(exe, "attach", "--wsl", "--busid", d.BusId, "--auto-attach")
		c.Stdout = &out
		c.Stderr = &out
		return c, &out, c.Start()
	}
	for try := 0; try < 2; try++ {
		c, out, err := start()
		if err != nil {
			return nil, err
		}
		exited := make(chan error, 1)
		go func() { exited <- c.Wait() }()
		select {
		case err := <-exited:
			msg := out.String()
			logf("usbipd auto-attach exited: %v: %s", err, msg)
			low := strings.ToLower(msg)
			if try == 0 && (strings.Contains(low, "not shared") || strings.Contains(low, "bind") || strings.Contains(low, "administrator")) {
				code, eerr := winx.RunElevated(exe, "bind --busid "+d.BusId, false)
				if eerr != nil || code != 0 {
					return nil, fmt.Errorf("binding the adapter needs administrator rights (exit %d): %v", code, eerr)
				}
				continue
			}
			return nil, fmt.Errorf("usbipd attach failed: %s", strings.TrimSpace(msg))
		case <-time.After(4 * time.Second):
			// Still running: the endless attach loop is active.
			go func() {
				err := <-exited
				logf("usbipd auto-attach ended: %v: %s", err, out.String())
			}()
			return c, nil
		}
	}
	return nil, fmt.Errorf("usbipd attach failed")
}

// Detach returns a device to Windows.
func Detach(d Device) error {
	_, err := winx.Run(Exe(), "detach", "--busid", d.BusId)
	return err
}

// AttachLock is the name of the mutex that serializes handing dongles
// between Windows and WSL (shared with Riff, see winx.NamedLock).
const AttachLock = `Local\RiffWifiUsbHandover`

// ForceBind shares the device with WSL in "forced" mode through UAC: the
// Windows Wi-Fi driver is unloaded once, cleanly, and stays off the device
// until Unbind. This avoids tearing the Windows driver down while it is
// running when the device is attached (the Realtek rtwlanu6 driver can
// crash Windows - BAD_POOL_HEADER - on that path).
func ForceBind(d Device) error {
	code, err := winx.RunElevated(Exe(), "bind --busid "+d.BusId+" --force", false)
	if err != nil {
		return fmt.Errorf("administrator rights are needed: %v", err)
	}
	if code != 0 {
		return fmt.Errorf("usbipd bind --force failed (exit %d)", code)
	}
	return nil
}

// Unbind gives the device back to its Windows driver (UAC).
func Unbind(busid string) error {
	code, err := winx.RunElevated(Exe(), "unbind --busid "+busid, false)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("usbipd unbind failed (exit %d)", code)
	}
	return nil
}

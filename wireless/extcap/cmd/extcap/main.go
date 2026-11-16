//go:build windows

// riff-wifi-extcap: Wireshark extcap that captures 802.11 frames in monitor
// mode from a USB Wi-Fi adapter handed to WSL2 with usbipd-win.
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"riffwifi/internal/common"
	"riffwifi/internal/pcapts"
	"riffwifi/internal/usbip"
	"riffwifi/internal/wifi"
	"riffwifi/internal/winx"
)

var boolFlags = map[string]bool{
	"extcap-interfaces": true, "extcap-dlts": true, "extcap-config": true,
	"capture": true, "debug": true, "help": true, "version": true, "keep": true, "hosttime": true, "fcserrors": true,
}

func parseArgs(argv []string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !strings.HasPrefix(a, "--") {
			continue
		}
		a = a[2:]
		if k, v, ok := strings.Cut(a, "="); ok {
			m[k] = v
			continue
		}
		if boolFlags[a] || i+1 >= len(argv) || strings.HasPrefix(argv[i+1], "--") {
			m[a] = "true"
			continue
		}
		m[a] = argv[i+1]
		i++
	}
	return m
}

func main() {
	args := parseArgs(os.Args[1:])
	setupLog()
	log.Printf("v%s args: %q", common.Version, os.Args[1:])

	var err error
	switch {
	case args["extcap-interfaces"] != "":
		printInterfaces()
	case args["extcap-dlts"] != "":
		fmt.Println("dlt {number=127}{name=IEEE802_11_RADIO}{display=802.11 + radiotap}")
	case args["extcap-config"] != "":
		printConfig()
	case args["capture"] != "":
		err = capture(args)
	case args["restore-after"] != "":
		restoreAfter(args["restore-after"], args["busid"])
	case args["version"] != "":
		fmt.Println(common.Product, common.Version)
	default:
		fmt.Fprintln(os.Stderr, "This program is a Wireshark extcap plugin. Start a capture from Wireshark.")
		os.Exit(1)
	}
	if err != nil {
		log.Printf("error: %v", err)
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func setupLog() {
	dir := common.DataDir()
	_ = os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, "extcap.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > 2<<20 {
		_ = os.Rename(p, p+".old")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.SetOutput(io.Discard)
		return
	}
	log.SetOutput(f)
	log.SetPrefix(fmt.Sprintf("[%d] ", os.Getpid()))
}

// ifaceValue builds the interface name "riffwifi_<vid>_<pid>_<bus>_<port>"
// ('-' is not allowed in Wireshark preference names).
func ifaceValue(d usbip.Device) string {
	return fmt.Sprintf("%s_%s_%s_%s", common.InterfaceID, d.VID, d.PID, strings.ReplaceAll(d.BusId, "-", "_"))
}

// parseIface returns vid, pid, busid from an interface name ("" if generic).
func parseIface(v string) (vid, pid, busid string) {
	s, ok := strings.CutPrefix(v, common.InterfaceID+"_")
	if !ok {
		return
	}
	f := strings.Split(s, "_")
	if len(f) >= 4 {
		return f[0], f[1], strings.Join(f[2:], "-")
	}
	return "", "", strings.Join(f, "-")
}

// printInterfaces lists one Wireshark interface per plugged-in supported
// dongle, so several adapters can be told apart and captured at the same
// time. With none plugged in, a generic entry is shown that uses the first
// adapter found at capture time.
func printInterfaces() {
	fmt.Printf("extcap {version=%s}{display=%s}\n", common.Version, common.Product)
	adapters, err := usbip.WifiAdapters()
	if err != nil {
		log.Printf("interfaces: %v", err)
	}
	for _, d := range adapters {
		desc := strings.TrimSpace(d.Description)
		if desc == "" {
			desc = d.HWID()
		}
		fmt.Printf("interface {value=%s}{display=Wi-Fi monitor: %s (%s, USB %s)}\n",
			ifaceValue(d), desc, d.Name, d.BusId)
	}
	if len(adapters) == 0 {
		fmt.Printf("interface {value=%s}{display=Wi-Fi monitor (USB dongle via WSL2) - plug in a dongle, then refresh interfaces}\n", common.InterfaceID)
	}
}

func printConfig() {
	fmt.Println("arg {number=0}{call=--channel}{display=Channel}{type=selector}{tooltip=Control channel to capture on}{group=Radio}")
	for _, c := range wifi.Channels() {
		def := ""
		if c.Band == wifi.Band5 && c.Num == 36 {
			def = "{default=true}"
		}
		fmt.Printf("value {arg=0}{value=%d}{display=%s  ch %d  (%d MHz)}%s\n", c.Freq, c.Band, c.Num, c.Freq, def)
	}
	fmt.Println("arg {number=1}{call=--width}{display=Channel width}{type=selector}{tooltip=Bandwidth. The adapter must support it (e.g. 320 MHz needs a Wi-Fi 7 320 MHz adapter).}{group=Radio}")
	for _, w := range []int{20, 40, 80, 160, 320} {
		def := ""
		if w == 20 {
			def = "{default=true}"
		}
		fmt.Printf("value {arg=1}{value=%d}{display=%d MHz}%s\n", w, w, def)
	}
	fmt.Println("arg {number=2}{call=--country}{display=Country (regulatory)}{type=string}{default=JP}{tooltip=ISO country code that decides which channels are allowed. 00 = do not change.}{group=Radio}")
	fmt.Println("arg {number=4}{call=--keep}{display=Keep adapter in WSL after capture}{type=boolflag}{default=false}{tooltip=Off (default): the dongle goes back to Windows as soon as the capture stops. On: it stays in WSL so the next capture starts faster.}{group=Adapter}")
	fmt.Println("arg {number=6}{call=--fcserrors}{display=Include frames with bad FCS / PHY errors}{type=boolflag}{default=false}{tooltip=Also capture corrupted frames (like AirPcap's 'all frames' FCS filter). They are marked in radiotap (Flags: Bad FCS); filter them with radiotap.flags.badfcs == 1.}{group=Radio}")
	fmt.Println("arg {number=5}{call=--hosttime}{display=Use host arrival time (disable radio TSFT timestamps)}{type=boolflag}{default=false}{tooltip=Off (default): frame times are rebuilt from the radio's microsecond TSF counter, so gaps between frames are exact (absolute time anchored to the PC clock). On: keep the time the frame reached WSL (includes USB/USB-IP batching delay).}{group=Radio}")
}

func capture(args map[string]string) error {
	fifo := args["fifo"]
	if fifo == "" {
		return fmt.Errorf("--fifo is required")
	}
	freq, _ := strconv.Atoi(args["channel"])
	if freq == 0 {
		freq = 5180
	}
	width, _ := strconv.Atoi(args["width"])
	if width == 0 {
		width = 20
	}
	country := strings.ToUpper(strings.TrimSpace(args["country"]))
	if country == "" {
		country = "JP"
	}
	// Riff's "Live Capture" button leaves one-shot settings per dongle
	// (Riff then also gives the dongle back to Windows when it is done)
	fromRiff := false
	if f, w, c, ok := riffRequest(args["extcap-interface"]); ok {
		fromRiff = true
		log.Printf("settings from Riff: %d MHz, %d MHz wide, country %q", f, w, c)
		freq = f
		if w > 0 {
			width = w
		}
		if c != "" {
			country = c
		}
	}
	log.Printf("started from Riff: %v", fromRiff)
	ch, err := wifi.FromFreq(freq)
	if err != nil {
		return err
	}
	center, err := wifi.Center(ch, width)
	if err != nil {
		return fmt.Errorf("%s ch %d では %d MHz 幅は使えません: %v", ch.Band, ch.Num, width, err)
	}

	if err := checkDistro(); err != nil {
		return err
	}

	adapters, err := usbip.WifiAdapters()
	if err != nil {
		return err
	}
	var dev *usbip.Device
	wantVID, wantPID, want := parseIface(args["extcap-interface"])
	for i := range adapters {
		if want == "" || adapters[i].BusId == want {
			dev = &adapters[i]
			break
		}
	}
	if dev == nil && wantVID != "" {
		// The bus id changed (re-plugged, or the dongle switched to USB 3
		// mode and re-enumerated). Use the same model if it is unambiguous.
		var same []int
		for i := range adapters {
			if adapters[i].VID == wantVID && adapters[i].PID == wantPID {
				same = append(same, i)
			}
		}
		if len(same) == 1 {
			dev = &adapters[same[0]]
			log.Printf("USB %s gone; using same model at %s", want, dev.BusId)
		}
	}
	if dev == nil {
		if want != "" {
			return fmt.Errorf("USB %s のドングルが見つかりません。挿し直した場合は、Wireshark の「キャプチャ → インターフェースを更新」で一覧を更新してください", want)
		}
		return fmt.Errorf("対応している USB Wi-Fi ドングルが見つかりません。ドングルを挿してから再度キャプチャを開始してください")
	}
	log.Printf("adapter %s %s (%s) attached=%v", dev.BusId, dev.HWID(), dev.Name, dev.Attached())
	var opts []string
	if args["keep"] == "" {
		opts = append(opts, "release")
	}
	if args["fcserrors"] != "" {
		opts = append(opts, "fcsfail")
	}
	optStr := strings.Join(opts, ",")
	if optStr == "" {
		optStr = "-"
	}

	out, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot open fifo: %v", err)
	}
	defer out.Close()

	// Hand dongles between Windows and WSL one at a time, and keep the
	// Windows Wi-Fi driver off the dongle while WSL uses it (force bind):
	// the Realtek Windows driver can crash Windows when it is torn down
	// on attach, especially for two dongles at once.
	unlock, lerr := winx.NamedLock(usbip.AttachLock, 3*time.Minute)
	if lerr != nil {
		log.Printf("handover lock: %v", lerr)
		unlock = func() {}
	}
	unlockOnce := sync.OnceFunc(unlock)
	defer unlockOnce()
	if !dev.IsForced {
		// not registered for Riff yet: register it here only when no other
		// supported dongle runs on its Windows driver (stopping one of two
		// adapters is what crashes some drivers, e.g. Realtek rtwlanu6)
		var others []string
		for _, a := range adapters {
			if a.BusId != dev.BusId && !a.IsForced {
				others = append(others, a.BusId)
			}
		}
		if len(others) > 0 {
			return fmt.Errorf("USB %s のドングルは Riff にまだ登録されていません。ほかにも Windows で動いているドングルがあるため (USB %s)、安全のため自動では登録しません。Riff の「ツール ＞ 無線ドングル」で 1 本ずつ登録してください", dev.BusId, strings.Join(others, ", "))
		}
		log.Printf("registering USB %s for Riff (force bind, UAC)", dev.BusId)
		if err := usbip.ForceBind(*dev); err != nil {
			return fmt.Errorf("ドングルを Windows のドライバーから切り離せませんでした (管理者の確認が必要です): %v", err)
		}
		time.Sleep(2 * time.Second) // the device restarts on the stub driver
	}
	cmdArgs := []string{"-d", common.DistroName, "-u", "root", "--", common.CaptureScript,
		country, strconv.Itoa(freq), strconv.Itoa(width), strconv.Itoa(center), dev.BusId + "@" + dev.HWID(), optStr}
	if f := strings.TrimSpace(args["extcap-capture-filter"]); f != "" {
		cmdArgs = append(cmdArgs, strings.Fields(f)...)
	}
	cmd := winx.Hidden("wsl.exe", cmdArgs...)
	// wsl.exe stdout -> 256 MiB memory queue -> (TSFT rewrite) -> Wireshark.
	// The queue keeps tcpdump drained even when Wireshark stalls.
	var tsStats pcapts.Stats
	pr, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	q := pcapts.NewQueue(pr, 256<<20)
	tsDone := make(chan struct{})
	go func() {
		defer close(tsDone)
		var err error
		if args["hosttime"] != "" {
			_, err = io.Copy(out, q)
		} else {
			err = pcapts.Copy(out, q, &tsStats)
		}
		if err != nil {
			log.Printf("output: %v", err)
		}
	}()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start WSL: %v", err)
	}
	job, jerr := winx.KillOnCloseJob()
	if jerr == nil {
		_ = winx.AssignToJob(job, cmd.Process)
	} else {
		log.Printf("job object: %v", jerr)
	}

	var mu sync.Mutex
	var errLines []string
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			log.Printf("wsl: %s", line)
			mu.Lock()
			errLines = append(errLines, line)
			mu.Unlock()
		}
		close(done)
	}()

	// Keep an auto-attach loop running for the whole capture: adapters often
	// drop off the bus once while the driver uploads firmware, and the loop
	// hands them straight back to WSL.
	if !dev.Attached() {
		time.Sleep(1500 * time.Millisecond) // let the distro (and WSL VM) boot
	}
	aa, aerr := usbip.StartAutoAttach(*dev, log.Printf)
	if aerr != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("ドングルを WSL に接続できませんでした: %v", aerr)
	}
	if job != 0 {
		_ = winx.AssignToJob(job, aa.Process)
	}
	log.Printf("auto-attach running for %s", dev.BusId)
	unlockOnce() // attached: the next dongle may be handed over

	// Attach loops and the dongle's current bus id, so a failed start can
	// hand the dongle back to Windows (the Linux-side release watcher only
	// exists once tuning succeeded).
	var amu sync.Mutex
	attachers := []*os.Process{aa.Process}
	curBus := dev.BusId
	stopAttach := func() {
		amu.Lock()
		defer amu.Unlock()
		for _, p := range attachers {
			_ = p.Kill()
		}
		attachers = nil
	}
	defer stopAttach()

	// rtw89/rtw88 switch USB 2 dongles to USB 3 mode on first use; the dongle
	// then re-enumerates on Windows under a different bus id. Follow it.
	go func(cur usbip.Device) {
		serial := cur.Serial()
		for i := 0; i < 45; i++ {
			time.Sleep(time.Second)
			list, err := usbip.WifiAdapters()
			if err != nil {
				continue
			}
			for _, d := range list {
				if d.BusId == cur.BusId || d.HWID() != cur.HWID() || d.Serial() != serial || d.Attached() {
					continue
				}
				if stillThere(list, cur.BusId) {
					continue // another identical dongle, not ours
				}
				log.Printf("dongle re-enumerated: USB %s -> %s (USB 3 mode switch?)", cur.BusId, d.BusId)
				p, err := usbip.StartAutoAttach(d, log.Printf)
				if err != nil {
					log.Printf("follow attach: %v", err)
					return
				}
				if job != 0 {
					_ = winx.AssignToJob(job, p.Process)
				}
				amu.Lock()
				if attachers == nil { // capture already ended
					_ = p.Process.Kill()
					amu.Unlock()
					return
				}
				attachers = append(attachers, p.Process)
				curBus = d.BusId
				amu.Unlock()
				cur = d
			}
		}
	}(*dev)

	<-tsDone // must drain stdout before Wait
	log.Printf("frames %d, tsft-rewritten %d, re-anchors %d, queue high-water %d KiB, overflow %v",
		tsStats.Frames, tsStats.Rewritten, tsStats.Reanchors, q.HighWater>>10, q.Overflow)
	werr := cmd.Wait()
	<-done
	if werr != nil {
		if args["keep"] == "" {
			// Start failed (no driver, monitor mode refused, bad channel...):
			// stop re-attaching and give the dongle back to Windows.
			stopAttach()
			amu.Lock()
			bus := curBus
			amu.Unlock()
			if err := usbip.Detach(usbip.Device{BusId: bus}); err != nil {
				log.Printf("detach after failure: %v", err)
			} else {
				log.Printf("start failed: USB %s returned to Windows", bus)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		msg := []string{}
		for _, l := range errLines {
			if strings.Contains(l, "ERROR") || strings.Contains(strings.ToLower(l), "error") {
				msg = append(msg, l)
			}
		}
		if len(msg) == 0 {
			msg = errLines
		}
		if len(msg) > 8 {
			msg = msg[len(msg)-8:]
		}
		return fmt.Errorf("キャプチャが停止しました (%v)\n%s", werr, strings.Join(msg, "\n"))
	}
	return nil
}

func stillThere(list []usbip.Device, busid string) bool {
	for _, d := range list {
		if d.BusId == busid {
			return true
		}
	}
	return false
}

func checkDistro() error {
	out, err := winx.Run("wsl.exe", "-l", "-q")
	if err != nil {
		return fmt.Errorf("WSL が使えません。Riff の「ツール ＞ 無線ドングル」で状態を確認してください (%v)", err)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.EqualFold(strings.TrimSpace(l), common.DistroName) {
			return nil
		}
	}
	return fmt.Errorf("Riff の無線環境 (%s) がありません。Riff の「ツール ＞ 無線ドングル」でセットアップしてください", common.DistroName)
}

// riffRequest reads the settings Riff writes just before it starts
// Wireshark for this interface (Tools > Wireless Dongle > Live Capture):
// %LOCALAPPDATA%\Riff\capture-requests\<interface>.txt with lines
// "freq=5180", "width=20", "country=JP". The file is used once and must be
// recent, so captures started later from Wireshark itself use Wireshark's
// own interface options again.
func riffRequest(iface string) (freq, width int, country string, ok bool) {
	if iface == "" {
		return
	}
	p := filepath.Join(common.DataDir(), "capture-requests", iface+".txt")
	fi, err := os.Stat(p)
	if err != nil {
		return
	}
	defer os.Remove(p)
	if time.Since(fi.ModTime()) > 2*time.Minute {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(l), "=")
		if !found {
			continue
		}
		switch k {
		case "freq":
			freq, _ = strconv.Atoi(v)
		case "width":
			width, _ = strconv.Atoi(v)
		case "country":
			country = strings.ToUpper(strings.TrimSpace(v))
		}
	}
	return freq, width, country, freq > 0
}

// restoreAfter waits for the capture process to end, then gives the dongle
// back to its Windows driver (unless another capture, or Riff, is using it).
func restoreAfter(pidStr, busid string) {
	pid, _ := strconv.Atoi(pidStr)
	if pid <= 0 || busid == "" {
		return
	}
	winx.WaitProcess(pid)
	time.Sleep(3 * time.Second) // let the Linux side detach the dongle
	unlock, err := winx.NamedLock(usbip.AttachLock, 3*time.Minute)
	if err == nil {
		defer unlock()
	}
	list, err := usbip.List()
	if err != nil {
		log.Printf("restore %s: %v", busid, err)
		return
	}
	for _, d := range list {
		if d.BusId != busid {
			continue
		}
		if d.Attached() {
			log.Printf("restore %s: still attached (in use), keeping it", busid)
			return
		}
		if !d.IsForced {
			return
		}
		log.Printf("restore %s: unbind (UAC)", busid)
		if err := usbip.Unbind(busid); err != nil {
			log.Printf("restore %s: %v", busid, err)
		}
		return
	}
}

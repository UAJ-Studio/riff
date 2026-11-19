//go:build windows

// Riff-<version>-setup.exe: installer for Riff (Windows packet generator).
//
//	Riff-x.y.z-setup.exe               install / update
//	Riff-x.y.z-setup.exe --uninstall   remove Riff
//	--yes                              answer every question with yes
//
// Riff is installed per user (no administrator rights needed) in
// %LOCALAPPDATA%\Programs\Riff. Only installing usbipd-win (for USB Wi-Fi
// dongles) and giving dongles back to Windows need a UAC prompt.
package main

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
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

const (
	product      = "Riff"
	uninstallKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Riff`
	settingsKey  = `HKCU\Software\Riff`
	npcapURL     = "https://npcap.com/#download"
)

var stdin = bufio.NewReader(os.Stdin)

// cleanupOnExit: the install directory to delete after this process exits
// (an uninstaller started from it cannot delete its own exe).
var cleanupOnExit string

func installDir() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Riff")
}

// kept for Settings > Apps > Uninstall. No "setup"/"install" in the name:
// Windows would ask for administrator rights for such names (the manifest
// says asInvoker, but a short neutral name avoids any doubt)
func appExe() string { return filepath.Join(installDir(), "riff-maintenance.exe") }

func startMenuDir() string {
	return filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs`)
}

func desktopDir() string {
	out, err := winx.Run("powershell.exe", "-NoProfile", "-Command",
		"[Environment]::GetFolderPath('Desktop')")
	if d := strings.TrimSpace(out); err == nil && d != "" {
		return d
	}
	return filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
}

func main() {
	winx.UTF8Console()
	args := os.Args[1:]
	known := map[string]bool{"--uninstall": true, "--yes": true,
		"--elevated-usbipd": true, "--elevated-unbind": true, "--version": true}
	for _, a := range args {
		if !known[strings.ToLower(a)] && !strings.HasPrefix(a, "--busids=") {
			fmt.Printf("%s セットアップ v%s\n\n", product, Version)
			fmt.Println("使い方:")
			fmt.Println("  Riff-x.y.z-setup.exe               インストール / 更新")
			fmt.Println("  Riff-x.y.z-setup.exe --uninstall   アンインストール")
			fmt.Println("  --yes                              確認をすべて「はい」で進める")
			return
		}
	}
	if has(args, "--version") {
		fmt.Printf("%s v%s\n", product, Version)
		return
	}
	var err error
	switch {
	case has(args, "--elevated-usbipd"):
		if err = elevatedUsbipd(); err != nil {
			fmt.Println("エラー:", err)
			time.Sleep(5 * time.Second)
			os.Exit(1)
		}
		return
	case has(args, "--elevated-unbind"):
		elevatedUnbind(args)
		return
	case has(args, "--uninstall"):
		banner()
		err = uninstall(has(args, "--yes"))
	default:
		banner()
		err = install(has(args, "--yes"))
	}
	if err != nil {
		fmt.Println()
		fmt.Println("✖ エラー:", err)
	}
	if !has(args, "--yes") {
		fmt.Println()
		fmt.Print("Enter キーで閉じます...")
		stdin.ReadString('\n')
	}
	if cleanupOnExit != "" {
		scheduleSelfCleanup(cleanupOnExit)
	}
	if err != nil {
		os.Exit(1)
	}
}

func has(args []string, f string) bool {
	for _, a := range args {
		if strings.EqualFold(a, f) {
			return true
		}
	}
	return false
}

func banner() {
	fmt.Printf("=== %s セットアップ v%s ===\n", product, Version)
	fmt.Println("Windows 用のパケット/トラフィックジェネレーターです（Ostinato 1.3.0 からの派生）。")
	fmt.Println()
}

func step(format string, a ...any) { fmt.Printf("▶ "+format+"\n", a...) }
func ok(format string, a ...any)   { fmt.Printf("  ✔ "+format+"\n", a...) }
func info(format string, a ...any) { fmt.Printf("  - "+format+"\n", a...) }

func ask(q string, auto bool, def bool) bool {
	if auto {
		return true
	}
	hint := "[Y/n]"
	if !def {
		hint = "[y/N]"
	}
	fmt.Printf("  %s %s: ", q, hint)
	s, _ := stdin.ReadString('\n')
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return def
	}
	return s == "y" || s == "yes"
}

// ---- install ----

func install(auto bool) error {
	dir := installDir()

	step("Riff が起動していないか確認しています")
	if err := closeRiff(auto); err != nil {
		return err
	}
	ok("OK")

	step("Riff をインストールしています: %s", dir)
	if prev := installedVersion(); prev != "" {
		info("インストール済みの v%s を v%s に置き換えます（設定はそのまま残ります）", prev, Version)
	}
	if err := extractRiff(dir); err != nil {
		return err
	}
	ok("インストールしました")

	step("ショートカットを作成しています")
	exe := filepath.Join(dir, "riff.exe")
	if err := shortcut(filepath.Join(startMenuDir(), "Riff.lnk"), exe, dir); err != nil {
		info("スタートメニューのショートカットを作れませんでした: %v", err)
	} else {
		ok("スタートメニューに「Riff」を追加しました")
	}
	desk := filepath.Join(desktopDir(), "Riff.lnk")
	if fileExists(desk) || ask("デスクトップにもショートカットを作りますか?", auto, true) {
		if err := shortcut(desk, exe, dir); err != nil {
			info("デスクトップのショートカットを作れませんでした: %v", err)
		} else {
			ok("デスクトップに「Riff」を追加しました")
		}
	}

	step("「インストールされているアプリ」に登録しています")
	if err := registerApp(dir); err != nil {
		return err
	}
	ok("登録しました（削除はここから行えます）")

	step("Npcap（パケット送受信に必要）を確認しています")
	if npcapInstalled() {
		ok("インストール済み")
	} else {
		info("⚠ Npcap が入っていません。Npcap がないと Riff はパケットを送受信できません")
		info("Npcap は再配布できないため同梱していません。公式サイトから入れてください: %s", npcapURL)
		if ask("ダウンロードページを開きますか?", auto, true) {
			_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", npcapURL).Start()
		}
	}

	step("USB Wi-Fi ドングル用の準備（使わない場合は不要です）")
	if usbip.Exe() != "" {
		ok("usbipd-win はインストール済み")
	} else {
		info("USB Wi-Fi ドングルから無線パケットを送受信するには usbipd-win が必要です")
		if ask("usbipd-win（同梱版）をインストールしますか? 管理者の確認画面が出ます", auto, true) {
			self, _ := os.Executable()
			code, err := winx.RunElevated(self, "--elevated-usbipd", true)
			switch {
			case err != nil:
				info("スキップしました: %v", err)
			case code != 0 || usbip.Exe() == "":
				info("usbipd-win のインストールを確認できませんでした (exit %d)。あとで Riff の「ツール ＞ 無線ドングル」から確認できます", code)
			default:
				ok("usbipd-win をインストールしました")
			}
		} else {
			info("スキップしました。あとで Riff の「ツール ＞ 無線ドングル」から確認できます")
		}
	}
	if wslAvailable() {
		ok("WSL は使えます（Riff 専用の WSL 環境は、Riff の「ツール ＞ 無線ドングル」から入れられます）")
	} else {
		info("WSL が入っていません。ドングルを使うときは、管理者の PowerShell で「wsl --install --no-distribution」を実行して PC を再起動してください")
	}

	fmt.Println()
	fmt.Printf("✔ Riff v%s のインストールが完了しました\n", Version)
	fmt.Println("  ※ スタートメニューの「Riff」から起動できます")
	fmt.Println("  ※ 新しいバージョンは、新しいセットアップを実行するだけで更新できます")
	fmt.Println("  ※ 削除するには: 設定 →「インストールされているアプリ」→ Riff → アンインストール")
	if !auto && ask("Riff を起動しますか?", auto, true) {
		_ = winx.StartApp(exe)
	}
	return nil
}

// closeRiff asks Riff (and its agents) to close - its files cannot be
// replaced while it runs.
func closeRiff(auto bool) error {
	if !processRunning("riff.exe") {
		return nil
	}
	info("Riff が起動しています")
	if !ask("Riff を閉じて続けますか?（保存していないストリームは失われます）", auto, true) {
		return fmt.Errorf("中止しました")
	}
	// a normal close first: Riff then hands USB dongles back cleanly
	_, _ = winx.Run("taskkill.exe", "/im", "riff.exe")
	for i := 0; i < 60 && processRunning("riff.exe"); i++ {
		time.Sleep(time.Second)
	}
	if processRunning("riff.exe") {
		_, _ = winx.Run("taskkill.exe", "/f", "/im", "riff.exe")
	}
	_, _ = winx.Run("taskkill.exe", "/f", "/im", "riff-agent.exe")
	time.Sleep(time.Second)
	return nil
}

func processRunning(image string) bool {
	out, _ := winx.Run("tasklist.exe", "/fi", "imagename eq "+image, "/fo", "csv", "/nh")
	return strings.Contains(strings.ToLower(out), strings.ToLower(image))
}

// extractRiff unpacks the embedded Riff folder into a fresh directory next
// to dir and swaps it in, so a failed update leaves the old one working.
func extractRiff(dir string) error {
	f, err := payload.Open("payload/riff.zip")
	if err != nil {
		return err
	}
	defer f.Close()
	st, _ := f.Stat()
	ra, ok := f.(io.ReaderAt)
	if !ok {
		return fmt.Errorf("payload is not seekable")
	}
	zr, err := zip.NewReader(ra, st.Size())
	if err != nil {
		return err
	}
	tmp := dir + ".new"
	_ = os.RemoveAll(tmp)
	for _, zf := range zr.File {
		dst := filepath.Join(tmp, filepath.FromSlash(zf.Name))
		if !strings.HasPrefix(dst, tmp+string(os.PathSeparator)) {
			continue // no paths outside the target
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		r, err := zf.Open()
		if err != nil {
			return err
		}
		w, err := os.Create(dst)
		if err != nil {
			r.Close()
			return err
		}
		_, err = io.Copy(w, r)
		r.Close()
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	// keep a portable riff.ini / riff-agent.ini the user may have created
	for _, ini := range []string{"riff.ini", "riff-agent.ini"} {
		if fileExists(filepath.Join(dir, ini)) {
			_ = copyFile(filepath.Join(dir, ini), filepath.Join(tmp, ini))
		}
	}
	old := dir + ".old"
	_ = os.RemoveAll(old)
	if fileExists(dir) {
		if err := os.Rename(dir, old); err != nil {
			os.RemoveAll(tmp)
			return fmt.Errorf("古いファイルを置き換えられません（Riff がまだ動いていませんか?）: %v", err)
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.Rename(old, dir)
		return err
	}
	_ = os.RemoveAll(old)
	return writeState(dir)
}

type state struct {
	Version string `json:"version"`
}

func writeState(dir string) error {
	b, _ := json.Marshal(state{Version: Version})
	return os.WriteFile(filepath.Join(dir, "install.json"), b, 0o644)
}

func installedVersion() string {
	b, err := os.ReadFile(filepath.Join(installDir(), "install.json"))
	if err != nil {
		return ""
	}
	var s state
	_ = json.Unmarshal(b, &s)
	return s.Version
}

// shortcut writes a .lnk through the Windows shell (WScript.Shell).
func shortcut(lnk, target, workDir string) error {
	ps := fmt.Sprintf(`$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%s');`+
		`$s.TargetPath='%s';$s.WorkingDirectory='%s';$s.IconLocation='%s,0';`+
		`$s.Description='Riff - packet generator';$s.Save()`,
		psq(lnk), psq(target), psq(workDir), psq(target))
	out, err := winx.Run("powershell.exe", "-NoProfile", "-Command", ps)
	if err != nil {
		return fmt.Errorf("%v %s", err, strings.TrimSpace(out))
	}
	return nil
}

func psq(s string) string { return strings.ReplaceAll(s, "'", "''") }

func registerApp(dir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dst := appExe()
	if !strings.EqualFold(filepath.Clean(self), filepath.Clean(dst)) {
		if err := copyFile(self, dst); err != nil {
			return fmt.Errorf("cannot copy %s: %v", dst, err)
		}
	}
	vals := []struct{ name, typ, data string }{
		{"DisplayName", "REG_SZ", product},
		{"DisplayVersion", "REG_SZ", Version},
		{"Publisher", "REG_SZ", "Riff"},
		{"Comments", "REG_SZ", "Packet/traffic generator for Windows (derived from Ostinato)"},
		{"InstallLocation", "REG_SZ", dir},
		{"DisplayIcon", "REG_SZ", filepath.Join(dir, "riff.exe")},
		{"UninstallString", "REG_SZ", `"` + dst + `" --uninstall`},
		{"InstallDate", "REG_SZ", time.Now().Format("20060102")},
		{"EstimatedSize", "REG_DWORD", fmt.Sprint(dirSizeKB(dir))},
		{"NoModify", "REG_DWORD", "1"},
		{"NoRepair", "REG_DWORD", "1"},
	}
	for _, v := range vals {
		if _, err := winx.Run("reg.exe", "add", uninstallKey, "/v", v.name,
			"/t", v.typ, "/d", v.data, "/f"); err != nil {
			return err
		}
	}
	return nil
}

func npcapInstalled() bool {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	return fileExists(filepath.Join(sys, "Npcap", "wpcap.dll")) ||
		fileExists(filepath.Join(sys, "wpcap.dll"))
}

func wslAvailable() bool {
	_, err := winx.Run("wsl.exe", "--status")
	return err == nil
}

// ---- uninstall ----

func uninstall(auto bool) error {
	dir := installDir()

	step("Riff が起動していないか確認しています")
	if err := closeRiff(auto); err != nil {
		return err
	}
	ok("OK")

	// dongles registered for Riff stay off their Windows driver until
	// given back
	if ids := riffDongles(dir); len(ids) > 0 {
		step("Riff 専用に登録した USB Wi-Fi ドングル: %s", strings.Join(ids, ", "))
		if ask("Windows に戻しますか? 管理者の確認画面が出ます", auto, true) {
			self, _ := os.Executable()
			if _, err := winx.RunElevated(self, "--elevated-unbind --busids="+strings.Join(ids, ","), false); err != nil {
				info("スキップしました: %v", err)
			} else {
				ok("Windows に戻しました")
			}
		}
	}

	if distroExists() {
		step("Riff 専用の WSL 環境（%s）", common.DistroName)
		if ask("削除しますか?", auto, true) {
			if _, err := winx.Run("wsl.exe", "--unregister", common.DistroName); err != nil {
				info("削除できませんでした: %v", err)
			} else {
				ok("削除しました")
			}
		}
	}

	step("Riff を削除しています")
	_ = os.Remove(filepath.Join(common.ExtcapDir(), common.ExtcapName))
	_ = os.Remove(filepath.Join(startMenuDir(), "Riff.lnk"))
	_ = os.Remove(filepath.Join(desktopDir(), "Riff.lnk"))
	_, _ = winx.Run("reg.exe", "delete", uninstallKey, "/f")
	_ = os.RemoveAll(dir)
	if fileExists(dir) {
		// we run from dir (Settings > Installed apps > Uninstall)
		cleanupOnExit = dir
	}
	ok("削除しました")

	if ask("Riff の設定（ウィンドウ配置、登録済みドングルの記録など）も削除しますか?", auto, false) {
		_, _ = winx.Run("reg.exe", "delete", settingsKey, "/f")
		_ = os.RemoveAll(common.DataDir())
		ok("設定を削除しました")
	}
	fmt.Println()
	fmt.Println("✔ アンインストール完了（Npcap と usbipd-win は残しています。不要なら「インストールされているアプリ」から削除してください）")
	return nil
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

// ---- elevated parts ----

func elevatedUsbipd() error {
	if usbip.Exe() != "" {
		return nil
	}
	fmt.Println("usbipd-win をインストールしています...")
	msi := filepath.Join(os.TempDir(), "riff-usbipd.msi")
	if err := extract("usbipd.msi", msi); err != nil {
		return err
	}
	defer os.Remove(msi)
	if out, err := winx.Run("msiexec.exe", "/i", msi, "/qn", "/norestart"); err != nil {
		return fmt.Errorf("usbipd-win のインストールに失敗: %v %s", err, out)
	}
	for i := 0; i < 20 && usbip.Exe() == ""; i++ {
		time.Sleep(500 * time.Millisecond)
	}
	if usbip.Exe() == "" {
		return fmt.Errorf("usbipd.exe が見つかりません")
	}
	return nil
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

// ---- helpers ----

// scheduleSelfCleanup deletes dir after this process (running from it) exits.
func scheduleSelfCleanup(dir string) {
	script := fmt.Sprintf(`for /l %%i in (1,1,30) do @(ping -n 3 127.0.0.1 >nul & rmdir /s /q "%s" 2>nul & if not exist "%s" exit /b 0)`,
		dir, dir)
	_ = winx.StartCmdDetached(script)
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}

func dirSizeKB(dir string) int64 {
	var n int64
	_ = filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			n += fi.Size()
		}
		return nil
	})
	return n / 1024
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

//go:build windows

// Package winx contains the few Win32 helpers we need without pulling in
// external modules.
package winx

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procSetConsoleOutputCP       = kernel32.NewProc("SetConsoleOutputCP")
	procWaitForSingleObject      = kernel32.NewProc("WaitForSingleObject")
	procGetExitCodeProcess       = kernel32.NewProc("GetExitCodeProcess")
	procShellExecuteExW          = shell32.NewProc("ShellExecuteExW")
	procIsUserAnAdmin            = shell32.NewProc("IsUserAnAdmin")
	procCreateMutexW             = kernel32.NewProc("CreateMutexW")
	procReleaseMutex             = kernel32.NewProc("ReleaseMutex")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
)

const createNoWindow = 0x08000000

// UTF8Console makes Japanese text print correctly in a console window.
func UTF8Console() { procSetConsoleOutputCP.Call(65001) }

// IsAdmin reports whether the current process is elevated.
func IsAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

// Hidden returns an exec.Cmd that does not pop up a console window and gets
// UTF-8 output from wsl.exe.
func Hidden(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	c.Env = append(os.Environ(), "WSL_UTF8=1")
	return c
}

// Run runs a hidden command and returns trimmed combined output.
func Run(name string, args ...string) (string, error) {
	out, err := Hidden(name, args...).CombinedOutput()
	s := strings.TrimSpace(strings.ReplaceAll(string(out), "\x00", ""))
	if err != nil {
		return s, fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, s)
	}
	return s, nil
}

// KillOnCloseJob creates a job object whose processes die when this process
// exits (Wireshark kills the extcap with TerminateProcess on stop).
func KillOnCloseJob() (syscall.Handle, error) {
	h, _, err := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return 0, err
	}
	// JOBOBJECT_EXTENDED_LIMIT_INFORMATION, only LimitFlags matters.
	type basic struct {
		PerProcessUserTimeLimit int64
		PerJobUserTimeLimit     int64
		LimitFlags              uint32
		MinimumWorkingSetSize   uintptr
		MaximumWorkingSetSize   uintptr
		ActiveProcessLimit      uint32
		Affinity                uintptr
		PriorityClass           uint32
		SchedulingClass         uint32
	}
	type ioCounters struct{ a, b, c, d, e, f uint64 }
	type extended struct {
		Basic                 basic
		Io                    ioCounters
		ProcessMemoryLimit    uintptr
		JobMemoryLimit        uintptr
		PeakProcessMemoryUsed uintptr
		PeakJobMemoryUsed     uintptr
	}
	var info extended
	info.Basic.LimitFlags = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	r, _, err := procSetInformationJobObject.Call(h, 9, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r == 0 {
		return 0, err
	}
	return syscall.Handle(h), nil
}

// AssignToJob puts a started process into the job.
func AssignToJob(job syscall.Handle, p *os.Process) error {
	const access = 0x0001 | 0x0100 // PROCESS_TERMINATE | PROCESS_SET_QUOTA
	ph, err := syscall.OpenProcess(access, false, uint32(p.Pid))
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(ph)
	r, _, err := procAssignProcessToJobObject.Call(uintptr(job), uintptr(ph))
	if r == 0 {
		return err
	}
	return nil
}

// StartCmdDetached runs `cmd.exe /c <script>` hidden, passing the command
// line verbatim (Go's argument quoting uses \" which cmd.exe does not
// understand) and outside our job object if allowed, so it survives our
// exit even when we were started by Settings' uninstall in a job.
func StartCmdDetached(script string) error {
	const breakaway = 0x01000000 // CREATE_BREAKAWAY_FROM_JOB
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	start := func(flags uint32) error {
		c := exec.Command(cmdExe)
		c.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CmdLine:       `"` + cmdExe + `" /c ` + script,
			CreationFlags: createNoWindow | flags,
		}
		if err := c.Start(); err != nil {
			return err
		}
		return c.Process.Release()
	}
	if err := start(breakaway); err == nil {
		return nil
	}
	return start(0) // the job may forbid breakaway
}

// RunElevated starts exe with args through UAC ("runas"), waits for it and
// returns its exit code.
func RunElevated(exe string, args string, show bool) (int, error) {
	type shellExecuteInfo struct {
		cbSize       uint32
		fMask        uint32
		hwnd         uintptr
		lpVerb       *uint16
		lpFile       *uint16
		lpParameters *uint16
		lpDirectory  *uint16
		nShow        int32
		hInstApp     uintptr
		lpIDList     uintptr
		lpClass      *uint16
		hkeyClass    uintptr
		dwHotKey     uint32
		hIcon        uintptr
		hProcess     syscall.Handle
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(args)
	var sei shellExecuteInfo
	sei.cbSize = uint32(unsafe.Sizeof(sei))
	sei.fMask = 0x00000040 // SEE_MASK_NOCLOSEPROCESS
	sei.lpVerb = verb
	sei.lpFile = file
	sei.lpParameters = params
	if show {
		sei.nShow = 1
	}
	r, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 {
		return -1, fmt.Errorf("elevation was cancelled or failed: %v", err)
	}
	defer syscall.CloseHandle(sei.hProcess)
	procWaitForSingleObject.Call(uintptr(sei.hProcess), 0xFFFFFFFF)
	var code uint32
	procGetExitCodeProcess.Call(uintptr(sei.hProcess), uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}

// NamedLock waits up to timeout for a named mutex shared by every Riff
// process in this session (Riff itself and each extcap instance), so that
// USB dongles are handed between Windows and WSL one at a time. Some Wi-Fi
// drivers crash Windows when two adapters are torn down concurrently.
// A Windows mutex belongs to the OS thread that acquired it and only that
// thread can release it, so the calling goroutine stays on its thread until
// the returned unlock function runs (call it from the same goroutine).
func NamedLock(name string, timeout time.Duration) (func(), error) {
	runtime.LockOSThread()
	n, _ := syscall.UTF16PtrFromString(name)
	h, _, err := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(n)))
	if h == 0 {
		runtime.UnlockOSThread()
		return nil, err
	}
	r, _, _ := procWaitForSingleObject.Call(h, uintptr(timeout.Milliseconds()))
	if r != 0 && r != 0x80 { // WAIT_OBJECT_0 / WAIT_ABANDONED
		syscall.CloseHandle(syscall.Handle(h))
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("timed out waiting for %s", name)
	}
	return func() {
		procReleaseMutex.Call(h)
		syscall.CloseHandle(syscall.Handle(h))
		runtime.UnlockOSThread()
	}, nil
}

// WaitProcess blocks until the process with the given id has exited.
func WaitProcess(pid int) {
	const synchronize = 0x00100000
	h, _, _ := procOpenProcess.Call(synchronize, 0, uintptr(pid))
	if h == 0 {
		return
	}
	procWaitForSingleObject.Call(h, 0xFFFFFFFF)
	syscall.CloseHandle(syscall.Handle(h))
}

// StartDetached starts exe hidden and outside our kill-on-close job, so it
// keeps running after Wireshark terminates us.
func StartDetached(exe string, args ...string) error {
	const breakaway = 0x01000000 // CREATE_BREAKAWAY_FROM_JOB
	start := func(flags uint32) error {
		c := exec.Command(exe, args...)
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
			CreationFlags: createNoWindow | flags}
		if err := c.Start(); err != nil {
			return err
		}
		return c.Process.Release()
	}
	if err := start(breakaway); err == nil {
		return nil
	}
	return start(0)
}

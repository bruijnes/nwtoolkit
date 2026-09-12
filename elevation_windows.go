//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var shell32 = syscall.NewLazyDLL("shell32.dll")

// isElevated reports whether the process runs with elevated rights. The built-in
// pktmon only works as Administrator, so this saves a pointless attempt and yields
// an understandable message instead of a timeout.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// relaunchAsAdmin starts a fresh copy of this executable with the given arguments
// through the "runas" verb, which raises the standard Windows UAC prompt. This is
// the supported way to elevate: it asks the user for consent, it does not bypass
// anything. On success the caller should exit, leaving the elevated copy running.
// If the user dismisses the UAC prompt an error is returned and nothing changes.
func relaunchAsAdmin(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)

	var params *uint16
	if line := commandLine(args); line != "" {
		params, _ = syscall.UTF16PtrFromString(line)
	}
	var dir *uint16
	if cwd, e := os.Getwd(); e == nil {
		dir, _ = syscall.UTF16PtrFromString(cwd)
	}

	const swShowNormal = 1
	r, _, _ := shell32.NewProc("ShellExecuteW").Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(dir)),
		uintptr(swShowNormal),
	)
	// ShellExecuteW returns a value greater than 32 on success. 5 (access denied) is
	// what a dismissed UAC prompt yields.
	if r <= 32 {
		if r == 5 {
			return errors.New("the elevation prompt was dismissed")
		}
		return fmt.Errorf("ShellExecuteW failed (code %d)", r)
	}
	return nil
}

// commandLine quotes arguments that contain spaces or quotes so the relaunched
// process receives them intact.
func commandLine(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if a == "" || strings.ContainsAny(a, " \t\"") {
			b.WriteByte('"')
			b.WriteString(strings.ReplaceAll(a, `"`, `\"`))
			b.WriteByte('"')
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}

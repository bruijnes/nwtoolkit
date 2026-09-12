//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")

func enableVT() bool {
	getMode := kernel32.NewProc("GetConsoleMode")
	setMode := kernel32.NewProc("SetConsoleMode")
	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	if r, _, _ := getMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return false
	}
	const enableVTP = 0x0004
	r, _, _ := setMode.Call(uintptr(h), uintptr(mode|enableVTP))
	return r != 0
}

// launchedFromExplorer decides whether the exe was double-clicked, giving it its own
// console with one process, versus started from an existing terminal, where two or
// more processes share the console.
func launchedFromExplorer() bool {
	proc := kernel32.NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return false
	}
	var ids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return n == 1
}

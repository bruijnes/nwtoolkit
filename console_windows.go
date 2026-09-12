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

// launchedFromExplorer bepaalt of de exe is dubbelgeklikt (eigen console, 1 proces)
// versus gestart vanuit een bestaande terminal (>=2 processen delen de console).
func launchedFromExplorer() bool {
	proc := kernel32.NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return false
	}
	var ids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return n == 1
}

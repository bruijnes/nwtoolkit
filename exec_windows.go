//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// createNoWindow suppresses the console window Windows would otherwise open for a
// child process. Without it a black console flashes up whenever the GUI starts
// pktmon or rundll32.
const createNoWindow = 0x08000000

// hidden builds a command that opens no window of its own.
func hidden(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return c
}

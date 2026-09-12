//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// createNoWindow onderdrukt het console-venster dat Windows anders opent voor een
// child-proces. Zonder dit flitst er een zwarte DOS-box op zodra de GUI pktmon of
// rundll32 start.
const createNoWindow = 0x08000000

// hidden maakt een commando dat geen eigen venster opent.
func hidden(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return c
}

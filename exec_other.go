//go:build !windows

package main

import "os/exec"

// hidden is op niet-Windows hetzelfde als exec.Command; er is geen console-venster
// dat onderdrukt moet worden.
func hidden(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

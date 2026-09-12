//go:build !windows

package main

import "os/exec"

// hidden is the same as exec.Command on non-Windows; there is no console window to
// suppress.
func hidden(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

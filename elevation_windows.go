//go:build windows

package main

import "golang.org/x/sys/windows"

// isElevated reports whether the process runs with elevated rights. The built-in
// pktmon only works as Administrator, so this saves a pointless attempt and yields
// an understandable message instead of a timeout.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

//go:build !windows

package main

import "errors"

// isElevated is only meaningful on Windows, which has UAC. Elsewhere there is no
// prompt-driven elevation, so report elevated and let the raw-socket calls surface
// a permission error themselves if the user is not root.
func isElevated() bool { return true }

// relaunchAsAdmin has no equivalent outside Windows.
func relaunchAsAdmin(args []string) error {
	return errors.New("restarting as administrator is only supported on Windows")
}

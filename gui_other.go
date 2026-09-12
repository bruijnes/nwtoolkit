//go:build !windows

package main

import "fmt"

// The native GUI only exists on Windows; elsewhere the tool falls back to the web UI.
func runGUI() {
	fmt.Println("The native window interface is only available on Windows; start the web UI instead.")
	cmdWeb("127.0.0.1:8733")
}

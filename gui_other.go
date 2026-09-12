//go:build !windows

package main

import "fmt"

// The native window UI only exists on Windows. Elsewhere there is nothing to open,
// so point the user at the command line and drop into the interactive menu.
func runGUI() {
	fmt.Println("The native window UI is only available on Windows. Use the command line, or the menu below.")
	interactiveMenu()
}

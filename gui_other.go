//go:build !windows

package main

import "fmt"

// De native GUI bestaat alleen op Windows; elders valt de tool terug op de web-UI.
func runGUI() {
	fmt.Println("De native vensterinterface is alleen op Windows beschikbaar; start in plaats daarvan de web-UI.")
	cmdWeb("127.0.0.1:8733")
}

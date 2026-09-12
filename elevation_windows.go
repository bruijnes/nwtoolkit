//go:build windows

package main

import "golang.org/x/sys/windows"

// isElevated zegt of het proces met verhoogde rechten draait. De ingebouwde
// pktmon werkt alleen als Administrator, dus dit scheelt een nutteloze poging
// en levert een begrijpelijke melding in plaats van een timeout.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

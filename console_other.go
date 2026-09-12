//go:build !windows

package main

import "os"

func enableVT() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func launchedFromExplorer() bool { return false }

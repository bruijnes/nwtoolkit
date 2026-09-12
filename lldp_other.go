//go:build !linux && !windows

package main

import (
	"fmt"
	"time"
)

// On other platforms, such as macOS, layer-2 capture is not implemented.
func openLLDP(hint string) (capturer, []string, error) {
	return nil, nil, fmt.Errorf("LLDP capture is not supported on this platform (Linux and Windows only)")
}

var _ = time.Second

func tryPktmon(o lldpOpts) error { return errPktmonUnsupported }

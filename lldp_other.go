//go:build !linux && !windows

package main

import (
	"fmt"
	"time"
)

// Op andere platforms (bijv. macOS) is L2-capture niet geïmplementeerd.
func openLLDP(hint string) (capturer, []string, error) {
	return nil, nil, fmt.Errorf("LLDP-capture wordt op dit platform niet ondersteund (alleen Linux en Windows)")
}

var _ = time.Second

func tryPktmon(o lldpOpts) error { return errPktmonUnsupported }

func pktmonCollect(wait time.Duration) (map[string]*lldpNeighbor, error) {
	return nil, errPktmonUnsupported
}

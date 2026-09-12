//go:build windows

package main

import (
	"errors"
	"time"
)

// lldpOnce captures LLDP neighbours until the first one is seen or wait elapses.
// Used by the native Windows GUI.
func lldpOnce(hint string, wait time.Duration) ([]*lldpNeighbor, string, error) {
	cap, _, err := openLLDP(hint)
	if err != nil {
		// No live capture? Fall back to the built-in pktmon (Windows, Administrator).
		if errors.Is(err, errNoLiveCapture) {
			nbs, perr := pktmonCollect(wait)
			if perr == nil {
				return sortedNeighbors(nbs), "pktmon", nil
			}
			if errors.Is(perr, errPktmonUnsupported) {
				return nil, "", err
			}
			return nil, "", perr
		}
		return nil, "", err
	}
	defer cap.close()
	neighbors := map[string]*lldpNeighbor{}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		frame, err := cap.next(1 * time.Second)
		if err != nil {
			continue
		}
		if nb, ok := parseLLDP(frame); ok {
			nb.localIf = cap.device()
			neighbors[nb.key()] = nb
		}
		if len(neighbors) > 0 && time.Now().Add(2*time.Second).After(deadline) {
			break
		}
	}
	return sortedNeighbors(neighbors), cap.device(), nil
}

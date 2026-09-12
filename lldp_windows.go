//go:build windows

package main

// Windows has no built-in API for live layer-2 capture: pcap-style access requires
// an external driver (Npcap/WinPcap). This tool does not want to depend on one, so
// the Windows route always goes through the built-in Packet Monitor (pktmon).
// openLLDP reports that here with errNoLiveCapture; the caller then falls back to
// pktmonCollect, which works with what Windows ships.

func openLLDP(hint string) (capturer, []string, error) {
	return nil, nil, errNoLiveCapture
}

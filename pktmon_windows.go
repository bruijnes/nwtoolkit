//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Packet Monitor is the only layer-2 capture Windows ships with. It works in batches
// rather than as a live stream: start a capture to an ETL file, let traffic happen,
// stop, convert to pcapng, then parse. Both the LLDP and the DHCP probe need exactly
// that sequence, so it lives here once.

// pktmonSettleDelay gives the capture a moment to actually start before the caller
// transmits. Without it the outgoing frame can be sent before pktmon is recording.
const pktmonSettleDelay = 150 * time.Millisecond

// pktmonCapture runs one Packet Monitor session and returns the raw pcapng bytes.
//
// during runs while the capture is recording and reports whether the recorded frames
// are still wanted. Returning false ends the session without the pcapng round trip,
// which the DHCP probe uses when an answer already arrived over its socket; in that
// case both return values are nil.
//
// Requires Administrator: without it the start fails and the error says so.
func pktmonCapture(name string, during func() bool) ([]byte, error) {
	if _, err := exec.LookPath("pktmon"); err != nil {
		return nil, errPktmonUnsupported
	}
	dir := os.TempDir()
	etl := filepath.Join(dir, "nwtoolkit_"+name+".etl")
	png := filepath.Join(dir, "nwtoolkit_"+name+".pcapng")
	os.Remove(etl)
	os.Remove(png)

	hidden("pktmon", "stop").Run() // clear a session left behind by an earlier run
	if out, err := hidden("pktmon", "start", "--capture", "--pkt-size", "0", "--file-name", etl).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pktmon start failed (Administrator required?): %s", trimOut(out))
	}
	defer func() {
		hidden("pktmon", "stop").Run()
		os.Remove(etl)
		os.Remove(png)
	}()

	if !during() {
		return nil, nil
	}
	hidden("pktmon", "stop").Run()

	if out, err := hidden("pktmon", "pcapng", etl, "-o", png).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pktmon pcapng conversion failed: %s", trimOut(out))
	}
	data, err := os.ReadFile(png)
	if err != nil {
		return nil, fmt.Errorf("reading pcapng: %w", err)
	}
	return data, nil
}

// trimOut shortens command output so a failure message stays readable.
func trimOut(b []byte) string {
	s := string(b)
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

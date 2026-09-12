//go:build windows

package main

import (
	"fmt"
	"time"
)

// pktmonCollect captures LLDP frames with the built-in Windows Packet Monitor.
// It simply records for the whole wait period, because LLDP is announced
// periodically and there is nothing to send ourselves.
func pktmonCollect(wait time.Duration) (map[string]*lldpNeighbor, error) {
	if wait <= 0 {
		wait = 35 * time.Second
	}
	data, err := pktmonCapture("lldp", func() bool {
		time.Sleep(wait)
		return true
	})
	if err != nil {
		return nil, err
	}
	neighbors := map[string]*lldpNeighbor{}
	for _, frame := range parsePcapng(data) {
		if nb, ok := parseLLDP(frame); ok {
			nb.localIf = "pktmon"
			neighbors[nb.key()] = nb
		}
	}
	return neighbors, nil
}

// tryPktmon is the console variant: capture and display, looping with -m.
func tryPktmon(o lldpOpts) error {
	fmt.Printf("%s  using the built-in pktmon (Administrator required).\n", col(cBold, "nwtoolkit"))
	for {
		fmt.Printf("%s\n", col(cGrey, fmt.Sprintf("Capturing for %s…", o.wait)))
		neighbors, err := pktmonCollect(o.wait)
		if err != nil {
			return err
		}
		if len(neighbors) == 0 {
			fmt.Println(col(cYellow, "No LLDP frames captured."))
			fmt.Println(col(cGrey, "LLDP may be disabled on the switch, or it is an unmanaged switch."))
		} else {
			if o.monitor {
				fmt.Print(clrScr)
				fmt.Printf("%s  LLDP monitor (pktmon)   %d neighbour(s)   Ctrl+C to stop\n", col(cBold, "nwtoolkit"), len(neighbors))
			}
			for _, n := range sortedNeighbors(neighbors) {
				fmt.Println()
				n.printBlock()
			}
		}
		if !o.monitor {
			return nil
		}
	}
}

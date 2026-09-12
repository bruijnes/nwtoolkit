//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// pktmonCollect vangt LLDP-frames met de ingebouwde Windows Packet Monitor (pktmon).
// Volledig op boordmiddelen — geen externe driver — maar vereist Administrator. Batch-gewijs:
// start capture, wacht, stop, converteer naar pcapng, parse.
func pktmonCollect(wait time.Duration) (map[string]*lldpNeighbor, error) {
	if _, err := exec.LookPath("pktmon"); err != nil {
		return nil, errPktmonUnsupported
	}
	if wait <= 0 {
		wait = 35 * time.Second
	}
	dir := os.TempDir()
	etl := filepath.Join(dir, "nwtoolkit_lldp.etl")
	png := filepath.Join(dir, "nwtoolkit_lldp.pcapng")
	os.Remove(etl)
	os.Remove(png)

	hidden("pktmon", "stop").Run() // eventuele vorige sessie opruimen

	start := hidden("pktmon", "start", "--capture", "--pkt-size", "0", "--file-name", etl)
	if out, err := start.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pktmon start faalde (Administrator nodig?): %s", trimOut(out))
	}

	time.Sleep(wait)
	hidden("pktmon", "stop").Run()

	conv := hidden("pktmon", "pcapng", etl, "-o", png)
	if out, err := conv.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pktmon pcapng-conversie faalde: %s", trimOut(out))
	}

	data, err := os.ReadFile(png)
	if err != nil {
		return nil, fmt.Errorf("pcapng lezen: %w", err)
	}
	neighbors := map[string]*lldpNeighbor{}
	for _, frame := range parsePcapng(data) {
		if nb, ok := parseLLDP(frame); ok {
			nb.localIf = "pktmon"
			neighbors[nb.key()] = nb
		}
	}
	os.Remove(etl)
	os.Remove(png)
	return neighbors, nil
}

func trimOut(b []byte) string {
	s := string(b)
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// tryPktmon is de console-variant: opnemen en tonen (met -m in een lus).
func tryPktmon(o lldpOpts) error {
	fmt.Printf("%s  gebruikt de ingebouwde pktmon (Administrator nodig).\n", col(cBold, "nwtoolkit"))
	for {
		fmt.Printf("%s\n", col(cGrey, fmt.Sprintf("Opnemen gedurende %s…", o.wait)))
		neighbors, err := pktmonCollect(o.wait)
		if err != nil {
			return err
		}
		if len(neighbors) == 0 {
			fmt.Println(col(cYellow, "Geen LLDP-frames opgevangen."))
			fmt.Println(col(cGrey, "Mogelijk staat LLDP uit op de switch, of het is een niet-beheerde switch."))
		} else {
			if o.monitor {
				fmt.Print(clrScr)
				fmt.Printf("%s  LLDP-monitor (pktmon)   %d buur/buren   Ctrl+C = stoppen\n", col(cBold, "nwtoolkit"), len(neighbors))
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

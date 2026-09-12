//go:build windows

package main

// Windows heeft geen ingebouwde API voor live laag-2-capture: pcap-achtige toegang
// vereist een externe driver (Npcap/WinPcap). Die wil deze tool niet nodig hebben,
// dus de Windows-route loopt altijd via de ingebouwde Packet Monitor (pktmon).
// openLLDP meldt dat hier met errNoLiveCapture; de aanroeper valt dan terug op
// pktmonCollect, dat wél met boordmiddelen werkt.

func openLLDP(hint string) (capturer, []string, error) {
	return nil, nil, errNoLiveCapture
}

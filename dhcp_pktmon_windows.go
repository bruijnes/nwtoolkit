//go:build windows

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// dhcpProbePktmon verstuurt een broadcast DISCOVER via een gewone UDP-socket en
// vangt de OFFER/ACK op met de ingebouwde Windows Packet Monitor (pktmon) — net als
// de LLDP-capture, dus volledig met boordmiddelen. De OFFER komt op poort 68 binnen (die de
// DHCP-Clientservice bezit), maar pktmon ziet het frame op de draad. Vereist
// Administrator. De responstijd komt uit de pcapng-tijdstempels.
func dhcpProbePktmon(o dhcpOpts) (dhcpResult, error) {
	if _, err := exec.LookPath("pktmon"); err != nil {
		return dhcpResult{}, errPktmonUnsupported
	}

	mac := macForIP(o.srcIP)
	if mac == nil {
		var e error
		if _, mac, e = localAddrFor("", o.iface); e != nil {
			return dhcpResult{}, fmt.Errorf("lokaal adres bepalen: %w", e)
		}
	}
	bindIP := net.IPv4zero
	if o.srcIP != nil {
		bindIP = o.srcIP
	}
	where := "pktmon"
	if o.srcIP != nil {
		where = "pktmon via " + o.srcIP.String()
	}

	var xidb [4]byte
	rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])
	packet := buildDHCP(dhcpDiscover, xid, mac, net.IPv4zero, true)

	dir := os.TempDir()
	etl := filepath.Join(dir, "nwtoolkit_dhcp.etl")
	png := filepath.Join(dir, "nwtoolkit_dhcp.pcapng")
	os.Remove(etl)
	os.Remove(png)

	hidden("pktmon", "stop").Run()
	start := hidden("pktmon", "start", "--capture", "--pkt-size", "0", "--file-name", etl)
	if out, err := start.CombinedOutput(); err != nil {
		return dhcpResult{}, fmt.Errorf("pktmon start faalde (Administrator nodig?): %s", trimOut(out))
	}
	// stop-capture wordt sowieso uitgevoerd voordat we parsen
	defer hidden("pktmon", "stop").Run()

	// even wachten zodat de capture zeker loopt voordat we zenden
	time.Sleep(150 * time.Millisecond)

	conn, err := dhcpListen(&net.UDPAddr{IP: bindIP, Port: 68}, true)
	if err != nil {
		return dhcpResult{}, fmt.Errorf("kan poort 68 niet openen (%v)", err)
	}
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	t0 := time.Now()
	if _, err := conn.WriteToUDP(packet, dst); err != nil {
		conn.Close()
		return dhcpResult{}, fmt.Errorf("verzenden: %w", err)
	}
	// de socket mag ook meeluisteren — soms komt de OFFER er tóch doorheen
	gotFromSock := make(chan dhcpResult, 1)
	go func() {
		conn.SetReadDeadline(time.Now().Add(o.timeout))
		buf := make([]byte, 1500)
		for {
			n, _, e := conn.ReadFromUDP(buf)
			if e != nil {
				return
			}
			mt, yi, sid, ok := parseDHCP(buf[:n])
			if ok && binary.BigEndian.Uint32(buf[4:8]) == xid && (mt == dhcpOffer || mt == dhcpAck) {
				gotFromSock <- dhcpResult{rtt: time.Since(t0), yiaddr: yi, serverID: sid, msgType: mt, method: "socket"}
				return
			}
		}
	}()

	// wachten op het antwoord (capturevenster)
	select {
	case r := <-gotFromSock:
		conn.Close()
		return r, nil
	case <-time.After(o.timeout):
	}
	conn.Close()

	// capture stoppen, converteren en parsen
	hidden("pktmon", "stop").Run()
	conv := hidden("pktmon", "pcapng", etl, "-o", png)
	if out, err := conv.CombinedOutput(); err != nil {
		return dhcpResult{}, fmt.Errorf("pktmon pcapng-conversie faalde: %s", trimOut(out))
	}
	data, err := os.ReadFile(png)
	if err != nil {
		return dhcpResult{}, fmt.Errorf("pcapng lezen: %w", err)
	}
	os.Remove(etl)
	os.Remove(png)

	// De hele capture wordt doorlopen, niet tot het eerste antwoord: op een
	// onbekend netwerk wil je juist weten of er méér dan één DHCP-server reageert.
	var reqTS int64
	var res dhcpResult
	got := false
	frames := parsePcapngTS(data)
	var nDHCP, nOurs int
	for _, fr := range frames {
		if isDHCPFrame(fr.data) {
			nDHCP++
		}
		mt, yi, sid, ok, dir := classifyDHCPFrame(fr.data, xid)
		if !ok {
			continue
		}
		nOurs++
		if dir == dhcpToServer && reqTS == 0 {
			reqTS = fr.tsNanos
			continue
		}
		if dir != dhcpToClient || (mt != dhcpOffer && mt != dhcpAck) {
			continue
		}
		if !got {
			base := t0.UnixNano()
			if reqTS != 0 {
				base = reqTS
			}
			rtt := time.Duration(fr.tsNanos - base)
			if rtt < 0 {
				rtt = 0
			}
			res = dhcpResult{rtt: rtt, yiaddr: yi, serverID: sid, msgType: mt, method: "pktmon"}
			got = true
		}
		res.addServer(sid)
	}
	if got {
		return res, nil
	}
	return dhcpResult{}, fmt.Errorf("geen antwoord binnen %s (%s) — %s",
		o.timeout, where, captureDiag(len(data), len(frames), nDHCP, nOurs, reqTS != 0))
}

const (
	dhcpToServer = 1 // 68 → 67
	dhcpToClient = 2 // 67 → 68
)

// classifyDHCPFrame ontleedt een ruw Ethernet-frame tot een DHCP-bericht en bepaalt
// de richting; dir is 0 als het geen bruikbaar DHCP-frame met ons xid is.
func classifyDHCPFrame(f []byte, xid uint32) (msgType byte, yiaddr, serverID net.IP, ok bool, dir int) {
	if len(f) < 14+20+8+240 {
		return 0, nil, nil, false, 0
	}
	if f[12] != 0x08 || f[13] != 0x00 {
		return 0, nil, nil, false, 0
	}
	ihl := int(f[14]&0x0f) * 4
	if ihl < 20 || 14+ihl+8 > len(f) || f[14+9] != 17 {
		return 0, nil, nil, false, 0
	}
	udp := 14 + ihl
	src := binary.BigEndian.Uint16(f[udp:])
	dstp := binary.BigEndian.Uint16(f[udp+2:])
	switch {
	case src == 68 && dstp == 67:
		dir = dhcpToServer
	case src == 67 && dstp == 68:
		dir = dhcpToClient
	default:
		return 0, nil, nil, false, 0
	}
	payload := f[udp+8:]
	mt, yi, sid, valid := parseDHCP(payload)
	if !valid || len(payload) < 8 || binary.BigEndian.Uint32(payload[4:8]) != xid {
		return 0, nil, nil, false, 0
	}
	return mt, yi, sid, true, dir
}

// isDHCPFrame zegt of een ruw Ethernet-frame UDP-verkeer op poort 67 of 68 is,
// ongeacht transactie-id. Gebruikt om te kunnen zeggen wát pktmon wél zag.
func isDHCPFrame(f []byte) bool {
	if len(f) < 14+20+8 || f[12] != 0x08 || f[13] != 0x00 {
		return false
	}
	ihl := int(f[14]&0x0f) * 4
	if ihl < 20 || 14+ihl+8 > len(f) || f[14+9] != 17 {
		return false
	}
	src := binary.BigEndian.Uint16(f[14+ihl:])
	dst := binary.BigEndian.Uint16(f[14+ihl+2:])
	return src == 67 || src == 68 || dst == 67 || dst == 68
}

// captureDiag vertelt in gewone taal waar de pktmon-meting op stukliep. Zonder dit
// is elke mislukking een kale timeout en valt er niets te herleiden.
func captureDiag(bytes, frames, dhcp, ours int, sawRequest bool) string {
	switch {
	case bytes == 0:
		return "de pcapng van pktmon was leeg; de capture is niet gelopen"
	case frames == 0:
		return fmt.Sprintf("pktmon leverde %d bytes pcapng op maar er kwam geen enkel frame uit de parser; "+
			"waarschijnlijk een pcapng-variant die deze tool niet leest", bytes)
	case dhcp == 0:
		return fmt.Sprintf("pktmon ving %d frames op, maar geen enkel DHCP-frame (UDP 67/68); "+
			"de capture staat mogelijk op een ander netwerkonderdeel dan de actieve adapter", frames)
	case !sawRequest:
		return fmt.Sprintf("pktmon ving %d frames op waarvan %d DHCP, maar onze eigen DISCOVER zat er niet bij; "+
			"het verzoek is de adapter niet uit gekomen", frames, dhcp)
	case ours == 0:
		return fmt.Sprintf("pktmon ving %d frames op waarvan %d DHCP, maar geen met ons transactie-id", frames, dhcp)
	default:
		return fmt.Sprintf("pktmon ving %d frames op, %d DHCP, %d met ons transactie-id, maar geen OFFER of ACK; "+
			"er staat geen DHCP-server op dit segment of hij antwoordt niet op een broadcast", frames, dhcp, ours)
	}
}

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// dhcpBroadcastInform vraagt het netwerk zelf wie er DHCP doet, zonder ook maar
// één server vooraf te kennen: een DHCP INFORM naar 255.255.255.255.
//
// Het verschil met een DISCOVER zit in waar het antwoord terugkomt. Een DISCOVER
// wordt beantwoord op poort 68, en die is op Windows eigendom van de
// DHCP-Clientservice en wordt door de firewall afgeschermd — daar is een
// capture-driver of pktmon (Administrator) voor nodig. Een INFORM verstuurd
// vanaf een efemere poort wordt door DHCP-servers beantwoord op diezelfde poort,
// en dat antwoord hoort bij ons eigen uitgaande verkeer, dus de firewall laat het
// door en er zijn geen verhoogde rechten nodig.
//
// Omdat het verzoek een broadcast is, antwoordt elke DHCP-server op het segment.
// Een tweede antwoord is daarmee direct het signaal voor een ongewenste server.
// Een INFORM reserveert bovendien geen adres, dus herhaald meten put de pool niet uit.
func dhcpBroadcastInform(o dhcpOpts) (dhcpResult, error) {
	localIP, mac, err := localAddrFor("", o.iface)
	if err != nil {
		return dhcpResult{}, fmt.Errorf("lokaal adres bepalen: %w", err)
	}
	if o.srcIP != nil {
		localIP = o.srcIP
		if m := macForIP(o.srcIP); m != nil {
			mac = m
		}
	}
	if localIP == nil {
		return dhcpResult{}, fmt.Errorf("geen lokaal IPv4-adres op deze interface")
	}

	var xidb [4]byte
	rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])

	// broadcast-vlag uit: het antwoord mag rechtstreeks naar ons terug.
	packet := buildDHCP(dhcpInform, xid, mac, localIP, false)

	bind := net.IPv4zero
	if o.srcIP != nil {
		bind = o.srcIP
	}
	conn, err := dhcpListen(&net.UDPAddr{IP: bind, Port: o.port}, true)
	if err != nil {
		return dhcpResult{}, fmt.Errorf("socket openen: %w", err)
	}
	defer conn.Close()

	start := time.Now()
	if _, err := conn.WriteToUDP(packet, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		return dhcpResult{}, fmt.Errorf("verzenden: %w", err)
	}

	deadline := start.Add(o.timeout)
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 1500)
	var res dhcpResult
	got := false
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if got {
				return res, nil
			}
			return dhcpResult{}, fmt.Errorf("geen antwoord binnen %s", o.timeout)
		}
		mt, yi, sid, ok := parseDHCP(buf[:n])
		if !ok || binary.BigEndian.Uint32(buf[4:8]) != xid {
			continue
		}
		if mt != dhcpAck && mt != dhcpOffer {
			continue
		}
		if !got {
			got = true
			res = dhcpResult{rtt: time.Since(start), yiaddr: yi, serverID: sid, msgType: mt,
				method: "broadcast INFORM"}
			// nog even doorluisteren: antwoordt er een tweede server?
			extra := 400 * time.Millisecond
			if rest := time.Until(deadline); rest < extra {
				extra = rest
			}
			if extra <= 0 {
				res.addServer(sid)
				return res, nil
			}
			conn.SetReadDeadline(time.Now().Add(extra))
		}
		res.addServer(sid)
	}
}

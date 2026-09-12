package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// dhcpBroadcastInform vraagt het netwerk zelf wie er DHCP doet, zonder ook maar
// één server vooraf te kennen: een DHCP INFORM naar 255.255.255.255.
//
// Het verschil met een DISCOVER zit in waar het antwoord terugkomt. Een DISCOVER
// wordt beantwoord op poort 68, en die is op Windows eigendom van de
// DHCP-Clientservice en wordt door de firewall afgeschermd. Een INFORM verstuurd
// vanaf een efemere poort wordt door DHCP-servers beantwoord op diezelfde poort,
// en dat antwoord hoort bij ons eigen uitgaande verkeer, dus de firewall laat het
// door en er zijn geen verhoogde rechten nodig.
//
// Het verzoek gaat over elke bruikbare interface tegelijk, elk vanaf een socket
// die aan het adres van díe interface is gebonden. Een socket op 0.0.0.0 laat de
// keuze aan de routeringstabel, en die stuurt een limited broadcast naar de
// interface met de laagste metric — op een machine met een VPN- of virtuele
// adapter is dat vaak niet de kabel waar de switch aan hangt.
//
// Omdat het verzoek een broadcast is, antwoordt elke DHCP-server op het segment.
// Een tweede antwoord is daarmee direct het signaal voor een ongewenste server.
// Een INFORM reserveert bovendien geen adres, dus herhaald meten put de pool niet uit.
func dhcpBroadcastInform(o dhcpOpts) (dhcpResult, error) {
	targets := broadcastTargets(o)
	if len(targets) == 0 {
		return dhcpResult{}, fmt.Errorf("geen bruikbare IPv4-interface gevonden")
	}

	type outcome struct {
		res dhcpResult
		err error
	}
	ch := make(chan outcome, len(targets))
	for _, ifc := range targets {
		go func(ifc netIface) {
			r, e := informOnIface(ifc, o)
			ch <- outcome{r, e}
		}(ifc)
	}

	var best dhcpResult
	var errs []string
	got := false
	for range targets {
		oc := <-ch
		if oc.err != nil {
			errs = append(errs, oc.err.Error())
			continue
		}
		if !got || oc.res.rtt < best.rtt {
			servers := best.servers
			best = oc.res
			best.servers = servers
			got = true
		}
		for _, s := range oc.res.servers {
			best.addServer(s)
		}
	}
	if got {
		return best, nil
	}
	return dhcpResult{}, fmt.Errorf("%s", strings.Join(dedup(errs), "; "))
}

// broadcastTargets bepaalt over welke interfaces het verzoek gaat: de gevraagde,
// of anders alle bruikbare tegelijk.
func broadcastTargets(o dhcpOpts) []netIface {
	all := usableIPv4Ifaces()
	if o.srcIP != nil {
		for _, i := range all {
			if i.ip.Equal(o.srcIP) {
				return []netIface{i}
			}
		}
		return []netIface{{name: o.iface, ip: o.srcIP, mac: macForIP(o.srcIP)}}
	}
	if o.iface != "" {
		var sel []netIface
		for _, i := range all {
			if strings.EqualFold(i.name, o.iface) || strings.Contains(strings.ToLower(i.name), strings.ToLower(o.iface)) {
				sel = append(sel, i)
			}
		}
		if len(sel) > 0 {
			return sel
		}
	}
	return all
}

// informOnIface stuurt het INFORM vanaf één specifieke interface en leest de
// antwoorden die binnen de timeout terugkomen.
func informOnIface(ifc netIface, o dhcpOpts) (dhcpResult, error) {
	mac := ifc.mac
	if len(mac) != 6 {
		mac = net.HardwareAddr{0x02, 0x00, 0x4e, 0x54, 0x00, 0x01}
	}

	var xidb [4]byte
	rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])

	// broadcast-vlag uit: het antwoord mag rechtstreeks naar ons terug.
	packet := buildDHCP(dhcpInform, xid, mac, ifc.ip, false)

	conn, err := dhcpListen(&net.UDPAddr{IP: ifc.ip, Port: o.port}, true)
	if err != nil {
		return dhcpResult{}, fmt.Errorf("%s: socket openen: %v", ifc.name, err)
	}
	defer conn.Close()

	start := time.Now()
	if _, err := conn.WriteToUDP(packet, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		return dhcpResult{}, fmt.Errorf("%s: verzenden: %v", ifc.name, err)
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
			return dhcpResult{}, fmt.Errorf("%s: geen antwoord binnen %s", ifc.name, o.timeout)
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
				method: "broadcast INFORM via " + ifc.name}
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

// dedup houdt de volgorde aan en laat dubbele meldingen weg.
func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

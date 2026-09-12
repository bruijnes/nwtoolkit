package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// dhcpBroadcastInform asks the network itself who is serving DHCP, without knowing
// a single server up front: a DHCP INFORM to 255.255.255.255.
//
// The difference with a DISCOVER is where the answer comes back. A DISCOVER is
// answered on port 68, which on Windows belongs to the DHCP Client service and is
// shielded by the firewall. An INFORM sent from an ephemeral port is answered by
// DHCP servers on that same port, and that answer belongs to our own outbound
// traffic, so the firewall lets it through and no elevation is required.
//
// The request goes out over every usable interface at once, each from a socket bound
// to that interface's own address. A socket on 0.0.0.0 leaves the choice to the
// routing table, which sends a limited broadcast to the interface with the lowest
// metric — on a machine with a VPN or virtual adapter that is often not the cable
// the switch is on.
//
// Because the request is a broadcast, every DHCP server on the segment answers. A
// second answer is therefore an immediate signal of a rogue server. An INFORM also
// reserves no address, so repeated measurement does not drain the pool.
func dhcpBroadcastInform(o dhcpOpts) (dhcpResult, error) {
	targets := broadcastTargets(o)
	if len(targets) == 0 {
		return dhcpResult{}, fmt.Errorf("no usable IPv4 interface found")
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

// broadcastTargets decides which interfaces the request goes out on: the requested
// one, or otherwise all usable ones at once.
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

// informOnIface sends the INFORM from one specific interface and reads the answers
// that come back within the timeout.
func informOnIface(ifc netIface, o dhcpOpts) (dhcpResult, error) {
	mac := ifc.mac
	if len(mac) != 6 {
		mac = net.HardwareAddr{0x02, 0x00, 0x4e, 0x54, 0x00, 0x01}
	}

	var xidb [4]byte
	rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])

	// broadcast flag off: the answer may come straight back to us.
	packet := buildDHCP(dhcpInform, xid, mac, ifc.ip, false)

	conn, err := dhcpListen(&net.UDPAddr{IP: ifc.ip, Port: o.port}, true)
	if err != nil {
		return dhcpResult{}, fmt.Errorf("%s: opening socket: %v", ifc.name, err)
	}
	defer conn.Close()

	start := time.Now()
	if _, err := conn.WriteToUDP(packet, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		return dhcpResult{}, fmt.Errorf("%s: sending: %v", ifc.name, err)
	}

	res, err := collectAnswers(conn, xid, start, o.timeout, true, ifc.name)
	if err != nil {
		return dhcpResult{}, err
	}
	res.method = "broadcast INFORM via " + ifc.name
	return res, nil
}

// dedup preserves order and drops duplicate messages.
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

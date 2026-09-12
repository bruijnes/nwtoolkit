//go:build windows

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// dhcpProbePktmon sends a broadcast DISCOVER over an ordinary UDP socket and
// captures the OFFER or ACK with the built-in Windows Packet Monitor (pktmon), just
// like the LLDP capture, so entirely with what Windows ships. The OFFER arrives on
// port 68, owned by the DHCP Client service, but pktmon sees the frame on the wire.
// Requires Administrator. The response time comes from the pcapng timestamps.
func dhcpProbePktmon(o dhcpOpts) (dhcpResult, error) {
	// The DISCOVER goes out over every usable interface, each from a socket bound to
	// that interface's own address. A socket on 0.0.0.0 leaves the choice to the
	// routing table, which sends a limited broadcast to the interface with the lowest
	// metric — on a machine with a VPN or virtual adapter that is often not the cable
	// the switch is on.
	targets := broadcastTargets(o)
	if len(targets) == 0 {
		return dhcpResult{}, fmt.Errorf("no usable IPv4 interface found")
	}
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.name
	}
	where := "pktmon via " + strings.Join(names, ", ")

	var xidb [4]byte
	rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])

	var t0 time.Time
	var sendErr error
	var fromSocket *dhcpResult

	data, err := pktmonCapture("dhcp", func() bool {
		time.Sleep(pktmonSettleDelay)

		conns, errs := sendDiscover(targets, xid)
		if len(conns) == 0 {
			sendErr = fmt.Errorf("DISCOVER could not be sent anywhere: %s", strings.Join(errs, "; "))
			return false
		}
		t0 = time.Now()
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()

		// The sockets listen along as well: sometimes the OFFER does get through, and
		// then there is no need to convert and parse the capture at all.
		answers := make(chan dhcpResult, len(conns))
		for _, c := range conns {
			go func(conn *net.UDPConn) {
				if r, err := collectAnswers(conn, xid, t0, o.timeout, false, ""); err == nil {
					r.method = "socket"
					answers <- r
				}
			}(c)
		}
		select {
		case r := <-answers:
			fromSocket = &r
			return false
		case <-time.After(o.timeout):
			return true
		}
	})
	if sendErr != nil {
		return dhcpResult{}, sendErr
	}
	if fromSocket != nil {
		return *fromSocket, nil
	}
	if err != nil {
		return dhcpResult{}, err
	}

	// The whole capture is scanned rather than stopping at the first answer: on an
	// unknown network you specifically want to know if more than one server responds.
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
	return dhcpResult{}, fmt.Errorf("no answer within %s (%s) — %s",
		o.timeout, where, captureDiag(len(data), len(frames), nDHCP, nOurs, reqTS != 0))
}

// sendDiscover opens one socket per interface, bound to that interface's own
// address, and broadcasts a DISCOVER from each. It returns the sockets that are
// listening plus a message for every interface that could not be used.
func sendDiscover(targets []netIface, xid uint32) ([]*net.UDPConn, []string) {
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	var conns []*net.UDPConn
	var errs []string
	for _, ifc := range targets {
		c, err := dhcpListen(&net.UDPAddr{IP: ifc.ip, Port: 68}, true)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: cannot open port 68 (%v)", ifc.name, err))
			continue
		}
		mac := ifc.mac
		if len(mac) != 6 {
			mac = net.HardwareAddr{0x02, 0x00, 0x4e, 0x54, 0x00, 0x01}
		}
		if _, err := c.WriteToUDP(buildDHCP(dhcpDiscover, xid, mac, net.IPv4zero, true), dst); err != nil {
			errs = append(errs, fmt.Sprintf("%s: sending failed (%v)", ifc.name, err))
			c.Close()
			continue
		}
		conns = append(conns, c)
	}
	return conns, errs
}

const (
	dhcpToServer = 1 // 68 → 67
	dhcpToClient = 2 // 67 → 68
)

// classifyDHCPFrame parses a raw Ethernet frame into a DHCP message and determines
// its direction; dir is 0 if it is not a usable DHCP frame carrying our xid.
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
	if len(payload) < 240 || binary.BigEndian.Uint32(payload[4:8]) != xid {
		return 0, nil, nil, false, 0
	}
	// Our own request is a BOOTREQUEST (op 1); parseDHCP only accepts replies (op 2).
	// The outgoing frame has to be recognised separately here, otherwise it looks as
	// though the request never left the adapter.
	if payload[0] == 1 {
		return 0, nil, nil, true, dhcpToServer
	}
	mt, yi, sid, valid := parseDHCP(payload)
	if !valid {
		return 0, nil, nil, false, 0
	}
	return mt, yi, sid, true, dir
}

// isDHCPFrame reports whether a raw Ethernet frame is UDP traffic on port 67 or 68,
// regardless of transaction id. Used to report what pktmon did see.
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

// captureDiag says in plain words where the pktmon measurement broke down. Without
// it every failure is a bare timeout with nothing to trace back.
func captureDiag(bytes, frames, dhcp, ours int, sawRequest bool) string {
	switch {
	case bytes == 0:
		return "the pcapng from pktmon was empty; the capture did not run"
	case frames == 0:
		return fmt.Sprintf("pktmon produced %d bytes of pcapng but the parser found no frames at all; "+
			"probably a pcapng variant this tool does not read", bytes)
	case dhcp == 0:
		return fmt.Sprintf("pktmon captured %d frames, but not a single DHCP frame (UDP 67/68); "+
			"the capture may be on a different network component than the active adapter", frames)
	case !sawRequest:
		return fmt.Sprintf("pktmon captured %d frames of which %d DHCP, but our own DISCOVER was not among them; "+
			"the request never left the adapter", frames, dhcp)
	case ours == 0:
		return fmt.Sprintf("pktmon captured %d frames of which %d DHCP, but none with our transaction id", frames, dhcp)
	default:
		return fmt.Sprintf("pktmon captured %d frames, %d DHCP, %d with our transaction id, but no OFFER or ACK; "+
			"there is no DHCP server on this segment, or it does not answer a broadcast", frames, dhcp, ours)
	}
}

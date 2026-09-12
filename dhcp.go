package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

type dhcpOpts struct {
	server   string // empty = broadcast DISCOVER; set = unicast INFORM
	iface    string
	srcIP    net.IP // local IPv4 to bind to (selects the outgoing interface); nil = the OS picks
	timeout  time.Duration
	monitor  bool
	interval time.Duration
	count    int
	port     int // local port; 0 = auto (68 for broadcast, ephemeral for inform)
	ipv6     bool
}

// netIface describes a usable interface for the DHCP interface choice.
type netIface struct {
	name string
	ip   net.IP
	mac  net.HardwareAddr
}

// usableIPv4Ifaces returns the active, non-loopback interfaces that have an IPv4 address.
func usableIPv4Ifaces() []netIface {
	var out []netIface
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLinkLocalUnicast() {
				out = append(out, netIface{ifc.Name, v4, ifc.HardwareAddr})
				break
			}
		}
	}
	return out
}

// macForIP looks up the MAC address of the interface holding this IPv4 address.
func macForIP(ip net.IP) net.HardwareAddr {
	if ip == nil {
		return nil
	}
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(ip) && len(ifc.HardwareAddr) == 6 {
				return ifc.HardwareAddr
			}
		}
	}
	return nil
}

const (
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpInform   = 8
	magicCookie  = 0x63825363
)

// localAddrFor determines the local IPv4 and MAC used to reach dst (or the default route).
func localAddrFor(dst string, ifname string) (net.IP, net.HardwareAddr, error) {
	target := dst
	if target == "" || target == "255.255.255.255" {
		target = "8.8.8.8:67"
	} else if _, _, err := net.SplitHostPort(target); err != nil {
		target = target + ":67"
	}
	c, err := net.Dial("udp4", target)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	localIP := c.LocalAddr().(*net.UDPAddr).IP.To4()

	// find the interface holding this IP (or the named one) to get its MAC address
	ifaces, _ := net.Interfaces()
	var mac net.HardwareAddr
	for _, ifc := range ifaces {
		if ifname != "" && ifc.Name != ifname {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(localIP) {
				if len(ifc.HardwareAddr) == 6 {
					mac = ifc.HardwareAddr
				}
			}
		}
	}
	if mac == nil {
		mac = net.HardwareAddr{0x02, 0x00, 0x4e, 0x54, 0x00, 0x01} // locally administered fallback
	}
	return localIP, mac, nil
}

func buildDHCP(msgType byte, xid uint32, mac net.HardwareAddr, ciaddr net.IP, broadcast bool) []byte {
	b := make([]byte, 240)
	b[0] = 1 // BOOTREQUEST
	b[1] = 1 // ethernet
	b[2] = 6 // hlen
	binary.BigEndian.PutUint32(b[4:], xid)
	if broadcast {
		binary.BigEndian.PutUint16(b[10:], 0x8000)
	}
	if ci := ciaddr.To4(); ci != nil {
		copy(b[12:16], ci) // ciaddr
	}
	copy(b[28:34], mac) // chaddr
	binary.BigEndian.PutUint32(b[236:], magicCookie)

	opts := []byte{
		53, 1, msgType, // DHCP message type
		55, 4, 1, 3, 6, 15, // param request list: subnet, router, dns, domain
		61, 7, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], // client id
		255, // end
	}
	return append(b, opts...)
}

func parseDHCP(b []byte) (msgType byte, yiaddr net.IP, serverID net.IP, ok bool) {
	if len(b) < 240 || b[0] != 2 {
		return 0, nil, nil, false
	}
	yiaddr = net.IP(append([]byte(nil), b[16:20]...))
	if binary.BigEndian.Uint32(b[236:]) != magicCookie {
		return 0, yiaddr, nil, false
	}
	i := 240
	for i < len(b) {
		code := b[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		l := int(b[i+1])
		if i+2+l > len(b) {
			break
		}
		val := b[i+2 : i+2+l]
		switch code {
		case 53:
			if l >= 1 {
				msgType = val[0]
			}
		case 54:
			if l == 4 {
				serverID = net.IP(append([]byte(nil), val...))
			}
		}
		i += 2 + l
	}
	return msgType, yiaddr, serverID, true
}

type dhcpResult struct {
	rtt      time.Duration
	yiaddr   net.IP
	serverID net.IP
	msgType  byte
	info6    string   // filled for DHCPv6 (e.g. "REPLY")
	method   string   // which capture method: "INFORM", "pktmon", "UDP"
	servers  []net.IP // every server that answered within the timeout (broadcast DISCOVER)
}

// addServer appends a server to the list, skipping duplicates.
func (r *dhcpResult) addServer(ip net.IP) {
	if ip == nil {
		return
	}
	for _, e := range r.servers {
		if e.Equal(ip) {
			return
		}
	}
	r.servers = append(r.servers, ip)
}

// serverSummary describes how many servers answered; more than one is a rogue-DHCP
// signal and therefore worth reporting.
func (r dhcpResult) serverSummary() string {
	if len(r.servers) < 2 {
		return ""
	}
	names := make([]string, len(r.servers))
	for i, s := range r.servers {
		names[i] = s.String()
	}
	return fmt.Sprintf("%d servers answered: %s", len(r.servers), strings.Join(names, ", "))
}

// dhcpProbeUDP sends a single DISCOVER (broadcast) or INFORM (unicast) over an
// ordinary UDP socket and waits for an OFFER or ACK. On Windows this is unreliable
// because the DHCP Client service owns port 68, which is why dhcpProbe there prefers
// a unicast INFORM to a known server, and otherwise the built-in pktmon.
func dhcpProbeUDP(o dhcpOpts) (dhcpResult, error) {
	localIP, mac, err := localAddrFor(o.server, o.iface)
	if err != nil {
		return dhcpResult{}, fmt.Errorf("determining local address: %w", err)
	}

	var xidb [4]byte
	rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])

	broadcast := o.server == ""
	msg := byte(dhcpInform)
	ci := localIP
	if broadcast {
		msg = dhcpDiscover
		ci = net.IPv4zero
	}
	packet := buildDHCP(msg, xid, mac, ci, broadcast)

	// set up the socket
	lport := o.port
	if lport == 0 {
		if broadcast {
			lport = 68
		} else {
			lport = 0 // ephemeral
		}
	}
	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: lport}
	conn, err := dhcpListen(laddr, broadcast)
	if err != nil {
		if broadcast {
			return dhcpResult{}, fmt.Errorf("cannot open port 68 (%v) — run as Administrator or stop the DHCP Client service, or use -server <ip> for the unicast INFORM method", err)
		}
		return dhcpResult{}, err
	}
	defer conn.Close()

	var dst *net.UDPAddr
	if broadcast {
		dst = &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	} else {
		sip, _ := resolve4(o.server)
		if sip == nil {
			return dhcpResult{}, fmt.Errorf("cannot resolve DHCP server %s", o.server)
		}
		dst = &net.UDPAddr{IP: sip, Port: 67}
	}

	start := time.Now()
	if _, err := conn.WriteToUDP(packet, dst); err != nil {
		return dhcpResult{}, fmt.Errorf("sending: %w", err)
	}

	return collectAnswers(conn, xid, start, o.timeout, broadcast, "")
}

// extraListenWindow is how long a broadcast probe keeps listening after the first
// answer. A second responder means a rogue DHCP server, which is worth catching,
// but waiting out the full timeout on every measurement would be pointless.
const extraListenWindow = 400 * time.Millisecond

// collectAnswers reads DHCP replies on conn until the timeout expires, and returns
// the first usable one together with every distinct server that answered.
//
// A unicast probe returns as soon as one answer arrives, because only one server can
// reply. A broadcast probe keeps listening for extraListenWindow afterwards, so a
// second server on the segment still shows up. label prefixes the timeout message
// when several interfaces are probed at once and the caller needs to say which one.
func collectAnswers(conn *net.UDPConn, xid uint32, start time.Time, timeout time.Duration, broadcast bool, label string) (dhcpResult, error) {
	deadline := start.Add(timeout)
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 1500)
	var res dhcpResult
	got := false
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if got {
				return res, nil // deadline of the extra listening window
			}
			if label != "" {
				return dhcpResult{}, fmt.Errorf("%s: no answer within %s", label, timeout)
			}
			return dhcpResult{}, fmt.Errorf("no answer within %s", timeout)
		}
		mt, yi, sid, ok := parseDHCP(buf[:n])
		if !ok || binary.BigEndian.Uint32(buf[4:8]) != xid {
			continue // not a reply, or not our transaction id
		}
		if mt != dhcpOffer && mt != dhcpAck {
			continue
		}
		if got {
			res.addServer(sid)
			continue
		}
		got = true
		res = dhcpResult{rtt: time.Since(start), yiaddr: yi, serverID: sid, msgType: mt}
		res.addServer(sid)
		if !broadcast {
			return res, nil // unicast: one answer is all there is
		}
		extra := extraListenWindow
		if rest := time.Until(deadline); rest < extra {
			extra = rest
		}
		if extra <= 0 {
			return res, nil
		}
		conn.SetReadDeadline(time.Now().Add(extra))
	}
}

func cmdDHCP(o dhcpOpts) {
	method := "broadcast to 255.255.255.255 — with no prior knowledge of any server"
	if o.ipv6 {
		method = "DHCPv6 INFORMATION-REQUEST (multicast ff02::1:2)"
		if o.server != "" {
			method = "DHCPv6 INFORMATION-REQUEST to " + o.server
		}
	} else if o.server != "" {
		method = "unicast INFORM to " + o.server
	}

	if !o.monitor && o.count <= 1 {
		res, err := dhcpProbe(o)
		fmt.Printf("DHCP speed test  method: %s\n", method)
		if err != nil {
			die("%v", err)
		}
		mt := "OFFER"
		if res.info6 != "" {
			mt = res.info6
		} else if res.msgType == dhcpAck {
			mt = "ACK"
		}
		fmt.Printf("Answer:     %s from server %s\n", mt, res.serverID)
		if sum := res.serverSummary(); sum != "" {
			fmt.Printf("Note:       %s\n", col(cYellow, sum))
		}
		if !res.yiaddr.Equal(net.IPv4zero) && res.yiaddr != nil {
			fmt.Printf("Offered:    %s\n", res.yiaddr)
		}
		fmt.Printf("Time:       %s\n", col(cGreen, fmt.Sprintf("%.2f ms", float64(res.rtt.Microseconds())/1000)))
		return
	}

	runSpeedGraph(speedGraphCfg{
		title:    "DHCP-speedtest  " + method,
		unit:     "ms",
		interval: o.interval,
		count:    o.count,
		monitor:  o.monitor,
		measure: func() (float64, string, error) {
			res, err := dhcpProbe(o)
			if err != nil {
				return 0, "", err
			}
			mt := "OFFER"
			if res.info6 != "" {
				mt = res.info6
			} else if res.msgType == dhcpAck {
				mt = "ACK"
			}
			info := fmt.Sprintf("%s from %s", mt, res.serverID)
			if !res.yiaddr.Equal(net.IPv4zero) && res.yiaddr != nil {
				info += " → " + res.yiaddr.String()
			}
			return float64(res.rtt.Microseconds()) / 1000, info, nil
		},
	})
}

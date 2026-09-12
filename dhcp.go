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
	server   string // leeg = broadcast DISCOVER; ingevuld = unicast INFORM
	iface    string
	srcIP    net.IP // lokaal IPv4 om aan te binden (kiest de uitgaande interface); nil = OS kiest
	timeout  time.Duration
	monitor  bool
	interval time.Duration
	count    int
	port     int // lokale poort; 0 = auto (68 voor broadcast, ephemeral voor inform)
	ipv6     bool
	discover bool // forceer broadcast DISCOVER: doe alsof geen enkele server bekend is
}

// netIface beschrijft een bruikbare interface voor de DHCP-interfacekeuze.
type netIface struct {
	name string
	ip   net.IP
	mac  net.HardwareAddr
}

// usableIPv4Ifaces geeft de actieve, niet-loopback interfaces met een IPv4-adres.
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

// macForIP zoekt het MAC-adres van de interface met dit IPv4-adres.
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

// localAddrFor bepaalt het lokale IPv4 + MAC voor het bereiken van dst (of default route).
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

	// vind de interface met dit IP (of met de opgegeven naam) voor het MAC-adres
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
		mac = net.HardwareAddr{0x02, 0x00, 0x4e, 0x54, 0x00, 0x01} // locally-administered fallback
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
	info6    string   // gevuld bij DHCPv6 (bijv. "REPLY")
	method   string   // welke opvangmethode: "INFORM", "pktmon", "UDP"
	servers  []net.IP // alle servers die binnen de timeout antwoordden (broadcast DISCOVER)
}

// addServer voegt een server toe aan de lijst zonder dubbelen.
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

// serverSummary beschrijft hoeveel servers antwoordden; bij meer dan één is dat
// een rogue-DHCP-signaal en dus het vermelden waard.
func (r dhcpResult) serverSummary() string {
	if len(r.servers) < 2 {
		return ""
	}
	names := make([]string, len(r.servers))
	for i, s := range r.servers {
		names[i] = s.String()
	}
	return fmt.Sprintf("%d servers antwoordden: %s", len(r.servers), strings.Join(names, ", "))
}

// dhcpProbeUDP verstuurt via een gewone UDP-socket één DISCOVER (broadcast) of
// INFORM (unicast) en wacht op OFFER/ACK. Op Windows is dit onbetrouwbaar omdat de
// DHCP-Clientservice poort 68 bezit; daar kiest dhcpProbe daarom eerst de unicast
// INFORM naar de server die Windows al kent, en anders de ingebouwde pktmon.
func dhcpProbeUDP(o dhcpOpts) (dhcpResult, error) {
	localIP, mac, err := localAddrFor(o.server, o.iface)
	if err != nil {
		return dhcpResult{}, fmt.Errorf("lokaal adres bepalen: %w", err)
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

	// socket opzetten
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
			return dhcpResult{}, fmt.Errorf("kan poort 68 niet openen (%v) — start als Administrator of stop de DHCP-clientservice, of gebruik -server <ip> voor de unicast INFORM-methode", err)
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
			return dhcpResult{}, fmt.Errorf("kan DHCP-server %s niet resolven", o.server)
		}
		dst = &net.UDPAddr{IP: sip, Port: 67}
	}

	start := time.Now()
	if _, err := conn.WriteToUDP(packet, dst); err != nil {
		return dhcpResult{}, fmt.Errorf("verzenden: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(o.timeout))
	buf := make([]byte, 1500)
	var res dhcpResult
	got := false
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if got {
				return res, nil // deadline van het extra luistervenster
			}
			return dhcpResult{}, fmt.Errorf("geen antwoord binnen %s", o.timeout)
		}
		mt, yi, sid, ok := parseDHCP(buf[:n])
		if !ok {
			continue
		}
		if binary.BigEndian.Uint32(buf[4:8]) != xid {
			continue // niet ons transactie-id
		}
		if mt != dhcpOffer && mt != dhcpAck {
			continue
		}
		if !got {
			got = true
			res = dhcpResult{rtt: time.Since(start), yiaddr: yi, serverID: sid, msgType: mt}
			res.addServer(sid)
			if !broadcast {
				return res, nil // unicast INFORM: één antwoord is genoeg
			}
			// broadcast: nog even doorluisteren of er een tweede server antwoordt
			extra := 400 * time.Millisecond
			if rest := time.Until(start.Add(o.timeout)); rest < extra {
				extra = rest
			}
			if extra <= 0 {
				return res, nil
			}
			conn.SetReadDeadline(time.Now().Add(extra))
			continue
		}
		res.addServer(sid)
	}
}

func cmdDHCP(o dhcpOpts) {
	method := "broadcast DISCOVER (poort 68)"
	if o.discover {
		method = "broadcast DISCOVER — alsof dit netwerk onbekend is"
	} else if o.ipv6 {
		method = "DHCPv6 INFORMATION-REQUEST (multicast ff02::1:2)"
		if o.server != "" {
			method = "DHCPv6 INFORMATION-REQUEST naar " + o.server
		}
	} else if o.server != "" {
		method = "unicast INFORM naar " + o.server
	}

	if !o.monitor && o.count <= 1 {
		res, err := dhcpProbe(o)
		fmt.Printf("DHCP-speedtest  methode: %s\n", method)
		if err != nil {
			die("%v", err)
		}
		mt := "OFFER"
		if res.info6 != "" {
			mt = res.info6
		} else if res.msgType == dhcpAck {
			mt = "ACK"
		}
		fmt.Printf("Antwoord:   %s van server %s\n", mt, res.serverID)
		if sum := res.serverSummary(); sum != "" {
			fmt.Printf("Let op:     %s\n", col(cYellow, sum))
		}
		if !res.yiaddr.Equal(net.IPv4zero) && res.yiaddr != nil {
			fmt.Printf("Aangeboden: %s\n", res.yiaddr)
		}
		fmt.Printf("Tijd:       %s\n", col(cGreen, fmt.Sprintf("%.2f ms", float64(res.rtt.Microseconds())/1000)))
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
			info := fmt.Sprintf("%s van %s", mt, res.serverID)
			if !res.yiaddr.Equal(net.IPv4zero) && res.yiaddr != nil {
				info += " → " + res.yiaddr.String()
			}
			return float64(res.rtt.Microseconds()) / 1000, info, nil
		},
	})
}

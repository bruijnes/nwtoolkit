//go:build windows

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
	"unsafe"
)

// DHCP op laag-2 via Npcap. Op Windows bezit de DHCP-Clientservice poort 68 en de
// server stuurt de OFFER dáárheen, dus een gewone UDP-socket ontvangt niets. Door
// het frame zelf te versturen én met pcap op te vangen omzeilen we de UDP-stack.

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// pickDHCPDev kiest een pcap-interface (op hint of eerste verbonden niet-loopback)
// en haalt het MAC-adres op via het IPv4-adres van die interface.
func pickDHCPDev(dll *wpcapDLL, hint string, srcIP net.IP) (name, label string, mac net.HardwareAddr, err error) {
	var alldevs uintptr
	errbuf := make([]byte, pcapErrbufSize)
	r := dll.call("pcap_findalldevs", uintptr(unsafe.Pointer(&alldevs)), uintptr(unsafe.Pointer(&errbuf[0])))
	if r != 0 || alldevs == 0 {
		return "", "", nil, fmt.Errorf("pcap_findalldevs: %s", cstr(errbuf))
	}
	defer dll.call("pcap_freealldevs", alldevs)

	type dev struct {
		name, desc string
		ip         net.IP
		connected  bool
	}
	var devs []dev
	for p := alldevs; p != 0; p = *(*uintptr)(unsafe.Pointer(p)) {
		nm := cstrPtr(*(*uintptr)(unsafe.Pointer(p + 8)))
		desc := cstrPtr(*(*uintptr)(unsafe.Pointer(p + 16)))
		flags := *(*uint32)(unsafe.Pointer(p + 32))
		label := nm
		if desc != "" {
			label = desc + "  [" + nm + "]"
		}
		connected := flags&0x10 != 0
		if connected {
			label += " (verbonden)"
		}
		// eerste IPv4-adres van deze interface zoeken (pcap_addr-lijst)
		var ip net.IP
		for a := *(*uintptr)(unsafe.Pointer(p + 24)); a != 0; a = *(*uintptr)(unsafe.Pointer(a)) {
			sa := *(*uintptr)(unsafe.Pointer(a + 8))
			if sa == 0 {
				continue
			}
			if *(*uint16)(unsafe.Pointer(sa)) == 2 { // AF_INET
				ip = net.IPv4(*(*byte)(unsafe.Pointer(sa + 4)), *(*byte)(unsafe.Pointer(sa + 5)),
					*(*byte)(unsafe.Pointer(sa + 6)), *(*byte)(unsafe.Pointer(sa + 7)))
				break
			}
		}
		devs = append(devs, dev{nm, label, ip, connected})
	}

	var chosen *dev
	if srcIP != nil {
		for i := range devs {
			if devs[i].ip != nil && devs[i].ip.Equal(srcIP) {
				chosen = &devs[i]
				break
			}
		}
		// geen match op IP → val terug op auto-keuze hieronder
	}
	if chosen == nil && hint != "" {
		for i := range devs {
			if strings.Contains(strings.ToLower(devs[i].name+devs[i].desc), strings.ToLower(hint)) {
				chosen = &devs[i]
				break
			}
		}
	}
	if chosen == nil {
		for i := range devs {
			if devs[i].connected && devs[i].ip != nil && !strings.Contains(strings.ToLower(devs[i].name), "loopback") {
				chosen = &devs[i]
				break
			}
		}
		if chosen == nil {
			for i := range devs {
				if devs[i].ip != nil {
					chosen = &devs[i]
					break
				}
			}
		}
	}
	if chosen == nil {
		return "", "", nil, fmt.Errorf("geen bruikbare interface gevonden")
	}

	// MAC opzoeken via het IPv4-adres van de gekozen interface
	if chosen.ip != nil {
		if ifaces, e := net.Interfaces(); e == nil {
			for _, ifc := range ifaces {
				addrs, _ := ifc.Addrs()
				for _, ad := range addrs {
					if ipn, ok := ad.(*net.IPNet); ok && ipn.IP.Equal(chosen.ip) && len(ifc.HardwareAddr) == 6 {
						mac = ifc.HardwareAddr
					}
				}
			}
		}
	}
	if mac == nil {
		mac = net.HardwareAddr{0x02, 0x00, 0x4e, 0x54, 0x00, 0x01} // fallback (OFFER komt toch als broadcast)
	}
	return chosen.name, chosen.desc, mac, nil
}

// dhcpProbeL2 stuurt een broadcast DISCOVER via Npcap en vangt de OFFER/ACK op L2 op.
func dhcpProbeL2(o dhcpOpts) (dhcpResult, error) {
	dll, err := loadWpcap()
	if err != nil {
		return dhcpResult{}, err
	}
	name, label, mac, err := pickDHCPDev(dll, o.iface, o.srcIP)
	if err != nil {
		return dhcpResult{}, err
	}

	var xidb [4]byte
	rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])

	dhcp := buildDHCP(dhcpDiscover, xid, mac, net.IPv4zero, true) // broadcast-vlag aan

	// UDP (src 68 → dst 67)
	udpLen := 8 + len(dhcp)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 68)
	binary.BigEndian.PutUint16(udp[2:], 67)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	// checksum 0 = niet ingevuld (toegestaan bij IPv4)
	udp = append(udp, dhcp...)

	// IP (0.0.0.0 → 255.255.255.255)
	ipTotal := 20 + udpLen
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(ipTotal))
	ip[8] = 128 // TTL
	ip[9] = 17  // UDP
	copy(ip[12:16], net.IPv4zero.To4())
	copy(ip[16:20], net.IPv4bcast.To4())
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))

	// Ethernet (broadcast)
	frame := make([]byte, 0, 14+ipTotal)
	frame = append(frame, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // dst
	frame = append(frame, mac...)                             // src
	frame = append(frame, 0x08, 0x00)                         // IPv4
	frame = append(frame, ip...)
	frame = append(frame, udp...)

	cname := append([]byte(name), 0)
	errbuf := make([]byte, pcapErrbufSize)
	h := dll.call("pcap_open_live", uintptr(unsafe.Pointer(&cname[0])), 65536, 0, 300,
		uintptr(unsafe.Pointer(&errbuf[0])))
	if h == 0 {
		return dhcpResult{}, fmt.Errorf("kan interface niet openen: %s (Administrator nodig?)", cstr(errbuf))
	}
	defer dll.call("pcap_close", h)

	start := time.Now()
	if dll.call("pcap_sendpacket", h, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame))) != 0 {
		return dhcpResult{}, fmt.Errorf("verzenden mislukt (pcap_sendpacket)")
	}

	deadline := time.Now().Add(o.timeout)
	var hdr, data uintptr
	for time.Now().Before(deadline) {
		r := int32(dll.call("pcap_next_ex", h, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data))))
		if r == 0 {
			continue // read-timeout, opnieuw
		}
		if r != 1 || hdr == 0 || data == 0 {
			continue
		}
		caplen := *(*uint32)(unsafe.Pointer(hdr + 8))
		if caplen < 42 || caplen > 65536 {
			continue
		}
		pkt := unsafe.Slice((*byte)(unsafe.Pointer(data)), caplen)
		mt, yi, sid, ok := parseDHCPFrame(pkt, xid)
		if !ok {
			continue
		}
		if mt == dhcpOffer || mt == dhcpAck {
			return dhcpResult{rtt: time.Since(start), yiaddr: yi, serverID: sid, msgType: mt, method: "Npcap"}, nil
		}
	}
	return dhcpResult{}, fmt.Errorf("geen antwoord binnen %s (Npcap L2 op %s)", o.timeout, label)
}

// parseDHCPFrame ontleedt een ruw Ethernet-frame en geeft het DHCP-antwoord terug
// als het een UDP 67→68 antwoord met ons xid is.
func parseDHCPFrame(f []byte, xid uint32) (msgType byte, yiaddr, serverID net.IP, ok bool) {
	if len(f) < 14+20+8 {
		return 0, nil, nil, false
	}
	if f[12] != 0x08 || f[13] != 0x00 { // IPv4?
		return 0, nil, nil, false
	}
	ihl := int(f[14]&0x0f) * 4
	if ihl < 20 || 14+ihl+8 > len(f) {
		return 0, nil, nil, false
	}
	if f[14+9] != 17 { // UDP?
		return 0, nil, nil, false
	}
	udp := 14 + ihl
	srcPort := binary.BigEndian.Uint16(f[udp:])
	dstPort := binary.BigEndian.Uint16(f[udp+2:])
	if srcPort != 67 || dstPort != 68 {
		return 0, nil, nil, false
	}
	payload := f[udp+8:]
	mt, yi, sid, valid := parseDHCP(payload)
	if !valid {
		return 0, nil, nil, false
	}
	if len(payload) < 8 || binary.BigEndian.Uint32(payload[4:8]) != xid {
		return 0, nil, nil, false
	}
	return mt, yi, sid, true
}

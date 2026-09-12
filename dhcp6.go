package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"
)

// DHCPv6 message types
const (
	dhcp6Solicit    = 1
	dhcp6Advertise  = 2
	dhcp6Reply      = 7
	dhcp6InfoReq    = 11
	dhcp6MulticastV = "ff02::1:2" // All_DHCP_Relay_Agents_and_Servers
	dhcp6ServerPort = 547
)

// pickV6Iface picks an interface (name/zone plus MAC) for DHCPv6.
func pickV6Iface(server, ifname string) (net.HardwareAddr, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "", err
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if ifname != "" && ifc.Name != ifname {
			continue
		}
		addrs, _ := ifc.Addrs()
		hasV6 := false
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() == nil && ipn.IP.To16() != nil {
				hasV6 = true
			}
		}
		if hasV6 && len(ifc.HardwareAddr) == 6 {
			return ifc.HardwareAddr, ifc.Name, nil
		}
	}
	if ifname != "" {
		return net.HardwareAddr{0x02, 0, 0x4e, 0x54, 0, 1}, ifname, nil
	}
	return nil, "", fmt.Errorf("no IPv6 interface found; pick one with an interface name")
}

func buildDHCPv6Inform(xid [3]byte, mac net.HardwareAddr) []byte {
	b := []byte{dhcp6InfoReq, xid[0], xid[1], xid[2]}
	// CLIENTID (1) with DUID-LL (type 3, hwtype 1 ethernet)
	duid := []byte{0, 3, 0, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}
	b = append(b, 0, 1, 0, byte(len(duid)))
	b = append(b, duid...)
	// ORO (6): request DNS servers (23)
	b = append(b, 0, 6, 0, 2, 0, 23)
	// ELAPSED_TIME (8)
	b = append(b, 0, 8, 0, 2, 0, 0)
	return b
}

// dhcpProbe6 measures the response time of a DHCPv6 server with an INFORMATION-REQUEST.
// NOT tested on this system.
func dhcpProbe6(o dhcpOpts) (dhcpResult, error) {
	mac, zone, err := pickV6Iface(o.server, o.iface)
	if err != nil {
		return dhcpResult{}, err
	}

	var xid [3]byte
	rand.Read(xid[:])
	packet := buildDHCPv6Inform(xid, mac)

	laddr := &net.UDPAddr{IP: net.IPv6unspecified, Port: o.port} // 0 = ephemeral
	conn, err := net.ListenUDP("udp6", laddr)
	if err != nil {
		return dhcpResult{}, fmt.Errorf("cannot open UDPv6 socket: %w", err)
	}
	defer conn.Close()

	var dst *net.UDPAddr
	if o.server != "" {
		sip, e := resolveIP(o.server, true)
		if e != nil {
			return dhcpResult{}, fmt.Errorf("cannot resolve DHCPv6 server %s: %w", o.server, e)
		}
		dst = &net.UDPAddr{IP: sip, Port: dhcp6ServerPort, Zone: zone}
	} else {
		dst = &net.UDPAddr{IP: net.ParseIP(dhcp6MulticastV), Port: dhcp6ServerPort, Zone: zone}
	}

	start := time.Now()
	if _, err := conn.WriteToUDP(packet, dst); err != nil {
		return dhcpResult{}, fmt.Errorf("sending: %w", err)
	}
	conn.SetReadDeadline(time.Now().Add(o.timeout))
	buf := make([]byte, 1500)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return dhcpResult{}, fmt.Errorf("no DHCPv6 answer within %s", o.timeout)
		}
		if n < 4 {
			continue
		}
		if buf[1] != xid[0] || buf[2] != xid[1] || buf[3] != xid[2] {
			continue // not our transaction id
		}
		if buf[0] == dhcp6Reply || buf[0] == dhcp6Advertise {
			mt := "REPLY"
			if buf[0] == dhcp6Advertise {
				mt = "ADVERTISE"
			}
			return dhcpResult{rtt: time.Since(start), serverID: raddr.IP, msgType: 0, info6: mt}, nil
		}
	}
}

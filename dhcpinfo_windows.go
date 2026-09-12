//go:build windows

package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Windows bewaart de actieve DHCP-lease per interface in het register. Dat is
// ingebouwd, leesbaar zonder Administrator en vereist geen capture-driver, dus
// het is de betrouwbaarste manier om te weten wélke DHCP-server ons bedient.
const (
	tcpipIfaces = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	netConnKey  = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`
)

// dhcpLease is de lease-informatie van één interface, zoals Windows die kent.
type dhcpLease struct {
	guid     string
	name     string // vriendelijke naam, bijv. "Ethernet"
	ip       net.IP
	server   net.IP
	gateway  net.IP
	dns      []net.IP
	obtained time.Time
	expires  time.Time
}

func (l dhcpLease) label() string {
	if l.name != "" {
		return l.name
	}
	return l.guid
}

// ifaceFriendlyName vertaalt een interface-GUID naar de naam die de gebruiker in
// Windows ziet. Faalt dat, dan geeft het een lege string terug.
func ifaceFriendlyName(guid string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, netConnKey+`\`+guid+`\Connection`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	name, _, err := k.GetStringValue("Name")
	if err != nil {
		return ""
	}
	return name
}

// parseIP4 leest een IPv4-adres uit een registerwaarde; lege of "0.0.0.0" telt niet.
func parseIP4(s string) net.IP {
	s = strings.TrimSpace(s)
	if s == "" || s == "0.0.0.0" {
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// dhcpLeases geeft alle interfaces met een actieve DHCP-lease, nieuwste eerst.
func dhcpLeases() ([]dhcpLease, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipIfaces, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("register openen: %w", err)
	}
	defer root.Close()

	guids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("interfaces lezen: %w", err)
	}

	var out []dhcpLease
	for _, guid := range guids {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipIfaces+`\`+guid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		enabled, _, _ := k.GetIntegerValue("EnableDHCP")
		srv, _, _ := k.GetStringValue("DhcpServer")
		l := dhcpLease{guid: guid, name: ifaceFriendlyName(guid), server: parseIP4(srv)}
		if enabled == 0 || l.server == nil {
			k.Close()
			continue
		}
		if v, _, err := k.GetStringValue("DhcpIPAddress"); err == nil {
			l.ip = parseIP4(v)
		}
		if v, _, err := k.GetStringValue("DhcpDefaultGateway"); err == nil {
			l.gateway = parseIP4(v)
		} else if vs, _, err := k.GetStringsValue("DhcpDefaultGateway"); err == nil && len(vs) > 0 {
			l.gateway = parseIP4(vs[0])
		}
		if v, _, err := k.GetStringValue("DhcpNameServer"); err == nil {
			for _, f := range strings.Fields(strings.ReplaceAll(v, ",", " ")) {
				if ip := parseIP4(f); ip != nil {
					l.dns = append(l.dns, ip)
				}
			}
		}
		if v, _, err := k.GetIntegerValue("LeaseObtainedTime"); err == nil && v != 0 {
			l.obtained = time.Unix(int64(v), 0)
		}
		if v, _, err := k.GetIntegerValue("LeaseTerminatesTime"); err == nil && v != 0 {
			l.expires = time.Unix(int64(v), 0)
		}
		k.Close()
		out = append(out, l)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("geen interface met een actieve DHCP-lease gevonden")
	}
	return out, nil
}

// leaseFor kiest de lease die hoort bij de gevraagde interface of bron-IP.
// Zonder voorkeur wint de lease waarvan het IP ook echt op een actieve
// interface zit, zodat een oude lease van een losgekoppelde adapter niet stoort.
func leaseFor(ifname string, srcIP net.IP) (dhcpLease, error) {
	leases, err := dhcpLeases()
	if err != nil {
		return dhcpLease{}, err
	}
	if srcIP != nil {
		for _, l := range leases {
			if l.ip != nil && l.ip.Equal(srcIP) {
				return l, nil
			}
		}
	}
	if ifname != "" {
		for _, l := range leases {
			if strings.EqualFold(l.name, ifname) || strings.Contains(strings.ToLower(l.name), strings.ToLower(ifname)) {
				return l, nil
			}
		}
	}
	// voorkeur voor een lease waarvan het IP op een actieve interface staat
	active := map[string]bool{}
	for _, ifc := range usableIPv4Ifaces() {
		active[ifc.ip.String()] = true
	}
	for _, l := range leases {
		if l.ip != nil && active[l.ip.String()] {
			return l, nil
		}
	}
	return leases[0], nil
}

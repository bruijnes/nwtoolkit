//go:build windows

package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Windows keeps the active DHCP lease per interface in the registry. That is
// built in, readable without Administrator and needs no capture driver, which makes
// it the most reliable way to learn which DHCP server is serving us.
const (
	tcpipIfaces = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	netConnKey  = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`
)

// dhcpLease is the lease information for one interface, as Windows knows it.
type dhcpLease struct {
	guid     string
	name     string // friendly name, e.g. "Ethernet"
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

// ifaceFriendlyName translates an interface GUID into the name the user sees in
// Windows. If that fails it returns an empty string.
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

// parseIP4 reads an IPv4 address from a registry value; empty or "0.0.0.0" does not count.
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

// dhcpLeases returns all interfaces holding an active DHCP lease, newest first.
func dhcpLeases() ([]dhcpLease, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipIfaces, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("opening registry: %w", err)
	}
	defer root.Close()

	guids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("reading interfaces: %w", err)
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
		return nil, fmt.Errorf("no interface with an active DHCP lease found")
	}
	return out, nil
}

// leaseFor picks the lease belonging to the requested interface or source IP.
// With no preference, the lease whose IP actually sits on an active interface wins,
// so a stale lease from a disconnected adapter does not get in the way.
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
	// prefer a lease whose IP is on an active interface
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

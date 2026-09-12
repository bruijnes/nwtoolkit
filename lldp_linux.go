//go:build linux

package main

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

type afpacketCap struct {
	fd     int
	devnam string
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func pickInterface(hint string) (*net.Interface, []string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	var list []string
	var chosen *net.Interface
	for i := range ifaces {
		ifc := ifaces[i]
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		up := ifc.Flags&net.FlagUp != 0
		desc := ifc.Name
		if up {
			desc += " (up)"
		}
		list = append(list, desc)
		if hint != "" {
			if ifc.Name == hint {
				chosen = &ifaces[i]
			}
			continue
		}
		if chosen == nil && up {
			if addrs, _ := ifc.Addrs(); len(addrs) > 0 {
				chosen = &ifaces[i]
			}
		}
	}
	return chosen, list, nil
}

func openLLDP(hint string) (capturer, []string, error) {
	ifc, list, err := pickInterface(hint)
	if err != nil {
		return nil, nil, err
	}
	if ifc == nil {
		return nil, list, fmt.Errorf("geen geschikte interface gevonden; kies er een met -i <naam> (zie -l)")
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(lldpEtherType)))
	if err != nil {
		return nil, list, fmt.Errorf("raw socket openen (root nodig): %w", err)
	}
	ll := unix.SockaddrLinklayer{Protocol: htons(lldpEtherType), Ifindex: ifc.Index}
	if err := unix.Bind(fd, &ll); err != nil {
		unix.Close(fd)
		return nil, list, fmt.Errorf("bind op %s: %w", ifc.Name, err)
	}
	return &afpacketCap{fd: fd, devnam: ifc.Name}, list, nil
}

func (c *afpacketCap) device() string { return c.devnam }
func (c *afpacketCap) close()         { unix.Close(c.fd) }

func (c *afpacketCap) next(timeout time.Duration) ([]byte, error) {
	tv := unix.NsecToTimeval(int64(timeout))
	unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	buf := make([]byte, 2048)
	n, _, err := unix.Recvfrom(c.fd, buf, 0)
	if err != nil {
		return nil, err
	}
	// AF_PACKET SOCK_RAW levert het frame ZONDER de 14-byte ethernetheader op de meeste
	// setups mét — afhankelijk van kernel. We krijgen hier het volledige frame inclusief header.
	return buf[:n], nil
}

// Geen pktmon op Linux.
func tryPktmon(o lldpOpts) error { return errPktmonUnsupported }

func pktmonCollect(wait time.Duration) (map[string]*lldpNeighbor, error) {
	return nil, errPktmonUnsupported
}

//go:build windows

package main

import (
	"context"
	"net"
	"syscall"
)

// dhcpListen opens a UDP socket for DHCP. SO_REUSEADDR lets port 68 be shared with
// the Windows DHCP Client service; SO_BROADCAST is needed to be allowed to send to
// 255.255.255.255.
func dhcpListen(laddr *net.UDPAddr, broadcast bool) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			c.Control(func(fd uintptr) {
				h := syscall.Handle(fd)
				syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if broadcast {
					syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
				}
			})
			return nil
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", laddr.String())
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

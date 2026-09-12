//go:build !windows

package main

import (
	"context"
	"net"
	"syscall"
)

// dhcpListen opent een UDP-socket voor DHCP met SO_REUSEADDR en (bij broadcast)
// SO_BROADCAST.
func dhcpListen(laddr *net.UDPAddr, broadcast bool) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if broadcast {
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
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

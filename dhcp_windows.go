//go:build windows

package main

import (
	"context"
	"net"
	"syscall"
)

// dhcpListen opent een UDP-socket voor DHCP. Met SO_REUSEADDR kan poort 68 gedeeld
// worden met de Windows DHCP-Clientservice; SO_BROADCAST is nodig om naar
// 255.255.255.255 te mogen zenden.
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

//go:build !windows

package main

import (
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ipSuccess           = 0
	ipReqTimedOut       = 11010
	ipTTLExpiredTransit = 11013
)

func ipStatusText(s uint32) string {
	switch s {
	case ipSuccess:
		return "ok"
	case ipReqTimedOut:
		return "timeout"
	case ipTTLExpiredTransit:
		return "ttl-expired"
	default:
		return "error"
	}
}

type icmpHandle struct{}

func icmpOpen() (icmpHandle, error) { return icmpHandle{}, nil }
func (icmpHandle) close()           {}

var echoSeq int

func (icmpHandle) echo(dst net.IP, ttl int, timeout time.Duration, payload []byte) (net.IP, time.Duration, uint32, error) {
	if dst.To4() == nil {
		return echo6(dst, ttl, timeout, payload)
	}
	var dstAddr net.Addr = &net.UDPAddr{IP: dst}
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		c, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return nil, 0, 0, err
		}
		dstAddr = &net.IPAddr{IP: dst}
	}
	defer c.Close()
	if ttl > 0 {
		c.IPv4PacketConn().SetTTL(ttl)
	}
	echoSeq++
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: echoSeq, Data: payload}}
	b, _ := msg.Marshal(nil)
	start := time.Now()
	if _, err := c.WriteTo(b, dstAddr); err != nil {
		return nil, 0, 0, err
	}
	c.SetReadDeadline(time.Now().Add(timeout))
	rb := make([]byte, 1500)
	n, peer, err := c.ReadFrom(rb)
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, ipReqTimedOut, nil
	}
	peerIP := addrIP(peer)
	rm, err := icmp.ParseMessage(1, rb[:n])
	if err != nil {
		return peerIP, rtt, 0, nil
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return peerIP, rtt, ipSuccess, nil
	case ipv4.ICMPTypeTimeExceeded:
		return peerIP, rtt, ipTTLExpiredTransit, nil
	default:
		return peerIP, rtt, 11003, nil
	}
}

func echo6(dst net.IP, ttl int, timeout time.Duration, payload []byte) (net.IP, time.Duration, uint32, error) {
	var dstAddr net.Addr = &net.UDPAddr{IP: dst}
	c, err := icmp.ListenPacket("udp6", "::")
	if err != nil {
		c, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			return nil, 0, 0, err
		}
		dstAddr = &net.IPAddr{IP: dst}
	}
	defer c.Close()
	if ttl > 0 {
		c.IPv6PacketConn().SetHopLimit(ttl)
	}
	echoSeq++
	msg := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: echoSeq, Data: payload}}
	b, _ := msg.Marshal(nil)
	start := time.Now()
	if _, err := c.WriteTo(b, dstAddr); err != nil {
		return nil, 0, 0, err
	}
	c.SetReadDeadline(time.Now().Add(timeout))
	rb := make([]byte, 1500)
	n, peer, err := c.ReadFrom(rb)
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, ipReqTimedOut, nil
	}
	peerIP := addrIP(peer)
	rm, err := icmp.ParseMessage(58, rb[:n]) // 58 = IPv6-ICMP
	if err != nil {
		return peerIP, rtt, 0, nil
	}
	switch rm.Type {
	case ipv6.ICMPTypeEchoReply:
		return peerIP, rtt, ipSuccess, nil
	case ipv6.ICMPTypeTimeExceeded:
		return peerIP, rtt, ipTTLExpiredTransit, nil
	default:
		return peerIP, rtt, 11003, nil
	}
}

func addrIP(a net.Addr) net.IP {
	switch p := a.(type) {
	case *net.UDPAddr:
		return p.IP
	case *net.IPAddr:
		return p.IP
	}
	return nil
}

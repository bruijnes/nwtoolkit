//go:build windows

package main

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi           = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreate     = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose      = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2  = iphlpapi.NewProc("IcmpSendEcho2")
	procIcmp6Create    = iphlpapi.NewProc("Icmp6CreateFile")
	procIcmp6SendEcho2 = iphlpapi.NewProc("Icmp6SendEcho2")
)

// sockaddr_in6 (Windows), 28 bytes.
type sockaddrIn6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

const afInet6 = 23

var icmp6Handle uintptr

// localV6 determines a local IPv6 source address to reach dst (:: if that fails).
func localV6(dst net.IP) [16]byte {
	var a [16]byte
	c, err := net.Dial("udp6", "["+dst.String()+"]:9")
	if err == nil {
		defer c.Close()
		if u, ok := c.LocalAddr().(*net.UDPAddr); ok {
			copy(a[:], u.IP.To16())
		}
	}
	return a
}

// echo6win sends one ICMPv6 echo via Icmp6SendEcho2 (NOT tested on this system).
func echo6win(dst net.IP, ttl int, timeout time.Duration, payload []byte) (net.IP, time.Duration, uint32, error) {
	if icmp6Handle == 0 {
		h, _, err := procIcmp6Create.Call()
		if h == 0 || h == uintptr(^uintptr(0)) {
			return nil, 0, 0, fmt.Errorf("Icmp6CreateFile: %v", err)
		}
		icmp6Handle = h
	}
	src := sockaddrIn6{Family: afInet6, Addr: localV6(dst)}
	dstA := sockaddrIn6{Family: afInet6}
	copy(dstA.Addr[:], dst.To16())

	opt := ipOptionInformation{TTL: uint8(ttl)}
	replySize := 96 + len(payload)
	reply := make([]byte, replySize)
	var reqData uintptr
	if len(payload) > 0 {
		reqData = uintptr(unsafe.Pointer(&payload[0]))
	}

	start := time.Now()
	ret, _, _ := procIcmp6SendEcho2.Call(
		icmp6Handle, 0, 0, 0,
		uintptr(unsafe.Pointer(&src)),
		uintptr(unsafe.Pointer(&dstA)),
		reqData,
		uintptr(uint16(len(payload))),
		uintptr(unsafe.Pointer(&opt)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(replySize),
		uintptr(uint32(timeout.Milliseconds())),
	)
	rtt := time.Since(start)
	if ret == 0 {
		return nil, rtt, ipReqTimedOut, nil
	}
	// ICMPV6_ECHO_REPLY: IPV6_ADDRESS_EX (packed) sin6_addr at offset 6 (16 bytes), Status at offset 26.
	var addr [16]byte
	copy(addr[:], reply[6:22])
	status := *(*uint32)(unsafe.Pointer(&reply[26]))
	return net.IP(append([]byte(nil), addr[:]...)), rtt, status, nil
}

// IP_OPTION_INFORMATION (x64 layout, 8-byte aligned pointer)
type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	_           [4]byte // padding to align pointer on 8
	OptionsData uintptr
}

// ICMP_ECHO_REPLY (x64)
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	_             [4]byte // padding before pointer
	Data          uintptr
	Options       ipOptionInformation
}

// Windows ICMP status codes we care about
const (
	ipSuccess           = 0
	ipReqTimedOut       = 11010
	ipTTLExpiredTransit = 11013
)

func ipStatusText(s uint32) string {
	switch s {
	case ipSuccess:
		return "ok"
	case 11002:
		return "net unreachable"
	case 11003:
		return "host unreachable"
	case 11004:
		return "protocol unreachable"
	case 11005:
		return "port unreachable"
	case ipReqTimedOut:
		return "timeout"
	case ipTTLExpiredTransit:
		return "ttl-expired"
	default:
		return fmt.Sprintf("status %d", s)
	}
}

type icmpHandle uintptr

func icmpOpen() (icmpHandle, error) {
	h, _, err := procIcmpCreate.Call()
	if h == uintptr(^uintptr(0)) || h == 0 {
		return 0, fmt.Errorf("IcmpCreateFile: %v", err)
	}
	return icmpHandle(h), nil
}

func (h icmpHandle) close() { procIcmpClose.Call(uintptr(h)) }

// echo sends one ICMP echo to dst (IPv4) with the given TTL and timeout.
// Returns: responder IP, RTT, Windows status, err (err only on API errors).
func (h icmpHandle) echo(dst net.IP, ttl int, timeout time.Duration, payload []byte) (net.IP, time.Duration, uint32, error) {
	v4 := dst.To4()
	if v4 == nil {
		return echo6win(dst, ttl, timeout, payload)
	}
	destAddr := uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24

	opt := ipOptionInformation{TTL: uint8(ttl)}
	replySize := int(unsafe.Sizeof(icmpEchoReply{})) + len(payload) + 8
	reply := make([]byte, replySize)

	var reqData uintptr
	if len(payload) > 0 {
		reqData = uintptr(unsafe.Pointer(&payload[0]))
	}

	start := time.Now()
	ret, _, _ := procIcmpSendEcho2.Call(
		uintptr(h),
		0, 0, 0,
		uintptr(destAddr),
		reqData,
		uintptr(uint16(len(payload))),
		uintptr(unsafe.Pointer(&opt)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(replySize),
		uintptr(uint32(timeout.Milliseconds())),
	)
	rtt := time.Since(start)

	if ret == 0 {
		// No replies. GetLastError gives the reason, e.g. a timeout.
		return nil, rtt, ipReqTimedOut, nil
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	ip := net.IPv4(byte(r.Address), byte(r.Address>>8), byte(r.Address>>16), byte(r.Address>>24))
	// Use wall-clock RTT; better resolution than the millisecond counter from Windows.
	return ip, rtt, r.Status, nil
}

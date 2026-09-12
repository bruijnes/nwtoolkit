//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var procGetNetworkParams = iphlpapi.NewProc("GetNetworkParams")

// systemDNS haalt de primaire DNS-server op via GetNetworkParams (FIXED_INFO).
func systemDNS() string {
	var size uint32
	// eerste call: benodigde buffergrootte
	procGetNetworkParams.Call(0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		size = 2048
	}
	buf := make([]byte, size)
	ret, _, _ := procGetNetworkParams.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret != 0 {
		return ""
	}
	// DnsServerList.IpAddress.String staat op offset 280 (x64), 16-byte C-string
	const off = 280
	if len(buf) < off+16 {
		return ""
	}
	s := buf[off : off+16]
	n := 0
	for n < len(s) && s[n] != 0 {
		n++
	}
	return string(s[:n])
}

var _ = syscall.Handle(0)

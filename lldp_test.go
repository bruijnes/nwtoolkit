package main

import "testing"

// bouwt een LLDP-frame met de gegeven TLV's (na de 14-byte ethernetheader).
func lldpFrame(tlvs ...[]byte) []byte {
	f := make([]byte, 14)
	f[12], f[13] = 0x88, 0xcc
	for _, t := range tlvs {
		f = append(f, t...)
	}
	return f
}

func tlv(typ byte, val []byte) []byte {
	l := len(val)
	b := []byte{typ<<1 | byte(l>>8&1), byte(l & 0xff)}
	return append(b, val...)
}

func TestParseLLDP(t *testing.T) {
	chassis := tlv(1, append([]byte{4}, 0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc)) // MAC
	port := tlv(2, append([]byte{5}, []byte("GigabitEthernet0/1")...))       // interface name
	ttl := tlv(3, []byte{0, 120})
	sysname := tlv(5, []byte("sw-core-01"))
	vlan := tlv(127, append([]byte{0x00, 0x80, 0xc2, 0x01}, 0x00, 0x64)) // 802.1 Port VLAN ID = 100
	end := tlv(0, nil)

	frame := lldpFrame(chassis, port, ttl, sysname, vlan, end)
	n, ok := parseLLDP(frame)
	if !ok {
		t.Fatal("parse mislukt")
	}
	if n.ChassisID != "00:0c:29:aa:bb:cc" {
		t.Errorf("chassis=%q", n.ChassisID)
	}
	if n.PortID != "GigabitEthernet0/1" {
		t.Errorf("port=%q", n.PortID)
	}
	if n.SysName != "sw-core-01" {
		t.Errorf("sysname=%q", n.SysName)
	}
	if n.TTL != 120 {
		t.Errorf("ttl=%d", n.TTL)
	}
	if n.VLAN != 100 {
		t.Errorf("vlan=%d", n.VLAN)
	}
}

func TestParseLLDPRejectsNonLLDP(t *testing.T) {
	f := make([]byte, 60)
	f[12], f[13] = 0x08, 0x00 // IPv4
	if _, ok := parseLLDP(f); ok {
		t.Error("niet-LLDP-frame werd toch geparsed")
	}
}

func TestParsePcapng(t *testing.T) {
	le := func(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
	// LLDP-frame (minimaal): eth-header + 1 sysname-TLV + end
	frame := lldpFrame(tlv(5, []byte("sw-test")), tlv(0, nil))
	// pad naar 32-bit
	pad := (4 - len(frame)%4) % 4
	padded := append(append([]byte{}, frame...), make([]byte, pad)...)

	var b []byte
	// Section Header Block: type(4)+len(4)+magic(4)+major(2)+minor(2)+sectionlen(8)+len(4) = 28
	shb := append([]byte{}, le(0x0A0D0D0A)...)
	shb = append(shb, le(28)...)
	shb = append(shb, le(0x1A2B3C4D)...)                              // byte-order magic
	shb = append(shb, 1, 0, 0, 0)                                     // major=1 minor=0
	shb = append(shb, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) // section length = -1 (8 bytes)
	shb = append(shb, le(28)...)                                      // total length herhaald
	b = append(b, shb...)

	// Enhanced Packet Block
	epbLen := 32 + len(padded)
	epb := append([]byte{}, le(0x00000006)...)
	epb = append(epb, le(uint32(epbLen))...)
	epb = append(epb, le(0)...)                  // interface id
	epb = append(epb, le(0)...)                  // ts high
	epb = append(epb, le(0)...)                  // ts low
	epb = append(epb, le(uint32(len(frame)))...) // captured len
	epb = append(epb, le(uint32(len(frame)))...) // original len
	epb = append(epb, padded...)
	epb = append(epb, le(uint32(epbLen))...) // total length herhaald
	b = append(b, epb...)

	frames := parsePcapng(b)
	if len(frames) != 1 {
		t.Fatalf("verwachtte 1 frame, kreeg %d", len(frames))
	}
	nb, ok := parseLLDP(frames[0])
	if !ok || nb.SysName != "sw-test" {
		t.Fatalf("frame niet correct geparsed: ok=%v nb=%+v", ok, nb)
	}
}

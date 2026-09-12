package main

import "testing"

// builds an LLDP frame with the given TLVs, after the 14-byte Ethernet header.
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
		t.Fatal("parse failed")
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
		t.Error("non-LLDP frame was parsed anyway")
	}
}

func TestParsePcapng(t *testing.T) {
	le := func(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
	// minimal LLDP frame: Ethernet header + one sysname TLV + end
	frame := lldpFrame(tlv(5, []byte("sw-test")), tlv(0, nil))
	// path to 32-bit
	pad := (4 - len(frame)%4) % 4
	padded := append(append([]byte{}, frame...), make([]byte, pad)...)

	var b []byte
	// Section Header Block: type(4)+len(4)+magic(4)+major(2)+minor(2)+sectionlen(8)+len(4) = 28
	shb := append([]byte{}, le(0x0A0D0D0A)...)
	shb = append(shb, le(28)...)
	shb = append(shb, le(0x1A2B3C4D)...)                              // byte-order magic
	shb = append(shb, 1, 0, 0, 0)                                     // major=1 minor=0
	shb = append(shb, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) // section length = -1 (8 bytes)
	shb = append(shb, le(28)...)                                      // total length repeated
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
	epb = append(epb, le(uint32(epbLen))...) // total length repeated
	b = append(b, epb...)

	frames := parsePcapng(b)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	nb, ok := parseLLDP(frames[0])
	if !ok || nb.SysName != "sw-test" {
		t.Fatalf("frame not parsed correctly: ok=%v nb=%+v", ok, nb)
	}
}

// pcapngBuilder assembles the minimum pcapng structure the parser needs: a Section
// Header Block, optional Interface Description Blocks and Enhanced Packet Blocks.
type pcapngBuilder struct{ b []byte }

func le32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func (p *pcapngBuilder) section() {
	blk := append([]byte{}, le32(0x0A0D0D0A)...)
	blk = append(blk, le32(28)...)
	blk = append(blk, le32(0x1A2B3C4D)...)
	blk = append(blk, 1, 0, 0, 0)
	blk = append(blk, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
	blk = append(blk, le32(28)...)
	p.b = append(p.b, blk...)
}

// iface adds an Interface Description Block. A tsresol below zero omits the
// if_tsresol option, so the parser has to fall back to its microsecond default.
func (p *pcapngBuilder) iface(tsresol int) {
	body := []byte{1, 0, 0, 0, 0, 0, 4, 0} // linktype ethernet, reserved, snaplen
	if tsresol >= 0 {
		body = append(body, 9, 0, 1, 0, byte(tsresol), 0, 0, 0) // option code 9, len 1, value + padding
		body = append(body, 0, 0, 0, 0)                         // opt_endofopt
	}
	total := uint32(12 + len(body))
	blk := append([]byte{}, le32(0x00000001)...)
	blk = append(blk, le32(total)...)
	blk = append(blk, body...)
	blk = append(blk, le32(total)...)
	p.b = append(p.b, blk...)
}

func (p *pcapngBuilder) packet(ifi uint32, tsHigh, tsLow uint32, payload []byte) {
	pad := (4 - len(payload)%4) % 4
	body := append([]byte{}, le32(ifi)...)
	body = append(body, le32(tsHigh)...)
	body = append(body, le32(tsLow)...)
	body = append(body, le32(uint32(len(payload)))...)
	body = append(body, le32(uint32(len(payload)))...)
	body = append(body, payload...)
	body = append(body, make([]byte, pad)...)
	total := uint32(12 + len(body))
	blk := append([]byte{}, le32(0x00000006)...)
	blk = append(blk, le32(total)...)
	blk = append(blk, body...)
	blk = append(blk, le32(total)...)
	p.b = append(p.b, blk...)
}

// TestParsePcapngTSResolution covers the timestamp scaling, which is what turns a
// capture into a response time. Getting the if_tsresol option wrong silently skews
// every DHCP measurement taken through pktmon.
func TestParsePcapngTSResolution(t *testing.T) {
	payload := lldpFrame(tlv(5, []byte("sw-test")), tlv(0, nil))

	cases := []struct {
		name    string
		tsresol int
		ts      uint32
		want    int64
	}{
		{"nanoseconds", 9, 123456789, 123456789},
		{"microseconds", 6, 1000, 1000 * 1000},
		{"milliseconds", 3, 5, 5 * 1000000},
		{"default is microseconds", -1, 2500, 2500 * 1000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var p pcapngBuilder
			p.section()
			p.iface(c.tsresol)
			p.packet(0, 0, c.ts, payload)

			frames := parsePcapngTS(p.b)
			if len(frames) != 1 {
				t.Fatalf("expected 1 frame, got %d", len(frames))
			}
			if frames[0].tsNanos != c.want {
				t.Errorf("tsNanos = %d, want %d", frames[0].tsNanos, c.want)
			}
			if string(frames[0].data) != string(payload) {
				t.Errorf("frame payload does not match")
			}
		})
	}
}

// TestParsePcapngTSPerInterface checks that each packet uses the resolution of its
// own interface, since pktmon writes several interfaces into one capture.
func TestParsePcapngTSPerInterface(t *testing.T) {
	payload := lldpFrame(tlv(0, nil))
	var p pcapngBuilder
	p.section()
	p.iface(9) // interface 0: nanoseconds
	p.iface(3) // interface 1: milliseconds
	p.packet(0, 0, 1000, payload)
	p.packet(1, 0, 1000, payload)

	frames := parsePcapngTS(p.b)
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if frames[0].tsNanos != 1000 {
		t.Errorf("interface 0: tsNanos = %d, want 1000", frames[0].tsNanos)
	}
	if frames[1].tsNanos != 1000*1000000 {
		t.Errorf("interface 1: tsNanos = %d, want %d", frames[1].tsNanos, 1000*1000000)
	}
}

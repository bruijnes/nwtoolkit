package main

import "encoding/binary"

// pcapFrame is een opgevangen frame met een tijdstempel in nanoseconden sinds epoch.
type pcapFrame struct {
	tsNanos int64
	data    []byte
}

func pow10i(n int) int64 {
	r := int64(1)
	for i := 0; i < n; i++ {
		r *= 10
	}
	return r
}

// parsePcapngTS is als parsePcapng maar geeft ook per-pakket tijdstempels terug,
// rekening houdend met de if_tsresol-optie per interface (default microseconden).
func parsePcapngTS(data []byte) []pcapFrame {
	le := binary.LittleEndian
	var nanosPerTick []int64 // per interface-index
	var out []pcapFrame
	i := 0
	for i+8 <= len(data) {
		btype := le.Uint32(data[i:])
		blen := int(le.Uint32(data[i+4:]))
		if blen < 12 || i+blen > len(data) {
			break
		}
		body := data[i+8 : i+blen-4]
		switch btype {
		case 0x00000001: // Interface Description Block
			npt := int64(1000) // default: microseconden → 1000 ns/tick
			if len(body) >= 8 {
				opts := body[8:]
				for len(opts) >= 4 {
					code := le.Uint16(opts[0:])
					l := int(le.Uint16(opts[2:]))
					if code == 0 || 4+l > len(opts) {
						break
					}
					if code == 9 && l >= 1 {
						r := opts[4]
						if r&0x80 == 0 {
							npt = pow10i(9 - int(r))
						} else {
							npt = int64(1000000000) >> uint(r&0x7f)
						}
						if npt < 1 {
							npt = 1
						}
					}
					opts = opts[4+((l+3)&^3):]
				}
			}
			nanosPerTick = append(nanosPerTick, npt)
		case 0x00000006: // Enhanced Packet Block
			if len(body) >= 20 {
				ifi := int(le.Uint32(body[0:]))
				tsHigh := uint64(le.Uint32(body[4:]))
				tsLow := uint64(le.Uint32(body[8:]))
				capLen := int(le.Uint32(body[12:]))
				if 20+capLen <= len(body) {
					npt := int64(1000)
					if ifi >= 0 && ifi < len(nanosPerTick) {
						npt = nanosPerTick[ifi]
					}
					frame := make([]byte, capLen)
					copy(frame, body[20:20+capLen])
					out = append(out, pcapFrame{tsNanos: int64(tsHigh<<32|tsLow) * npt, data: frame})
				}
			}
		}
		i += blen
	}
	return out
}

// parsePcapng haalt de ruwe pakketframes uit een pcapng-bestand (zoals pktmon dat schrijft).
// Ondersteunt Enhanced Packet Block (0x06) en Simple Packet Block (0x03), little-endian.
func parsePcapng(data []byte) [][]byte {
	var frames [][]byte
	le := binary.LittleEndian
	i := 0
	for i+8 <= len(data) {
		btype := le.Uint32(data[i:])
		blen := int(le.Uint32(data[i+4:]))
		if blen < 12 || i+blen > len(data) {
			break
		}
		body := data[i+8 : i+blen-4]
		switch btype {
		case 0x00000006: // Enhanced Packet Block
			// interface(4) tsHigh(4) tsLow(4) capLen(4) origLen(4) data...
			if len(body) >= 20 {
				capLen := int(le.Uint32(body[12:]))
				if 20+capLen <= len(body) {
					frame := make([]byte, capLen)
					copy(frame, body[20:20+capLen])
					frames = append(frames, frame)
				}
			}
		case 0x00000003: // Simple Packet Block
			// origLen(4) data...
			if len(body) >= 4 {
				origLen := int(le.Uint32(body[0:]))
				if 4+origLen <= len(body) {
					frame := make([]byte, origLen)
					copy(frame, body[4:4+origLen])
					frames = append(frames, frame)
				}
			}
		}
		i += blen
	}
	return frames
}

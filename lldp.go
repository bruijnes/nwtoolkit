package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"
)

// LLDP EtherType and multicast destination.
const lldpEtherType = 0x88cc

// errNoLiveCapture means this platform has no live layer-2 capture, in which case
// the built-in pktmon route is used (Windows only).
var errNoLiveCapture = errors.New("this platform has no live layer-2 capture; the built-in pktmon is used (Administrator required)")

// errPktmonUnsupported: no pktmon fallback on this platform.
var errPktmonUnsupported = errors.New("pktmon not available on this platform")

// lldpNeighbor holds the decoded fields of one LLDP neighbour (the switch and port on the other end).
type lldpNeighbor struct {
	ChassisID string
	PortID    string
	PortDesc  string
	SysName   string
	SysDesc   string
	TTL       int
	MgmtAddr  string
	Caps      string
	VLAN      int
	localIf   string
	lastSeen  time.Time
}

func (n lldpNeighbor) key() string { return n.ChassisID + "|" + n.PortID }

// capturer is the platform-specific layer-2 capture (Linux AF_PACKET; Windows uses pktmon).
type capturer interface {
	next(timeout time.Duration) (frame []byte, err error)
	device() string
	close()
}

// parseLLDP decodes a complete Ethernet frame, including the 14-byte header, into a neighbour.
func parseLLDP(frame []byte) (*lldpNeighbor, bool) {
	if len(frame) < 14 {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != lldpEtherType {
		return nil, false
	}
	n := &lldpNeighbor{}
	p := frame[14:]
	i := 0
	for i+2 <= len(p) {
		t := p[i] >> 1
		l := int(p[i]&1)<<8 | int(p[i+1])
		i += 2
		if t == 0 { // End of LLDPDU
			break
		}
		if i+l > len(p) {
			break
		}
		v := p[i : i+l]
		i += l
		switch t {
		case 1: // Chassis ID
			n.ChassisID = decodeChassisID(v)
		case 2: // Port ID
			n.PortID = decodePortID(v)
		case 3: // TTL
			if len(v) >= 2 {
				n.TTL = int(binary.BigEndian.Uint16(v))
			}
		case 4: // Port description
			n.PortDesc = string(v)
		case 5: // System name
			n.SysName = string(v)
		case 6: // System description
			n.SysDesc = string(v)
		case 7: // Capabilities
			n.Caps = decodeCaps(v)
		case 8: // Management address
			n.MgmtAddr = decodeMgmtAddr(v)
		case 127: // Organizationally specific
			decodeOrg(v, n)
		}
	}
	if n.ChassisID == "" && n.PortID == "" && n.SysName == "" {
		return nil, false
	}
	n.lastSeen = time.Now()
	return n, true
}

func decodeMAC(b []byte) string {
	if len(b) != 6 {
		return hexColon(b)
	}
	return net.HardwareAddr(b).String()
}

func hexColon(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

func decodeChassisID(v []byte) string {
	if len(v) < 2 {
		return ""
	}
	sub, val := v[0], v[1:]
	switch sub {
	case 4: // MAC address
		return decodeMAC(val)
	case 5: // network address
		return decodeNetAddr(val)
	case 7: // locally assigned
		return string(val)
	default:
		return string(val)
	}
}

func decodePortID(v []byte) string {
	if len(v) < 2 {
		return ""
	}
	sub, val := v[0], v[1:]
	switch sub {
	case 3: // MAC address
		return decodeMAC(val)
	case 4: // network address
		return decodeNetAddr(val)
	case 1, 2, 5, 7: // alias / port comp / interface name / locally assigned
		return string(val)
	default:
		return string(val)
	}
}

func decodeNetAddr(v []byte) string {
	if len(v) >= 5 && v[0] == 1 { // IPv4
		return net.IP(v[1:5]).String()
	}
	if len(v) >= 17 && v[0] == 2 { // IPv6
		return net.IP(v[1:17]).String()
	}
	return hexColon(v)
}

func decodeMgmtAddr(v []byte) string {
	if len(v) < 2 {
		return ""
	}
	addrLen := int(v[0])
	if addrLen < 1 || 1+addrLen > len(v) {
		return ""
	}
	subtype := v[1]
	addr := v[2 : 1+addrLen]
	switch subtype {
	case 1:
		if len(addr) == 4 {
			return net.IP(addr).String()
		}
	case 2:
		if len(addr) == 16 {
			return net.IP(addr).String()
		}
	}
	return hexColon(addr)
}

func decodeCaps(v []byte) string {
	if len(v) < 4 {
		return ""
	}
	enabled := binary.BigEndian.Uint16(v[2:4])
	names := []struct {
		bit  uint16
		name string
	}{
		{1 << 0, "Other"}, {1 << 1, "Repeater"}, {1 << 2, "Bridge"},
		{1 << 3, "WLAN-AP"}, {1 << 4, "Router"}, {1 << 5, "Telephone"},
		{1 << 6, "DOCSIS"}, {1 << 7, "Station"},
	}
	var out []string
	for _, c := range names {
		if enabled&c.bit != 0 {
			out = append(out, c.name)
		}
	}
	return strings.Join(out, ", ")
}

// decodeOrg reads organisation-specific TLVs, notably the IEEE 802.1 Port VLAN ID.
func decodeOrg(v []byte, n *lldpNeighbor) {
	if len(v) < 4 {
		return
	}
	oui := [3]byte{v[0], v[1], v[2]}
	sub := v[3]
	body := v[4:]
	// IEEE 802.1: OUI 00-80-c2
	if oui == [3]byte{0x00, 0x80, 0xc2} {
		switch sub {
		case 1: // Port VLAN ID
			if len(body) >= 2 {
				n.VLAN = int(binary.BigEndian.Uint16(body))
			}
		case 3: // VLAN name: [vlanid(2)][len(1)][name]
			if len(body) >= 3 && n.VLAN == 0 {
				n.VLAN = int(binary.BigEndian.Uint16(body))
			}
		}
	}
}

func (n lldpNeighbor) printBlock() {
	line := func(label, val string) {
		if val != "" {
			fmt.Printf("  %-16s %s\n", label+":", val)
		}
	}
	fmt.Println(col(cBold, "  LLDP neighbour (connected device):"))
	line("System name", col(cCyan, n.SysName))
	line("Port", col(cGreen, n.PortID))
	line("Port descr.", n.PortDesc)
	if n.VLAN > 0 {
		line("VLAN", fmt.Sprintf("%d", n.VLAN))
	}
	line("Chassis ID", n.ChassisID)
	line("Mgmt address", n.MgmtAddr)
	line("Capabilities", n.Caps)
	if n.TTL > 0 {
		line("TTL", fmt.Sprintf("%d s", n.TTL))
	}
	if n.localIf != "" {
		line("Local port", n.localIf)
	}
	if n.SysDesc != "" {
		fmt.Printf("  %-16s %s\n", "System info:", firstLine(n.SysDesc))
	}
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i] + " …"
	}
	if len(s) > 120 {
		return s[:120] + " …"
	}
	return s
}

type lldpOpts struct {
	iface   string
	wait    time.Duration
	monitor bool
	list    bool
}

func cmdLLDP(o lldpOpts) {
	cap, devs, err := openLLDP(o.iface)
	if o.list {
		if len(devs) == 0 {
			fmt.Println("no interfaces found.")
		}
		fmt.Println("Available interfaces:")
		for _, d := range devs {
			fmt.Println("  " + d)
		}
		if cap != nil {
			cap.close()
		}
		return
	}
	if err != nil {
		// No live capture? Use the built-in pktmon route (Windows).
		if errors.Is(err, errNoLiveCapture) {
			perr := tryPktmon(o)
			if perr == nil {
				return
			}
			if !errors.Is(perr, errPktmonUnsupported) {
				die("%v", perr)
			}
		}
		die("%v", err)
	}
	defer cap.close()

	fmt.Printf("%s  listening on %s for LLDP frames…\n", col(cBold, "nwtoolkit"), col(cCyan, cap.device()))
	fmt.Println(col(cGrey, "LLDP is usually sent every 30 s, so this may take a while. Ctrl+C to stop."))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	stop := make(chan struct{})
	go func() { <-sig; close(stop) }()

	neighbors := map[string]*lldpNeighbor{}
	deadline := time.Now().Add(o.wait)

	for {
		select {
		case <-stop:
			finishLLDP(neighbors)
			return
		default:
		}
		if !o.monitor && time.Now().After(deadline) && len(neighbors) == 0 {
			fmt.Println(col(cYellow, "\nNo LLDP frames received within the wait time."))
			fmt.Println(col(cGrey, "LLDP may be disabled on the switch, or it is an unmanaged switch. (On Windows: run as Administrator.)"))
			return
		}

		frame, err := cap.next(1 * time.Second)
		if err != nil {
			continue
		}
		nb, ok := parseLLDP(frame)
		if !ok {
			continue
		}
		nb.localIf = cap.device()
		_, existed := neighbors[nb.key()]
		neighbors[nb.key()] = nb

		if o.monitor {
			drawLLDP(neighbors)
		} else if !existed {
			fmt.Println()
			nb.printBlock()
			// one-shot: stop as soon as we have a neighbour
			return
		}
	}
}

func drawLLDP(neighbors map[string]*lldpNeighbor) {
	fmt.Print(clrScr)
	fmt.Printf("%s  LLDP monitor   %d neighbour(s)   Ctrl+C to stop\n", col(cBold, "nwtoolkit"), len(neighbors))
	for _, n := range sortedNeighbors(neighbors) {
		fmt.Println()
		n.printBlock()
		fmt.Printf("  %-16s %s\n", "Last seen:", n.lastSeen.Format("15:04:05"))
	}
}

func finishLLDP(neighbors map[string]*lldpNeighbor) {
	fmt.Printf("\n%d LLDP neighbour(s) seen.\n", len(neighbors))
}

// lldpOnce captures LLDP neighbours until the first one is seen or wait elapses.
// Used by the web UI.
func lldpOnce(hint string, wait time.Duration) ([]*lldpNeighbor, string, error) {
	cap, _, err := openLLDP(hint)
	if err != nil {
		// No live capture? Fall back to the built-in pktmon (Windows, Administrator).
		if errors.Is(err, errNoLiveCapture) {
			nbs, perr := pktmonCollect(wait)
			if perr == nil {
				return sortedNeighbors(nbs), "pktmon", nil
			}
			if errors.Is(perr, errPktmonUnsupported) {
				return nil, "", err
			}
			return nil, "", perr
		}
		return nil, "", err
	}
	defer cap.close()
	neighbors := map[string]*lldpNeighbor{}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		frame, err := cap.next(1 * time.Second)
		if err != nil {
			continue
		}
		if nb, ok := parseLLDP(frame); ok {
			nb.localIf = cap.device()
			neighbors[nb.key()] = nb
		}
		if len(neighbors) > 0 && time.Now().Add(2*time.Second).After(deadline) {
			break
		}
	}
	return sortedNeighbors(neighbors), cap.device(), nil
}

func sortedNeighbors(m map[string]*lldpNeighbor) []*lldpNeighbor {
	out := make([]*lldpNeighbor, 0, len(m))
	for _, n := range m {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

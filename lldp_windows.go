//go:build windows

package main

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Windows heeft geen ingebouwde L2-capture. We laden wpcap.dll (Npcap) pas hier,
// zodat de rest van de tool werkt zonder Npcap. Geen cgo — alles via LazyDLL/SyscallN.

const pcapErrbufSize = 256

var (
	k32load    = kernel32.NewProc("LoadLibraryW")
	k32getproc = kernel32.NewProc("GetProcAddress")
)

type wpcapDLL struct {
	handle uintptr
	procs  map[string]uintptr
}

var wp *wpcapDLL

func loadWpcap() (*wpcapDLL, error) {
	if wp != nil {
		return wp, nil
	}
	name, _ := syscall.UTF16PtrFromString("wpcap.dll")
	h, _, _ := k32load.Call(uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return nil, errNoNpcap
	}
	wp = &wpcapDLL{handle: h, procs: map[string]uintptr{}}
	return wp, nil
}

func (d *wpcapDLL) addr(name string) uintptr {
	if a, ok := d.procs[name]; ok {
		return a
	}
	cn := append([]byte(name), 0)
	a, _, _ := k32getproc.Call(d.handle, uintptr(unsafe.Pointer(&cn[0])))
	d.procs[name] = a
	return a
}

func (d *wpcapDLL) call(name string, args ...uintptr) uintptr {
	r, _, _ := syscall.SyscallN(d.addr(name), args...)
	return r
}

// cstr leest een null-getermineerde C-string uit een byte-buffer.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// cstrPtr leest een null-getermineerde C-string vanaf een pointer.
func cstrPtr(p uintptr) string {
	if p == 0 {
		return ""
	}
	var b []byte
	for i := 0; ; i++ {
		c := *(*byte)(unsafe.Pointer(p + uintptr(i)))
		if c == 0 {
			break
		}
		b = append(b, c)
		if i > 4096 {
			break
		}
	}
	return string(b)
}

type winCap struct {
	handle uintptr
	devnam string
}

func openLLDP(hint string) (capturer, []string, error) {
	dll, err := loadWpcap()
	if err != nil {
		return nil, nil, err
	}

	var alldevs uintptr
	errbuf := make([]byte, pcapErrbufSize)
	r := dll.call("pcap_findalldevs", uintptr(unsafe.Pointer(&alldevs)), uintptr(unsafe.Pointer(&errbuf[0])))
	if r != 0 || alldevs == 0 {
		return nil, nil, fmt.Errorf("pcap_findalldevs: %s", cstr(errbuf))
	}
	defer dll.call("pcap_freealldevs", alldevs)

	type dev struct{ name, desc string }
	var devs []dev
	// pcap_if_t (x64): next(0) name(8) description(16) addresses(24) flags(32)
	for p := alldevs; p != 0; {
		name := cstrPtr(*(*uintptr)(unsafe.Pointer(p + 8)))
		desc := cstrPtr(*(*uintptr)(unsafe.Pointer(p + 16)))
		flags := *(*uint32)(unsafe.Pointer(p + 32))
		label := name
		if desc != "" {
			label = desc + "  [" + name + "]"
		}
		if flags&0x10 != 0 { // PCAP_IF_CONNECTION_STATUS_CONNECTED
			label += " (verbonden)"
		}
		devs = append(devs, dev{name, label})
		p = *(*uintptr)(unsafe.Pointer(p))
	}

	list := make([]string, len(devs))
	for i, d := range devs {
		list[i] = d.desc
	}

	chosen, chosenLabel := "", ""
	if hint != "" {
		for _, d := range devs {
			if strings.Contains(strings.ToLower(d.name+d.desc), strings.ToLower(hint)) {
				chosen, chosenLabel = d.name, d.desc
				break
			}
		}
		if chosen == "" {
			return nil, list, fmt.Errorf("geen interface gevonden die overeenkomt met %q (zie -l)", hint)
		}
	} else {
		for _, d := range devs {
			if !strings.Contains(strings.ToLower(d.name), "loopback") && strings.Contains(d.desc, "verbonden") {
				chosen, chosenLabel = d.name, d.desc
				break
			}
		}
		if chosen == "" && len(devs) > 0 {
			chosen, chosenLabel = devs[0].name, devs[0].desc
		}
	}
	if chosen == "" {
		return nil, list, fmt.Errorf("geen interfaces gevonden")
	}

	cname := append([]byte(chosen), 0)
	h := dll.call("pcap_open_live",
		uintptr(unsafe.Pointer(&cname[0])),
		65536, // snaplen
		1,     // promiscuous (nodig voor LLDP-multicast; vereist meestal Administrator)
		1000,  // read timeout ms
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if h == 0 {
		return nil, list, fmt.Errorf("kan %s niet openen: %s (Administrator nodig?)", chosenLabel, cstr(errbuf))
	}
	return &winCap{handle: h, devnam: chosenLabel}, list, nil
}

func (c *winCap) device() string { return c.devnam }
func (c *winCap) close()         { wp.call("pcap_close", c.handle) }

func (c *winCap) next(timeout time.Duration) ([]byte, error) {
	var hdr, data uintptr
	deadline := time.Now().Add(timeout)
	for {
		r := int32(wp.call("pcap_next_ex", c.handle, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data))))
		switch r {
		case 1:
			if hdr == 0 || data == 0 {
				return nil, fmt.Errorf("leeg frame")
			}
			// pcap_pkthdr (x64): timeval(8) + caplen(4) + len(4)
			caplen := *(*uint32)(unsafe.Pointer(hdr + 8))
			if caplen == 0 || caplen > 65536 {
				return nil, fmt.Errorf("ongeldige lengte")
			}
			out := make([]byte, caplen)
			copy(out, unsafe.Slice((*byte)(unsafe.Pointer(data)), caplen))
			return out, nil
		case 0:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timeout")
			}
		default:
			return nil, fmt.Errorf("pcap_next_ex fout")
		}
	}
}

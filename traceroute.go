package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

type traceOpts struct {
	host     string
	maxHops  int
	probes   int
	timeout  time.Duration
	monitor  bool
	interval time.Duration
	resolve  bool
	ipv6     bool
}

type hopResult struct {
	n       int
	ip      net.IP
	rtts    []float64 // per probe, -1 = timeout
	name    string
	reached bool
}

// runTrace performs one complete traceroute.
func runTrace(h icmpHandle, dst net.IP, o traceOpts) []hopResult {
	payload := []byte("nwtoolkit-traceroute")
	var hops []hopResult
	for ttl := 1; ttl <= o.maxHops; ttl++ {
		hr := hopResult{n: ttl}
		for p := 0; p < o.probes; p++ {
			peer, rtt, status, err := h.echo(dst, ttl, o.timeout, payload)
			if err != nil || status == ipReqTimedOut || peer == nil || peer.IsUnspecified() {
				hr.rtts = append(hr.rtts, -1)
				continue
			}
			hr.ip = peer
			hr.rtts = append(hr.rtts, float64(rtt.Microseconds())/1000)
			if status == ipSuccess {
				hr.reached = true
			}
		}
		if o.resolve && hr.ip != nil {
			if names, _ := net.LookupAddr(hr.ip.String()); len(names) > 0 {
				hr.name = strings.TrimSuffix(names[0], ".")
			}
		}
		hops = append(hops, hr)
		if hr.reached {
			break
		}
	}
	return hops
}

func printHops(dst net.IP, host string, hops []hopResult) {
	fmt.Printf("traceroute to %s (%s), max %d hops   %s\n", host, dst, hops[len(hops)-1].n, col(cGrey, "(all times in ms)"))
	for _, hr := range hops {
		var b strings.Builder
		fmt.Fprintf(&b, " %2d  ", hr.n)
		if hr.ip == nil {
			b.WriteString(col(cGrey, "* * *  (no answer)"))
		} else {
			for _, r := range hr.rtts {
				if r < 0 {
					b.WriteString(col(cGrey, "   *    "))
				} else {
					c := cGreen
					if r > 50 {
						c = cYellow
					}
					if r > 150 {
						c = cRed
					}
					b.WriteString(col(c, fmt.Sprintf("%6.2f  ", r)))
				}
			}
			target := hr.ip.String()
			if hr.name != "" {
				target = fmt.Sprintf("%s (%s)", hr.name, hr.ip)
			}
			b.WriteString(" " + target)
			if hr.reached {
				b.WriteString(col(cGreen, "  <== target"))
			}
		}
		fmt.Println(b.String())
	}
}

func cmdTrace(o traceOpts) {
	dst, err := resolveIP(o.host, o.ipv6)
	if err != nil {
		die("%v", err)
	}
	h, err := icmpOpen()
	if err != nil {
		die("cannot open ICMP: %v", err)
	}
	defer h.close()

	if !o.monitor {
		hops := runTrace(h, dst, o)
		printHops(dst, o.host, hops)
		return
	}

	// Continuous mode: repeat every interval, clear the screen, summarising min/avg/max per hop.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	type agg struct {
		ip          net.IP
		name        string
		samples     []float64
		lost, total int
		reached     bool
	}
	aggs := map[int]*agg{}
	var mu sync.Mutex
	round := 0

	draw := func() {
		mu.Lock()
		defer mu.Unlock()
		fmt.Print(clrScr)
		fmt.Printf("%s  traceroute monitor to %s (%s)   round %d   every %s   Ctrl+C to stop\n\n",
			col(cBold, "nwtoolkit"), o.host, dst, round, o.interval)
		fmt.Printf(" %-3s %-32s %8s %8s %8s %8s %7s\n", "hop", "adres", "laatst", "min", "gem", "max", "verlies")
		fmt.Printf(" %-3s %-32s %8s %8s %8s %8s %7s\n", "", "", "(ms)", "(ms)", "(ms)", "(ms)", "")
		fmt.Println(strings.Repeat("-", 86))
		maxHop := 0
		for k := range aggs {
			if k > maxHop {
				maxHop = k
			}
		}
		for i := 1; i <= maxHop; i++ {
			a := aggs[i]
			if a == nil {
				fmt.Printf(" %-3d %-32s\n", i, col(cGrey, "* (no answer)"))
				continue
			}
			addr := "*"
			if a.ip != nil {
				addr = a.ip.String()
				if a.name != "" {
					addr = a.name
				}
			}
			if len(addr) > 32 {
				addr = addr[:31] + "…"
			}
			st := computeStats(a.samples, a.lost)
			last := 0.0
			if len(a.samples) > 0 {
				last = a.samples[len(a.samples)-1]
			}
			lc := cGreen
			if st.Loss > 0 {
				lc = cYellow
			}
			if st.Loss >= 50 {
				lc = cRed
			}
			mark := ""
			if a.reached {
				mark = col(cGreen, " ⇐ target")
			}
			fmt.Printf(" %-3d %-32s %8.2f %8.2f %8.2f %8.2f %s%s\n",
				i, addr, last, st.Min, st.Avg, st.Max, col(lc, fmt.Sprintf("%6.0f%%", st.Loss)), mark)
		}
	}

	for {
		round++
		hops := runTrace(h, dst, o)
		mu.Lock()
		for _, hr := range hops {
			a := aggs[hr.n]
			if a == nil {
				a = &agg{}
				aggs[hr.n] = a
			}
			if hr.ip != nil {
				a.ip = hr.ip
				a.name = hr.name
			}
			if hr.reached {
				a.reached = true
			}
			for _, r := range hr.rtts {
				a.total++
				if r < 0 {
					a.lost++
				} else {
					a.samples = append(a.samples, r)
					if len(a.samples) > 300 {
						a.samples = a.samples[len(a.samples)-300:]
					}
				}
			}
		}
		mu.Unlock()
		draw()

		select {
		case <-sig:
			fmt.Println("\nstopped.")
			return
		case <-time.After(o.interval):
		}
	}
}

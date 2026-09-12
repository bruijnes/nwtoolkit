package main

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"time"
)

const version = "1.28"

// ANSI colours
const (
	cReset  = "\033[0m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cCyan   = "\033[36m"
	cGrey   = "\033[90m"
	cBold   = "\033[1m"
	clrScr  = "\033[2J\033[H"
)

var useColor = true

func col(c, s string) string {
	if !useColor {
		return s
	}
	return c + s + cReset
}

// resolve4 resolves a hostname to an IPv4 address.
func resolve4(host string) (net.IP, error) { return resolveIP(host, false) }

// resolveIP resolves a hostname to an IPv4 or IPv6 address, depending on v6.
func resolveIP(host string, v6 bool) (net.IP, error) {
	match := func(ip net.IP) net.IP {
		if v6 {
			if ip.To4() == nil && ip.To16() != nil {
				return ip
			}
			return nil
		}
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
		return nil
	}
	fam := "IPv4"
	if v6 {
		fam = "IPv6"
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil // a literal IP is explicit; the family follows from the address itself
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if m := match(ip); m != nil {
			return m, nil
		}
	}
	return nil, fmt.Errorf("no %s address found for %s", fam, host)
}

// stats computes min/avg/max/stddev over a series of RTTs in ms.
type stats struct {
	Min, Avg, Max, Stddev, Last float64
	Loss                        float64
	N, Lost                     int
}

func computeStats(samples []float64, lost int) stats {
	s := stats{Min: math.MaxFloat64}
	if len(samples) == 0 {
		s.Min = 0
		s.Lost = lost
		if lost > 0 {
			s.Loss = 100
		}
		return s
	}
	var sum float64
	for _, v := range samples {
		sum += v
		if v < s.Min {
			s.Min = v
		}
		if v > s.Max {
			s.Max = v
		}
	}
	s.N = len(samples)
	s.Avg = sum / float64(len(samples))
	s.Last = samples[len(samples)-1]
	var sq float64
	for _, v := range samples {
		sq += (v - s.Avg) * (v - s.Avg)
	}
	s.Stddev = math.Sqrt(sq / float64(len(samples)))
	s.Lost = lost
	total := len(samples) + lost
	if total > 0 {
		s.Loss = float64(lost) * 100 / float64(total)
	}
	return s
}

func (s stats) String() string {
	return fmt.Sprintf("min %.2f / avg %.2f / max %.2f / stddev %.2f ms   loss %.0f%% (%d/%d)",
		s.Min, s.Avg, s.Max, s.Stddev, s.Loss, s.Lost, s.N+s.Lost)
}

// pXX returns the p-th percentile.
func percentile(samples []float64, p float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]float64(nil), samples...)
	sort.Float64s(cp)
	idx := int(math.Ceil(p/100*float64(len(cp)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

// ring keeps the last n floats for the chart.
type ring struct {
	buf []float64
	max int
}

func newRing(max int) *ring { return &ring{max: max} }
func (r *ring) push(v float64) {
	r.buf = append(r.buf, v)
	if len(r.buf) > r.max {
		r.buf = r.buf[len(r.buf)-r.max:]
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, col(cRed, "error: ")+format+"\n", a...)
	holdIfNeeded()
	os.Exit(1)
}

// holdOnExit is set when this process was relaunched with -keepopen, i.e. an elevated
// copy running in a fresh console that would otherwise close the instant it finishes.
var holdOnExit bool

// holdIfNeeded pauses so the output stays readable before such a window closes.
func holdIfNeeded() {
	if !holdOnExit {
		return
	}
	fmt.Print("\nPress Enter to close\u2026")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func nowStamp() string { return time.Now().Format("15:04:05") }

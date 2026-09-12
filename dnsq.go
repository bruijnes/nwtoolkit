package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/guptarohit/asciigraph"
	"github.com/miekg/dns"
)

type dnsOpts struct {
	name    string
	server  string // leeg = systeemresolver uit /etc/resolv.conf of Windows
	qtype   string
	timeout time.Duration
	// speedtest
	speed    bool
	monitor  bool
	interval time.Duration
	count    int
	ipv6     bool
}

// serverAddr geeft host:poort voor de DNS-server, met de host geresolved naar de
// gekozen IP-familie als het een naam is.
func serverAddr(server string, v6 bool) string {
	s := withPort(server)
	host, port, err := net.SplitHostPort(s)
	if err != nil || net.ParseIP(host) != nil {
		return s // al een IP-literal of geen host:poort
	}
	ip, err := resolveIP(host, v6)
	if err != nil {
		return s
	}
	if v6 {
		return "[" + ip.String() + "]:" + port
	}
	return ip.String() + ":" + port
}

func qtypeCode(s string) uint16 {
	if c, ok := dns.StringToType[strings.ToUpper(s)]; ok {
		return c
	}
	return dns.TypeA
}

func defaultServer() string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(cfg.Servers) > 0 {
		return cfg.Servers[0] + ":53"
	}
	if s := systemDNS(); s != "" {
		return s + ":53"
	}
	return "8.8.8.8:53"
}

func withPort(s string) string {
	if s == "" {
		return defaultServer()
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s // al host:poort (incl. [v6]:poort)
	}
	if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
		return "[" + s + "]:53" // kaal IPv6-literal → brackets
	}
	return s + ":53"
}

// doQuery voert één DNS-query uit en geeft RTT + antwoorden terug.
func doQuery(server, name string, qtype uint16, timeout time.Duration) (time.Duration, []string, error) {
	c := &dns.Client{Timeout: timeout}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	r, rtt, err := c.Exchange(m, server)
	if err != nil {
		return rtt, nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return rtt, nil, fmt.Errorf("rcode %s", dns.RcodeToString[r.Rcode])
	}
	var ans []string
	for _, a := range r.Answer {
		parts := strings.Fields(a.String())
		if len(parts) > 0 {
			ans = append(ans, parts[len(parts)-1]+" ("+dns.TypeToString[a.Header().Rrtype]+")")
		}
	}
	return rtt, ans, nil
}

func cmdDNS(o dnsOpts) {
	server := serverAddr(o.server, o.ipv6)
	qtype := qtypeCode(o.qtype)

	if !o.speed && !o.monitor {
		rtt, ans, err := doQuery(server, o.name, qtype, o.timeout)
		fmt.Printf("Server:  %s\n", server)
		fmt.Printf("Query:   %s %s\n", o.name, strings.ToUpper(o.qtype))
		if err != nil {
			fmt.Printf("Fout:    %s   (%.2f ms)\n", col(cRed, err.Error()), float64(rtt.Microseconds())/1000)
			os.Exit(1)
		}
		c := cGreen
		ms := float64(rtt.Microseconds()) / 1000
		if ms > 50 {
			c = cYellow
		}
		fmt.Printf("Tijd:    %s\n", col(c, fmt.Sprintf("%.2f ms", ms)))
		fmt.Println("Antwoord:")
		if len(ans) == 0 {
			fmt.Println("  (geen records)")
		}
		for _, a := range ans {
			fmt.Println("  " + a)
		}
		return
	}

	// speedtest / monitor
	runSpeedGraph(speedGraphCfg{
		title:    fmt.Sprintf("DNS-speedtest  server=%s  query=%s %s", server, o.name, strings.ToUpper(o.qtype)),
		unit:     "ms",
		interval: o.interval,
		count:    o.count,
		monitor:  o.monitor,
		measure: func() (float64, string, error) {
			rtt, ans, err := doQuery(server, o.name, qtype, o.timeout)
			ms := float64(rtt.Microseconds()) / 1000
			info := ""
			if len(ans) > 0 {
				info = ans[0]
			}
			return ms, info, err
		},
	})
}

// ---- gedeelde speedtest+grafiek runner (ook door DHCP gebruikt) ----

type speedGraphCfg struct {
	title    string
	unit     string
	interval time.Duration
	count    int
	monitor  bool
	measure  func() (value float64, info string, err error)
}

func runSpeedGraph(cfg speedGraphCfg) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	r := newRing(120)
	var lost, n int

	draw := func(lastInfo string, lastErr error) {
		if cfg.monitor {
			fmt.Print(clrScr)
		}
		fmt.Printf("%s  %s\n", col(cBold, "nwtoolkit"), cfg.title)
		if len(r.buf) >= 2 {
			height := 12
			width := 100
			g := asciigraph.Plot(r.buf,
				asciigraph.Height(height), asciigraph.Width(width),
				asciigraph.Caption(fmt.Sprintf("laatste %d metingen (%s)", len(r.buf), cfg.unit)))
			fmt.Println()
			fmt.Println(g)
		}
		st := computeStats(r.buf, lost)
		fmt.Println()
		last := "-"
		if lastErr != nil {
			last = col(cRed, "FOUT: "+lastErr.Error())
		} else if len(r.buf) > 0 {
			c := cGreen
			v := r.buf[len(r.buf)-1]
			if v > st.Avg*1.5 {
				c = cYellow
			}
			last = col(c, fmt.Sprintf("%.2f %s", v, cfg.unit)) + "   " + col(cGrey, lastInfo)
		}
		fmt.Printf("laatst: %s\n", last)
		fmt.Printf("min %.2f %s  gem %.2f %s  max %.2f %s  p95 %.2f %s   metingen %d  fouten %d\n",
			st.Min, cfg.unit, st.Avg, cfg.unit, st.Max, cfg.unit, percentile(r.buf, 95), cfg.unit, n, lost)
		if cfg.monitor {
			fmt.Println(col(cGrey, "\nCtrl+C = stoppen"))
		}
	}

	for {
		v, info, err := cfg.measure()
		n++
		if err != nil {
			lost++
		} else {
			r.push(v)
		}
		if cfg.monitor || cfg.count == 0 {
			draw(info, err)
		} else {
			// eenmalige/vaste-count run: regel per meting
			if err != nil {
				fmt.Printf("  %s  %s\n", nowStamp(), col(cRed, "fout: "+err.Error()))
			} else {
				fmt.Printf("  %s  %.2f %s   %s\n", nowStamp(), v, cfg.unit, col(cGrey, info))
			}
		}

		if !cfg.monitor && cfg.count > 0 && n >= cfg.count {
			if cfg.count > 1 {
				st := computeStats(r.buf, lost)
				fmt.Printf("\n%s\n", st)
			}
			return
		}
		select {
		case <-sig:
			if !cfg.monitor {
				st := computeStats(r.buf, lost)
				fmt.Printf("\n%s\n", st)
			}
			fmt.Println("\ngestopt.")
			return
		case <-time.After(cfg.interval):
		}
	}
}

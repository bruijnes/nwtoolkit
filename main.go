package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func usage() {
	fmt.Print(`nwtoolkit ` + version + ` — network diagnostics (IPv4)

Usage:    nwtoolkit <command> [options]
          nwtoolkit            (double-click: native window; in a terminal: menu)
          nwtoolkit gui        (native Windows window)
          nwtoolkit menu       (interactive text menu)

Commands:
  ping   <host>              ICMP ping
      -c <n>       count (default 4; -t for endless)
      -t           keep pinging until Ctrl+C
      -i <s>       interval in seconds (default 1)
      -w <s>       timeout per ping in seconds (default 2)
      -s <bytes>   payload size (default 32)
      -6           use IPv6

  trace  <host>              traceroute
      -m           continuous monitor (live table with min/avg/max per hop)
      -i <s>       repeat interval in seconds while monitoring (default 3)
      -h <n>       max hops (default 30)
      -q <n>       probes per hop (default 3)
      -n           look up reverse DNS names
      -6           use IPv6

  dns    <name>              DNS query with response time
      -s <server>  DNS server (default: system)
      -type <T>    A, AAAA, MX, TXT, NS, CNAME, SOA, PTR (default A)
      -6           use IPv6 (server over v6; default type AAAA)

  dnsspeed <name>            measure DNS response time + chart
      -s <server>  DNS server (default: system)
      -1           single measurement
      -m           continuous monitor with live chart (default)
      -i <s>       interval in seconds (default 5)
      -c <n>       fixed number of measurements instead of monitoring

  dhcp                       measure DHCP response time + chart
      -s <server>  measure one specific DHCP server (unicast INFORM)
                   empty = broadcast: ask the network itself, with no prior
                   knowledge, and list every server that answers
      -6           DHCPv6 (INFORMATION-REQUEST; multicast or -s <server>)
      -1           single measurement
      -m           continuous monitor with live chart (default)
      -i <s>       interval in seconds (default 5)
      -c <n>       fixed number of measurements

  lldp                       show LLDP neighbour (connected switch/port)
      -l           list available interfaces
      -i <name>    pick interface (part of name/description)
      -w <s>       wait time in seconds for a single capture (default 35)
      -m           keep monitoring
      (Windows: uses the built-in pktmon; Administrator required)


Examples:
  nwtoolkit ping 8.8.8.8 -t
  nwtoolkit trace switch.example.com -m
  nwtoolkit dns example.com -s 1.1.1.1 -type MX
  nwtoolkit dnsspeed example.com -s 1.1.1.1
  nwtoolkit dhcp -s 192.168.1.1
`)
}

func main() {
	useColor = enableVT()
	stripKeepOpen()
	defer holdIfNeeded()

	if len(os.Args) < 2 {
		// Double-clicked from Explorer -> native Windows window (GUI).
		// No arguments from a terminal -> the interactive console menu.
		if launchedFromExplorer() {
			runGUI()
		} else {
			interactiveMenu()
		}
		return
	}

	cmd := strings.ToLower(os.Args[1])
	args := os.Args[2:]

	switch cmd {
	case "help", "-h", "--help", "/?":
		usage()
	case "version", "-v", "--version":
		fmt.Println("nwtoolkit", version)
	case "ping":
		runPing(args)
	case "trace", "traceroute", "tracert":
		runTraceCmd(args)
	case "dns", "nslookup":
		runDNS(args, false)
	case "dnsspeed", "dnstest":
		runDNS(args, true)
	case "dhcp", "dhcptest":
		runDHCP(args)
	case "lldp", "cdp", "neighbor", "buur":
		runLLDP(args)
	case "menu":
		interactiveMenu()
	case "gui", "window":
		runGUI()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

// splitArgs separates positional arguments from flags. boolFlags holds the names of
// flags that take no value, so that "-s host -1" does not read '-1' as the value of
// -s. This lets flags appear both before and after the host.
func splitArgs(args []string, boolFlags map[string]bool) (positionals []string, flags []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if idx := strings.IndexByte(name, '='); idx >= 0 || boolFlags[name] {
				continue // the value is already bound, or it is a bool flag
			}
			if i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positionals = append(positionals, a)
	}
	return
}

func firstPositional(args []string, boolFlags map[string]bool) (string, []string) {
	pos, flags := splitArgs(args, boolFlags)
	host := ""
	if len(pos) > 0 {
		host = pos[0]
	}
	return host, flags
}

func runPing(args []string) {
	host, rest := firstPositional(args, map[string]bool{"t": true, "6": true})
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	c := fs.Int("c", 4, "count")
	t := fs.Bool("t", false, "oneindig")
	i := fs.Float64("i", 1, "interval (s)")
	w := fs.Float64("w", 2, "timeout (s)")
	s := fs.Int("s", 32, "payload bytes")
	six := fs.Bool("6", false, "use IPv6")
	fs.Parse(rest)
	if host == "" {
		die("specify a host: nwtoolkit ping <host>")
	}
	count := *c
	if *t {
		count = 0
	}
	cmdPing(pingOpts{host: host, count: count, interval: dur(*i), timeout: dur(*w), size: *s, ipv6: *six})
}

func runTraceCmd(args []string) {
	host, rest := firstPositional(args, map[string]bool{"m": true, "n": true, "6": true})
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	m := fs.Bool("m", false, "monitor")
	i := fs.Float64("i", 3, "interval (s)")
	h := fs.Int("h", 30, "max hops")
	q := fs.Int("q", 3, "probes")
	n := fs.Bool("n", false, "reverse dns")
	six := fs.Bool("6", false, "use IPv6")
	fs.Parse(rest)
	if host == "" {
		die("specify a host: nwtoolkit trace <host>")
	}
	cmdTrace(traceOpts{host: host, maxHops: *h, probes: *q, timeout: 2 * time.Second, monitor: *m, interval: dur(*i), resolve: *n, ipv6: *six})
}

func runDNS(args []string, speed bool) {
	name, rest := firstPositional(args, map[string]bool{"1": true, "m": true, "6": true})
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	s := fs.String("s", "", "server")
	// the speed test defaults to a light HINFO query; a plain dns query uses A
	six6 := false
	for _, a := range rest {
		if a == "-6" || a == "--6" {
			six6 = true
		}
	}
	defType := "A"
	if six6 {
		defType = "AAAA"
	}
	if speed {
		defType = "HINFO"
	}
	typ := fs.String("type", defType, "recordtype")
	one := fs.Bool("1", false, "one-shot")
	m := fs.Bool("m", speed, "monitor")
	i := fs.Float64("i", 5, "interval (s)")
	c := fs.Int("c", 0, "fixed count")
	six := fs.Bool("6", false, "use IPv6")
	fs.Parse(rest)
	if name == "" {
		die("specify a name: nwtoolkit dns <name>")
	}
	o := dnsOpts{name: name, server: *s, qtype: *typ, timeout: 3 * time.Second,
		speed: speed, monitor: *m && !*one, interval: dur(*i), count: *c, ipv6: *six}
	if *c > 0 {
		o.monitor = false // a fixed sample count takes precedence over monitoring
	}
	if *one {
		o.monitor = false
		if speed {
			o.count = 1
		}
	}
	cmdDNS(o)
}

func runDHCP(args []string) {
	_, rest := splitArgs(args, map[string]bool{"1": true, "m": true, "6": true})
	fs := flag.NewFlagSet("dhcp", flag.ExitOnError)
	s := fs.String("s", "", "server ip")
	one := fs.Bool("1", false, "one-shot")
	m := fs.Bool("m", true, "monitor")
	i := fs.Float64("i", 5, "interval (s)")
	c := fs.Int("c", 0, "fixed count")
	port := fs.Int("port", 0, "local port")
	six := fs.Bool("6", false, "use DHCPv6")
	fs.Parse(rest)
	o := dhcpOpts{server: *s, timeout: 3 * time.Second, monitor: *m && !*one, interval: dur(*i), count: *c, port: *port, ipv6: *six}
	if *c > 0 {
		o.monitor = false
	}
	if *one {
		o.monitor = false
		o.count = 1
	}
	cmdDHCP(o)
}

func runLLDP(args []string) {
	_, rest := splitArgs(args, map[string]bool{"m": true, "l": true})
	fs := flag.NewFlagSet("lldp", flag.ExitOnError)
	i := fs.String("i", "", "interface (part of name/description)")
	w := fs.Float64("w", 35, "wait (s) for a single capture")
	m := fs.Bool("m", false, "monitor (keep showing)")
	l := fs.Bool("l", false, "list available interfaces")
	fs.Parse(rest)
	// LLDP capture needs elevated rights (pktmon on Windows). Offer to restart with
	// a UAC prompt when we are not elevated and are actually going to capture.
	if !*l && !isElevated() && promptRestartAsAdmin("LLDP capture") {
		if err := relaunchAsAdmin(append(os.Args[1:], "-keepopen")); err != nil {
			die("could not restart as administrator: %v", err)
		}
		return
	}
	cmdLLDP(lldpOpts{iface: *i, wait: dur(*w), monitor: *m, list: *l})
}

func dur(sec float64) time.Duration { return time.Duration(sec * float64(time.Second)) }

// ---- interactive menu (when the exe is double-clicked) ----

func interactiveMenu() {
	in := bufio.NewReader(os.Stdin)
	ask := func(prompt, def string) string {
		if def != "" {
			fmt.Printf("%s [%s]: ", prompt, def)
		} else {
			fmt.Printf("%s: ", prompt)
		}
		line, _ := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		return line
	}

	for {
		fmt.Print(clrScr)
		fmt.Println(col(cBold, "  nwtoolkit "+version) + "  —  network diagnostics")
		fmt.Println(col(cGrey, "  ────────────────────────────────────"))
		fmt.Println("   1)  Ping")
		fmt.Println("   2)  Traceroute")
		fmt.Println("   3)  DNS query (with response time)")
		fmt.Println("   4)  DNS speed test (chart)")
		fmt.Println("   5)  DHCP speed test (chart)")
		fmt.Println("   6)  LLDP neighbour (connected switch/port)")
		fmt.Println("   0)  Exit")
		fmt.Println()
		choice := ask("  Choice", "")

		switch choice {
		case "1":
			host := ask("  Host/IP", "1.1.1.1")
			cont := strings.HasPrefix(strings.ToLower(ask("  Ping continuously? (y/n)", "n")), "y")
			cnt := 4
			if cont {
				cnt = 0
			}
			cmdPing(pingOpts{host: host, count: cnt, interval: time.Second, timeout: 2 * time.Second, size: 32})
		case "2":
			host := ask("  Host/IP", "example.com")
			mon := strings.HasPrefix(strings.ToLower(ask("  Monitor continuously? (y/n)", "n")), "y")
			cmdTrace(traceOpts{host: host, maxHops: 30, probes: 3, timeout: 2 * time.Second, monitor: mon, interval: 3 * time.Second, resolve: true})
		case "3":
			name := ask("  Name", "example.com")
			srv := ask("  DNS server (empty=system)", "")
			typ := ask("  Type", "A")
			cmdDNS(dnsOpts{name: name, server: srv, qtype: typ, timeout: 3 * time.Second})
		case "4":
			name := ask("  Name", "example.com")
			srv := ask("  DNS server (empty=system)", "")
			cont := strings.HasPrefix(strings.ToLower(ask("  Continuous (chart) or one-shot? (c/o)", "c")), "c")
			o := dnsOpts{name: name, server: srv, qtype: "A", timeout: 3 * time.Second, speed: true, interval: 5 * time.Second}
			o.monitor = cont
			if !cont {
				o.count = 1
			}
			cmdDNS(o)
		case "5":
			srv := ask("  DHCP server IP (empty=broadcast, admin required)", "")
			cont := strings.HasPrefix(strings.ToLower(ask("  Continuous (chart) or one-shot? (c/o)", "c")), "c")
			o := dhcpOpts{server: srv, timeout: 3 * time.Second, interval: 5 * time.Second}
			o.monitor = cont
			if !cont {
				o.count = 1
			}
			cmdDHCP(o)
		case "6":
			iface := ask("  Interface (empty=automatic, or part of the name)", "")
			mon := strings.HasPrefix(strings.ToLower(ask("  Monitor continuously? (y/n)", "n")), "y")
			cmdLLDP(lldpOpts{iface: iface, wait: 35 * time.Second, monitor: mon})
		case "0", "q", "":
			return
		default:
			continue
		}
		fmt.Print("\n  " + col(cGrey, "Press Enter to return to the menu…"))
		in.ReadString('\n')
	}
}

// stripKeepOpen removes the internal -keepopen marker from the argument list and
// records that this run should pause before its window closes. relaunchAsAdmin adds
// the marker so an elevated copy launched in a fresh console stays readable instead
// of vanishing the moment the command finishes.
func stripKeepOpen() {
	out := os.Args[:0]
	for _, a := range os.Args {
		if a == "-keepopen" || a == "--keepopen" {
			holdOnExit = true
			continue
		}
		out = append(out, a)
	}
	os.Args = out
}

// promptRestartAsAdmin asks, on the console, whether to relaunch elevated. Returns
// false at once when there is no console to read from.
func promptRestartAsAdmin(what string) bool {
	fmt.Printf("%s needs administrator rights. Restart as administrator? (y/n): ", what)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y")
}

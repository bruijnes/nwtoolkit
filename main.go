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
	fmt.Print(`nwtoolkit ` + version + ` — netwerkdiagnose (IPv4)

Gebruik:  nwtoolkit <commando> [opties]
          nwtoolkit            (dubbelklik: native venster; in terminal: menu)
          nwtoolkit gui        (native Windows-venster)
          nwtoolkit web        (grafische web-UI in de browser)
          nwtoolkit menu       (interactief tekst-menu)

Commando's:
  ping   <host>              ICMP-ping
      -c <n>       aantal (standaard 4; -t voor oneindig)
      -t           blijf pingen tot Ctrl+C
      -i <sec>     interval (standaard 1)
      -w <sec>     timeout per ping (standaard 2)
      -s <bytes>   payloadgrootte (standaard 32)
      -6           gebruik IPv6

  trace  <host>              traceroute
      -m           continu-monitor (verse tabel met min/gem/max per hop)
      -i <sec>     herhaalinterval in monitor (standaard 3)
      -h <n>       max hops (standaard 30)
      -q <n>       probes per hop (standaard 3)
      -n           reverse-DNS namen opzoeken
      -6           gebruik IPv6

  dns    <naam>              DNS-query met responstijd
      -s <server>  DNS-server (standaard: systeem)
      -type <T>    A, AAAA, MX, TXT, NS, CNAME, SOA, PTR (standaard A)
      -6           gebruik IPv6 (server over v6; default type AAAA)

  dnsspeed <naam>            DNS-responstijd meten + grafiek
      -s <server>  DNS-server (standaard: systeem)
      -1           eenmalige meting
      -m           continu-monitor met live grafiek (standaard)
      -i <sec>     interval (standaard 5)
      -c <n>       vast aantal metingen i.p.v. monitor

  dhcp                       DHCP-responstijd meten + grafiek
      -s <server>  DHCP-server-IP (unicast INFORM, geen admin nodig)
                   leeg = automatisch: INFORM naar de server die Windows al kent
      -b           broadcast DISCOVER forceren, alsof dit netwerk onbekend is;
                   toont elke server die antwoordt (Windows: als Administrator)
      -6           DHCPv6 (INFORMATION-REQUEST; multicast of -s <server>)
      -1           eenmalige meting
      -m           continu-monitor met live grafiek (standaard)
      -i <sec>     interval (standaard 5)
      -c <n>       vast aantal metingen

  lldp                       toon LLDP-buur (aangesloten switch/poort)
      -l           toon beschikbare interfaces
      -i <naam>    kies interface (deel van naam/omschrijving)
      -w <sec>     wachttijd voor eenmalige capture (standaard 35)
      -m           blijf monitoren
      (Windows: gebruikt de ingebouwde pktmon; Administrator nodig)

  web    [adres]             web-UI (standaard 127.0.0.1:8733)

Voorbeelden:
  nwtoolkit ping 8.8.8.8 -t
  nwtoolkit trace synapseprod-http.zmst.loc -m
  nwtoolkit dns deep.radio -s 1.1.1.1 -type MX
  nwtoolkit dnsspeed deep.radio -s 1.1.1.1
  nwtoolkit dhcp -s 192.168.1.1
  nwtoolkit web
`)
}

func main() {
	useColor = enableVT()

	if len(os.Args) < 2 {
		// Dubbelklik vanuit Verkenner → native Windows-venster (GUI).
		// Zonder argumenten vanuit een terminal → het interactieve console-menu.
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
	case "gui", "venster":
		runGUI()
	case "web":
		addr := "127.0.0.1:8733"
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			addr = args[0]
			if !strings.Contains(addr, ":") {
				addr = "127.0.0.1:" + addr
			}
		}
		cmdWeb(addr)
	default:
		fmt.Fprintf(os.Stderr, "onbekend commando: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

// splitArgs scheidt positionele argumenten van flags. boolFlags bevat de namen
// van flags die GEEN waarde nemen (zodat "-s host -1" niet '-1' als waarde van -s pakt).
// Zo werken flags zowel vóór als na de host.
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
				continue // waarde zit al vast, of het is een bool-flag
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
	c := fs.Int("c", 4, "aantal")
	t := fs.Bool("t", false, "oneindig")
	i := fs.Float64("i", 1, "interval sec")
	w := fs.Float64("w", 2, "timeout sec")
	s := fs.Int("s", 32, "payload bytes")
	six := fs.Bool("6", false, "IPv6 gebruiken")
	fs.Parse(rest)
	if host == "" {
		die("geef een host op: nwtoolkit ping <host>")
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
	i := fs.Float64("i", 3, "interval sec")
	h := fs.Int("h", 30, "max hops")
	q := fs.Int("q", 3, "probes")
	n := fs.Bool("n", false, "reverse dns")
	six := fs.Bool("6", false, "IPv6 gebruiken")
	fs.Parse(rest)
	if host == "" {
		die("geef een host op: nwtoolkit trace <host>")
	}
	cmdTrace(traceOpts{host: host, maxHops: *h, probes: *q, timeout: 2 * time.Second, monitor: *m, interval: dur(*i), resolve: *n, ipv6: *six})
}

func runDNS(args []string, speed bool) {
	name, rest := firstPositional(args, map[string]bool{"1": true, "m": true, "6": true})
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	s := fs.String("s", "", "server")
	// speedtest meet standaard met een lichte HINFO-query; gewone dns-query met A
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
	one := fs.Bool("1", false, "eenmalig")
	m := fs.Bool("m", speed, "monitor")
	i := fs.Float64("i", 5, "interval sec")
	c := fs.Int("c", 0, "vast aantal")
	six := fs.Bool("6", false, "IPv6 gebruiken")
	fs.Parse(rest)
	if name == "" {
		die("geef een naam op: nwtoolkit dns <naam>")
	}
	o := dnsOpts{name: name, server: *s, qtype: *typ, timeout: 3 * time.Second,
		speed: speed, monitor: *m && !*one, interval: dur(*i), count: *c, ipv6: *six}
	if *c > 0 {
		o.monitor = false // vast aantal metingen heeft voorrang op monitor
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
	_, rest := splitArgs(args, map[string]bool{"1": true, "m": true, "6": true, "b": true})
	fs := flag.NewFlagSet("dhcp", flag.ExitOnError)
	s := fs.String("s", "", "server ip")
	one := fs.Bool("1", false, "eenmalig")
	m := fs.Bool("m", true, "monitor")
	i := fs.Float64("i", 5, "interval sec")
	c := fs.Int("c", 0, "vast aantal")
	port := fs.Int("port", 0, "lokale poort")
	six := fs.Bool("6", false, "DHCPv6 gebruiken")
	b := fs.Bool("b", false, "broadcast DISCOVER forceren")
	fs.Parse(rest)
	o := dhcpOpts{server: *s, timeout: 3 * time.Second, monitor: *m && !*one, interval: dur(*i), count: *c, port: *port, ipv6: *six, discover: *b}
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
	i := fs.String("i", "", "interface (deel van naam/omschrijving)")
	w := fs.Float64("w", 35, "wachttijd sec voor eenmalige capture")
	m := fs.Bool("m", false, "monitor (blijf tonen)")
	l := fs.Bool("l", false, "toon beschikbare interfaces")
	fs.Parse(rest)
	cmdLLDP(lldpOpts{iface: *i, wait: dur(*w), monitor: *m, list: *l})
}

func dur(sec float64) time.Duration { return time.Duration(sec * float64(time.Second)) }

// ---- interactief menu (bij dubbelklik op de exe) ----

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
		fmt.Println(col(cBold, "  nwtoolkit "+version) + "  —  netwerkdiagnose")
		fmt.Println(col(cGrey, "  ────────────────────────────────────"))
		fmt.Println("   1)  Ping")
		fmt.Println("   2)  Traceroute")
		fmt.Println("   3)  DNS-query (met responstijd)")
		fmt.Println("   4)  DNS-speedtest (grafiek)")
		fmt.Println("   5)  DHCP-speedtest (grafiek)")
		fmt.Println("   6)  LLDP-buur (aangesloten switch/poort)")
		fmt.Println("   7)  Web-UI in browser")
		fmt.Println("   0)  Afsluiten")
		fmt.Println()
		choice := ask("  Keuze", "")

		switch choice {
		case "1":
			host := ask("  Host/IP", "1.1.1.1")
			cont := strings.HasPrefix(strings.ToLower(ask("  Continu pingen? (j/n)", "n")), "j")
			cnt := 4
			if cont {
				cnt = 0
			}
			cmdPing(pingOpts{host: host, count: cnt, interval: time.Second, timeout: 2 * time.Second, size: 32})
		case "2":
			host := ask("  Host/IP", "example.com")
			mon := strings.HasPrefix(strings.ToLower(ask("  Continu monitoren? (j/n)", "n")), "j")
			cmdTrace(traceOpts{host: host, maxHops: 30, probes: 3, timeout: 2 * time.Second, monitor: mon, interval: 3 * time.Second, resolve: true})
		case "3":
			name := ask("  Naam", "example.com")
			srv := ask("  DNS-server (leeg=systeem)", "")
			typ := ask("  Type", "A")
			cmdDNS(dnsOpts{name: name, server: srv, qtype: typ, timeout: 3 * time.Second})
		case "4":
			name := ask("  Naam", "example.com")
			srv := ask("  DNS-server (leeg=systeem)", "")
			cont := strings.HasPrefix(strings.ToLower(ask("  Continu (grafiek) of eenmalig? (c/e)", "c")), "c")
			o := dnsOpts{name: name, server: srv, qtype: "A", timeout: 3 * time.Second, speed: true, interval: 5 * time.Second}
			o.monitor = cont
			if !cont {
				o.count = 1
			}
			cmdDNS(o)
		case "5":
			srv := ask("  DHCP-server-IP (leeg=broadcast, admin nodig)", "")
			cont := strings.HasPrefix(strings.ToLower(ask("  Continu (grafiek) of eenmalig? (c/e)", "c")), "c")
			o := dhcpOpts{server: srv, timeout: 3 * time.Second, interval: 5 * time.Second}
			o.monitor = cont
			if !cont {
				o.count = 1
			}
			cmdDHCP(o)
		case "6":
			iface := ask("  Interface (leeg=automatisch, of deel van naam)", "")
			mon := strings.HasPrefix(strings.ToLower(ask("  Continu monitoren? (j/n)", "n")), "j")
			cmdLLDP(lldpOpts{iface: iface, wait: 35 * time.Second, monitor: mon})
		case "7":
			go cmdWeb("127.0.0.1:8733")
			fmt.Println("\n  Web-UI gestart. Enter om terug te keren naar het menu (server blijft draaien).")
			in.ReadString('\n')
			continue
		case "0", "q", "":
			return
		default:
			continue
		}
		fmt.Print("\n  " + col(cGrey, "Enter om terug te keren naar het menu…"))
		in.ReadString('\n')
	}
}

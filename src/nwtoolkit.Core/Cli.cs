using System.Globalization;
using static Nwtoolkit.Util;

namespace Nwtoolkit;

/// <summary>Command line: usage, dispatch, the flag parser and the interactive menu.</summary>
public static class Cli
{
    public static string UsageText() => $@"nwtoolkit {Util.Version} — network diagnostics

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
      -n           look up the reverse DNS name of the responder
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
      -i <s>       interval in seconds (default 1)
      -c <n>       fixed number of measurements

  lldp                       show LLDP neighbour (connected switch/port)
      -l           list network interfaces
      -w <s>       wait time in seconds for a single capture (default 35)
      -m           keep monitoring
      (uses the built-in pktmon; Administrator required)

  tcpdump                    live packet capture, one line per packet
      -i <iface>   interface name, description or IP
                   empty = the adapter of the default route
      -l           list the interfaces that can be captured on
      -c <n>       stop after n packets
      -d <s>       stop after s seconds
      -host <ip>   only packets from or to this address (a name is resolved)
      -src <ip>    only packets from this address
      -dst <ip>    only packets to this address
      -port <n>    only packets from or to this port
      -sport <n>   only packets from this port
      -dport <n>   only packets to this port
      -proto <p>   only tcp, udp or icmp
                   (filters combine: -src 10.0.0.5 -dport 443 is one direction)
      -w <file>    also write a .pcapng file to open in Wireshark
      -6           capture IPv6 instead of IPv4
      (Administrator required; IP packets only, so no ARP - use lldp for layer 2)


Examples:
  nwtoolkit ping 8.8.8.8 -t
  nwtoolkit trace switch.example.com -m
  nwtoolkit dns example.com -s 1.1.1.1 -type MX
  nwtoolkit dnsspeed example.com -s 1.1.1.1
  nwtoolkit dhcp -s 192.168.1.1
  nwtoolkit tcpdump -i Ethernet -port 53 -c 20
  nwtoolkit tcpdump -proto tcp -host 10.0.0.1 -w capture.pcapng
  nwtoolkit tcpdump -src 192.168.1.10 -dport 443
";

    public static void Usage() => Console.Write(UsageText());

    /// <summary>
    /// Entry point shared by every platform. <paramref name="runGui"/> opens the native
    /// window; pass null where there is none.
    /// </summary>
    public static int Run(string[] argv, Action? runGui)
    {
        CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
        try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch { }

        UseColor = Term.EnableVT();
        var args = StripKeepOpen(argv);
        try
        {
            if (args.Length == 0)
            {
                // Double-clicked from Explorer -> native Windows window (GUI).
                // No arguments from a terminal -> the interactive console menu.
                if (Term.LaunchedFromExplorer() && runGui != null) runGui();
                else InteractiveMenu();
                return 0;
            }

            var cmd = args[0].ToLowerInvariant();
            var rest = args[1..];
            switch (cmd)
            {
                case "help": case "-h": case "--help": case "/?":
                    Usage();
                    break;
                case "version": case "-v": case "--version":
                    Console.WriteLine("nwtoolkit " + Util.Version);
                    if (UpdateCheck.Latest(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult() is { } upd)
                        Console.WriteLine(Col(CYellow, $"update available: {upd.Latest}") + "  " + upd.Url);
                    break;
                case "ping":
                    RunPing(rest);
                    break;
                case "trace": case "traceroute": case "tracert":
                    RunTrace(rest);
                    break;
                case "dns": case "nslookup":
                    RunDns(rest, false);
                    break;
                case "dnsspeed": case "dnstest":
                    RunDns(rest, true);
                    break;
                case "dhcp": case "dhcptest":
                    RunDhcp(rest);
                    break;
                case "lldp": case "cdp": case "neighbor": case "buur":
                    RunLldp(rest);
                    break;
                case "tcpdump": case "dump": case "capture": case "sniff":
                    RunTcpdump(rest);
                    break;
                case "menu":
                    InteractiveMenu();
                    break;
                case "gui": case "window":
                    if (runGui != null) runGui();
                    else
                    {
                        Console.WriteLine("The native window UI is only available on Windows. Use the command line, or the menu below.");
                        InteractiveMenu();
                    }
                    break;
                default:
                    Console.Error.WriteLine($"unknown command: {cmd}\n");
                    Usage();
                    return 2;
            }
            return 0;
        }
        finally
        {
            HoldIfNeeded();
        }
    }

    /// <summary>
    /// Separates positional arguments from flags. boolFlags holds the names of flags that
    /// take no value, so that "-s host -1" does not read '-1' as the value of -s. This
    /// lets flags appear both before and after the host.
    /// </summary>
    public static (List<string> Positionals, List<string> Flags) SplitArgs(IReadOnlyList<string> args, ISet<string> boolFlags)
    {
        var positionals = new List<string>();
        var flags = new List<string>();
        for (var i = 0; i < args.Count; i++)
        {
            var a = args[i];
            if (a == "--")
            {
                for (var j = i + 1; j < args.Count; j++) positionals.Add(args[j]);
                break;
            }
            if (a.StartsWith('-') && a.Length > 1)
            {
                flags.Add(a);
                var name = a.TrimStart('-');
                if (name.Contains('=') || boolFlags.Contains(name)) continue; // the value is already bound, or it is a bool flag
                if (i + 1 < args.Count)
                {
                    flags.Add(args[i + 1]);
                    i++;
                }
                continue;
            }
            positionals.Add(a);
        }
        return (positionals, flags);
    }

    static (string Host, List<string> Flags) FirstPositional(string[] args, params string[] boolFlags)
    {
        var (pos, flags) = SplitArgs(args, new HashSet<string>(boolFlags));
        return (pos.Count > 0 ? pos[0] : "", flags);
    }

    static void RunPing(string[] args)
    {
        var (host, rest) = FirstPositional(args, "t", "n", "6");
        var fs = new FlagSet("ping");
        var c = fs.Int("c", 4);
        var t = fs.Bool("t");
        var i = fs.Double("i", 1);
        var w = fs.Double("w", 2);
        var s = fs.Int("s", 32);
        var n = fs.Bool("n");
        var six = fs.Bool("6");
        fs.Parse(rest);
        if (host == "") Die("specify a host: nwtoolkit ping <host>");
        PingCmd.Run(new PingOpts { Host = host, Count = t.Value ? 0 : c.Value, Interval = Dur(i.Value), Timeout = Dur(w.Value), Size = s.Value, IPv6 = six.Value, Resolve = n.Value });
    }

    static void RunTrace(string[] args)
    {
        var (host, rest) = FirstPositional(args, "m", "n", "6");
        var fs = new FlagSet("trace");
        var m = fs.Bool("m");
        var i = fs.Double("i", 3);
        var h = fs.Int("h", 30);
        var q = fs.Int("q", 3);
        var n = fs.Bool("n");
        var six = fs.Bool("6");
        fs.Parse(rest);
        if (host == "") Die("specify a host: nwtoolkit trace <host>");
        Traceroute.Run(new TraceOpts { Host = host, MaxHops = h.Value, Probes = q.Value, Timeout = TimeSpan.FromSeconds(2), Monitor = m.Value, Interval = Dur(i.Value), Resolve = n.Value, IPv6 = six.Value });
    }

    static void RunDns(string[] args, bool speed)
    {
        var (name, rest) = FirstPositional(args, "1", "m", "6");
        var fs = new FlagSet("dns");
        var s = fs.String("s", "");
        // the speed test defaults to a light HINFO query; a plain dns query uses A
        var six6 = rest.Any(a => a == "-6" || a == "--6");
        var defType = six6 ? "AAAA" : "A";
        if (speed) defType = "HINFO";
        var typ = fs.String("type", defType);
        var one = fs.Bool("1");
        var m = fs.Bool("m", speed);
        var i = fs.Double("i", 5);
        var c = fs.Int("c", 0);
        var six = fs.Bool("6");
        fs.Parse(rest);
        if (name == "") Die("specify a name: nwtoolkit dns <name>");
        var o = new DnsOpts
        {
            Name = name, Server = s.Value, Qtype = typ.Value, Timeout = TimeSpan.FromSeconds(3),
            Speed = speed, Monitor = m.Value && !one.Value, Interval = Dur(i.Value), Count = c.Value, IPv6 = six.Value,
        };
        if (c.Value > 0) o.Monitor = false; // a fixed sample count takes precedence over monitoring
        if (one.Value)
        {
            o.Monitor = false;
            if (speed) o.Count = 1;
        }
        DnsCmd.Run(o);
    }

    static void RunDhcp(string[] args)
    {
        var (_, rest) = SplitArgs(args, new HashSet<string> { "1", "m", "6" });
        var fs = new FlagSet("dhcp");
        var s = fs.String("s", "");
        var one = fs.Bool("1");
        var m = fs.Bool("m", true);
        var i = fs.Double("i", DhcpOpts.DefaultInterval.TotalSeconds);
        var c = fs.Int("c", 0);
        var port = fs.Int("port", 0);
        var six = fs.Bool("6");
        fs.Parse(rest);
        var o = new DhcpOpts { Server = s.Value, Monitor = m.Value && !one.Value, Interval = Dur(i.Value), Count = c.Value, Port = port.Value, IPv6 = six.Value };
        if (c.Value > 0) o.Monitor = false;
        if (one.Value)
        {
            o.Monitor = false;
            o.Count = 1;
        }
        Dhcp.Run(o);
    }

    static void RunLldp(string[] args)
    {
        var (_, rest) = SplitArgs(args, new HashSet<string> { "m", "l" });
        var fs = new FlagSet("lldp");
        var w = fs.Double("w", 35);
        var m = fs.Bool("m");
        var l = fs.Bool("l");
        fs.Parse(rest);
        // LLDP capture needs elevated rights (pktmon on Windows). Offer to restart with
        // a UAC prompt when we are not elevated and are actually going to capture.
        if (!l.Value && !Elevation.IsElevated() && PromptRestartAsAdmin("LLDP capture"))
        {
            try
            {
                Elevation.RelaunchAsAdmin(new[] { "lldp" }.Concat(args).Append("-keepopen"));
            }
            catch (Exception e)
            {
                Die($"could not restart as administrator: {e.Message}");
            }
            return;
        }
        Lldp.Run(new LldpOpts { Wait = Dur(w.Value), Monitor = m.Value, List = l.Value });
    }

    static void RunTcpdump(string[] args)
    {
        var (_, rest) = SplitArgs(args, new HashSet<string> { "l", "6" });
        var fs = new FlagSet("tcpdump");
        var i = fs.String("i", "");
        var l = fs.Bool("l");
        var c = fs.Int("c", 0);
        var d = fs.Double("d", 0);
        var host = fs.String("host", "");
        var src = fs.String("src", "");
        var dst = fs.String("dst", "");
        var port = fs.Int("port", 0);
        var sport = fs.Int("sport", 0);
        var dport = fs.Int("dport", 0);
        var proto = fs.String("proto", "");
        var w = fs.String("w", "");
        var six = fs.Bool("6");
        fs.Parse(rest);
        var o = new DumpOpts
        {
            Iface = i.Value, List = l.Value, Count = c.Value, Duration = Dur(d.Value),
            Host = host.Value, SrcHost = src.Value, DstHost = dst.Value,
            Port = port.Value, SrcPort = sport.Value, DstPort = dport.Value,
            Proto = proto.Value, File = w.Value, IPv6 = six.Value,
        };
        // The raw socket needs Administrator; listing the interfaces does not.
        if (!o.List && !Elevation.IsElevated() && PromptRestartAsAdmin("Packet capture"))
        {
            try
            {
                Elevation.RelaunchAsAdmin(new[] { "tcpdump" }.Concat(args).Append("-keepopen"));
            }
            catch (Exception e)
            {
                Die($"could not restart as administrator: {e.Message}");
            }
            return;
        }
        Tcpdump.Run(o);
    }

    // ---- interactive menu (when the exe is started without arguments in a terminal) ----

    public static void InteractiveMenu()
    {
        string Ask(string prompt, string def)
        {
            Console.Write(def != "" ? $"{prompt} [{def}]: " : $"{prompt}: ");
            var line = Console.ReadLine();
            if (line == null) return ""; // end of input: leave the menu
            line = line.Trim();
            return line == "" ? def : line;
        }
        bool Yes(string prompt, string def) => Ask(prompt, def).StartsWith('y');

        while (true)
        {
            Console.Write(ClrScr);
            Console.WriteLine(Col(CBold, "  nwtoolkit " + Util.Version) + "  —  network diagnostics");
            Console.WriteLine(Col(CGrey, "  ────────────────────────────────────"));
            Console.WriteLine("   1)  Ping");
            Console.WriteLine("   2)  Traceroute");
            Console.WriteLine("   3)  DNS query (with response time)");
            Console.WriteLine("   4)  DNS speed test (chart)");
            Console.WriteLine("   5)  DHCP speed test (chart)");
            Console.WriteLine("   6)  LLDP neighbour (connected switch/port)");
            Console.WriteLine("   7)  Packet capture (tcpdump)");
            Console.WriteLine("   0)  Exit");
            Console.WriteLine();
            var choice = Ask("  Choice", "");

            switch (choice)
            {
                case "1":
                {
                    var host = Ask("  Host/IP", "1.1.1.1");
                    var cont = Yes("  Ping continuously? (y/n)", "n");
                    PingCmd.Run(new PingOpts { Host = host, Count = cont ? 0 : 4, Interval = TimeSpan.FromSeconds(1), Timeout = TimeSpan.FromSeconds(2), Size = 32 });
                    break;
                }
                case "2":
                {
                    var host = Ask("  Host/IP", "example.com");
                    var mon = Yes("  Monitor continuously? (y/n)", "n");
                    Traceroute.Run(new TraceOpts { Host = host, MaxHops = 30, Probes = 3, Timeout = TimeSpan.FromSeconds(2), Monitor = mon, Interval = TimeSpan.FromSeconds(3), Resolve = true });
                    break;
                }
                case "3":
                {
                    var name = Ask("  Name", "example.com");
                    var srv = Ask("  DNS server (empty=system)", "");
                    var typ = Ask("  Type", "A");
                    DnsCmd.Run(new DnsOpts { Name = name, Server = srv, Qtype = typ, Timeout = TimeSpan.FromSeconds(3) });
                    break;
                }
                case "4":
                {
                    var name = Ask("  Name", "example.com");
                    var srv = Ask("  DNS server (empty=system)", "");
                    var cont = Ask("  Continuous (chart) or one-shot? (c/o)", "c").StartsWith('c');
                    var o = new DnsOpts { Name = name, Server = srv, Qtype = "A", Timeout = TimeSpan.FromSeconds(3), Speed = true, Interval = TimeSpan.FromSeconds(5), Monitor = cont };
                    if (!cont) o.Count = 1;
                    DnsCmd.Run(o);
                    break;
                }
                case "5":
                {
                    var srv = Ask("  DHCP server IP (empty=broadcast)", "");
                    var cont = Ask("  Continuous (chart) or one-shot? (c/o)", "c").StartsWith('c');
                    var o = new DhcpOpts { Server = srv, Monitor = cont };
                    if (!cont) o.Count = 1;
                    Dhcp.Run(o);
                    break;
                }
                case "6":
                {
                    var mon = Yes("  Monitor continuously? (y/n)", "n");
                    Lldp.Run(new LldpOpts { Wait = TimeSpan.FromSeconds(35), Monitor = mon });
                    break;
                }
                case "7":
                {
                    foreach (var d in Sniffer.Interfaces(false)) Console.WriteLine(Col(CGrey, $"    {d.Name}  ({d.Ip})"));
                    var iface = Ask("  Interface (empty = default adapter)", "");
                    var filter = Ask("  Filter: host/IP (empty = all)", "");
                    var port = Ask("  Filter: port (empty = all)", "");
                    var count = Ask("  Stop after how many packets", "50");
                    Tcpdump.Run(new DumpOpts
                    {
                        Iface = iface,
                        Host = filter,
                        Port = int.TryParse(port, out var p) ? p : 0,
                        Count = int.TryParse(count, out var n) ? n : 50,
                    });
                    break;
                }
                case "0": case "q": case "": case "":
                    return;
                default:
                    continue;
            }
            Console.Write("\n  " + Col(CGrey, "Press Enter to return to the menu…"));
            if (Console.ReadLine() == null) return;
        }
    }

    /// <summary>
    /// Removes the internal -keepopen marker from the argument list and records that this
    /// run should pause before its window closes. RelaunchAsAdmin adds the marker so an
    /// elevated copy launched in a fresh console stays readable instead of vanishing the
    /// moment the command finishes.
    /// </summary>
    public static string[] StripKeepOpen(string[] args)
    {
        var out_ = new List<string>(args.Length);
        foreach (var a in args)
        {
            if (a == "-keepopen" || a == "--keepopen")
            {
                HoldOnExit = true;
                continue;
            }
            out_.Add(a);
        }
        return out_.ToArray();
    }

    /// <summary>Asks, on the console, whether to relaunch elevated. Returns false at once when there is no console to read from.</summary>
    static bool PromptRestartAsAdmin(string what)
    {
        Console.Write($"{what} needs administrator rights. Restart as administrator? (y/n): ");
        string? line;
        try { line = Console.ReadLine(); }
        catch { return false; }
        return line != null && line.Trim().StartsWith('y');
    }
}

/// <summary>A typed flag value, filled in by <see cref="FlagSet.Parse"/>.</summary>
public sealed class Opt<T>
{
    public T Value;
    public Opt(T def) => Value = def;
}

/// <summary>
/// A small flag parser in the style of Go's flag package: -name value, -name=value,
/// --name; bool flags take no value. Unknown flags and bad values print the usage and
/// exit with code 2.
/// </summary>
public sealed class FlagSet
{
    readonly string name;
    readonly Dictionary<string, (bool IsBool, Action<string> Set)> flags = new();

    public FlagSet(string name) => this.name = name;

    public Opt<int> Int(string flag, int def)
    {
        var o = new Opt<int>(def);
        flags[flag] = (false, v => o.Value = int.Parse(v, CultureInfo.InvariantCulture));
        return o;
    }

    public Opt<double> Double(string flag, double def)
    {
        var o = new Opt<double>(def);
        flags[flag] = (false, v => o.Value = double.Parse(v, CultureInfo.InvariantCulture));
        return o;
    }

    public Opt<string> String(string flag, string def)
    {
        var o = new Opt<string>(def);
        flags[flag] = (false, v => o.Value = v);
        return o;
    }

    public Opt<bool> Bool(string flag, bool def = false)
    {
        var o = new Opt<bool>(def);
        flags[flag] = (true, v => o.Value = v == "" || v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1");
        return o;
    }

    public void Parse(IReadOnlyList<string> args)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var a = args[i];
            if (a == "--") break;
            if (!a.StartsWith('-') || a.Length < 2) continue;
            var key = a.TrimStart('-');
            string? value = null;
            var eq = key.IndexOf('=');
            if (eq >= 0)
            {
                value = key[(eq + 1)..];
                key = key[..eq];
            }
            if (!flags.TryGetValue(key, out var f))
                Fail($"flag provided but not defined: -{key}");
            if (!f.IsBool && value == null)
            {
                if (i + 1 >= args.Count) Fail($"flag needs an argument: -{key}");
                value = args[++i];
            }
            try
            {
                f.Set(value ?? "");
            }
            catch (FormatException)
            {
                Fail($"invalid value \"{value}\" for flag -{key}");
            }
            catch (OverflowException)
            {
                Fail($"invalid value \"{value}\" for flag -{key}");
            }
        }
    }

    void Fail(string msg)
    {
        Console.Error.WriteLine($"{name}: {msg}");
        Console.Error.WriteLine();
        Cli.Usage();
        Util.HoldIfNeeded();
        Environment.Exit(2);
    }
}

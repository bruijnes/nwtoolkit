using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using static Nwtoolkit.Util;

namespace Nwtoolkit;

public sealed class DnsOpts
{
    public string Name = "";
    public string Server = ""; // empty = the system resolver
    public string Qtype = "A";
    public TimeSpan Timeout = TimeSpan.FromSeconds(3);
    // speed test
    public bool Speed;
    public bool Monitor;
    public TimeSpan Interval = TimeSpan.FromSeconds(5);
    public int Count;
    public bool IPv6;
}

public static class DnsCmd
{
    /// <summary>
    /// Returns the endpoint for the DNS server, resolving the host to the chosen IP
    /// family if it is a name. An empty server means the system resolver.
    /// </summary>
    public static IPEndPoint ServerAddr(string server, bool v6)
    {
        server = server.Trim();
        if (server == "") return DefaultServer(v6);

        // already host:port, [v6]:port, a bare IPv4/IPv6 literal, or a bare name
        string host;
        var port = 53;
        if (server.StartsWith('['))
        {
            var close = server.IndexOf(']');
            if (close < 0) throw new Exception($"bad server address: {server}");
            host = server[1..close];
            var rest = server[(close + 1)..];
            if (rest.StartsWith(':') && !int.TryParse(rest[1..], out port)) throw new Exception($"bad port in {server}");
        }
        else if (IPAddress.TryParse(server, out var lit))
        {
            return new IPEndPoint(lit, 53);
        }
        else
        {
            var colon = server.LastIndexOf(':');
            if (colon > 0 && server.IndexOf(':') == colon)
            {
                host = server[..colon];
                if (!int.TryParse(server[(colon + 1)..], out port)) throw new Exception($"bad port in {server}");
            }
            else
            {
                host = server;
            }
        }
        if (IPAddress.TryParse(host, out var ip)) return new IPEndPoint(ip, port);
        return new IPEndPoint(ResolveIP(host, v6), port);
    }

    /// <summary>The first DNS server of an operational interface, preferring the wanted family.</summary>
    public static IPEndPoint DefaultServer(bool v6)
    {
        var want = v6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        IPAddress? any = null;
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var dns in nic.GetIPProperties().DnsAddresses)
                {
                    if (dns.AddressFamily == want) return new IPEndPoint(dns, 53);
                    any ??= dns;
                }
            }
        }
        catch { }
        if (any != null) return new IPEndPoint(any, 53);
        return new IPEndPoint(v6 ? IPAddress.Parse("2001:4860:4860::8888") : IPAddress.Parse("8.8.8.8"), 53);
    }

    public static string Show(IPEndPoint ep) => ep.ToString();

    public static void Run(DnsOpts o)
    {
        IPEndPoint server;
        try { server = ServerAddr(o.Server, o.IPv6); }
        catch (Exception e) { Die(e.Message); return; }
        var qtype = DnsWire.TypeCode(o.Qtype);

        if (!o.Speed && !o.Monitor)
        {
            Console.WriteLine($"Server:  {Show(server)}");
            Console.WriteLine($"Query:   {o.Name} {o.Qtype.ToUpperInvariant()}");
            TimeSpan rtt;
            List<string> ans;
            try
            {
                (rtt, ans) = DnsWire.Query(server, o.Name, qtype, o.Timeout);
            }
            catch (DnsRcodeException e)
            {
                Console.WriteLine($"Error:   {Col(CRed, e.Message)}   ({Ms(e.Rtt).F(2)} ms)");
                HoldIfNeeded();
                Environment.Exit(1);
                return;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error:   {Col(CRed, e.Message)}");
                HoldIfNeeded();
                Environment.Exit(1);
                return;
            }
            var ms = Ms(rtt);
            var c = ms > 50 ? CYellow : CGreen;
            Console.WriteLine($"Time:    {Col(c, ms.F(2) + " ms")}");
            Console.WriteLine("Answer:");
            if (ans.Count == 0) Console.WriteLine("  (no records)");
            foreach (var a in ans) Console.WriteLine("  " + a);
            return;
        }

        // speed test / monitor
        SpeedGraph.Run(new SpeedGraphCfg
        {
            Title = $"DNS speed test  server={Show(server)}  query={o.Name} {o.Qtype.ToUpperInvariant()}",
            Unit = "ms",
            Interval = o.Interval,
            Count = o.Count,
            Monitor = o.Monitor,
            Measure = () =>
            {
                try
                {
                    var (rtt, ans) = DnsWire.Query(server, o.Name, qtype, o.Timeout);
                    return (Ms(rtt), ans.Count > 0 ? ans[0] : "", null);
                }
                catch (Exception e)
                {
                    return (0, "", e.Message);
                }
            },
        });
    }
}

/// <summary>Shared speed test and chart runner, also used by DHCP.</summary>
public sealed class SpeedGraphCfg
{
    public string Title = "";
    public string Unit = "ms";
    public TimeSpan Interval = TimeSpan.FromSeconds(5);
    public int Count;
    public bool Monitor;
    /// <summary>Returns the value, a short info string and an error message (null when ok).</summary>
    public Func<(double Value, string Info, string? Error)> Measure = () => (0, "", null);
}

public static class SpeedGraph
{
    public static void Run(SpeedGraphCfg cfg)
    {
        using var ctrlC = new CtrlC();
        var r = new Ring(120);
        int lost = 0, n = 0;

        void Draw(string lastInfo, string? lastErr)
        {
            if (cfg.Monitor) Console.Write(ClrScr);
            Console.WriteLine($"{Col(CBold, "nwtoolkit")}  {cfg.Title}");
            if (r.Buf.Count >= 2)
            {
                var g = AsciiGraph.Plot(r.Buf, 12, 100, $"last {r.Buf.Count} samples ({cfg.Unit})");
                Console.WriteLine();
                Console.WriteLine(g);
            }
            var st = Stats.Compute(r.Buf, lost);
            Console.WriteLine();
            var last = "-";
            if (lastErr != null)
            {
                last = Col(CRed, "ERROR: " + lastErr);
            }
            else if (r.Buf.Count > 0)
            {
                var v = r.Buf[^1];
                var c = v > st.Avg * 1.5 ? CYellow : CGreen;
                last = Col(c, $"{v.F(2)} {cfg.Unit}") + "   " + Col(CGrey, lastInfo);
            }
            Console.WriteLine($"last: {last}");
            Console.WriteLine($"min {st.Min.F(2)} {cfg.Unit}  avg {st.Avg.F(2)} {cfg.Unit}  max {st.Max.F(2)} {cfg.Unit}  p95 {Percentile(r.Buf, 95).F(2)} {cfg.Unit}   samples {n}  errors {lost}");
            if (cfg.Monitor) Console.WriteLine(Col(CGrey, "\nCtrl+C to stop"));
        }

        while (true)
        {
            var (v, info, err) = cfg.Measure();
            n++;
            if (err != null) lost++;
            else r.Push(v);

            if (cfg.Monitor || cfg.Count == 0)
            {
                Draw(info, err);
            }
            else
            {
                // single or fixed-count run: one line per measurement
                if (err != null) Console.WriteLine($"  {NowStamp()}  {Col(CRed, "error: " + err)}");
                else Console.WriteLine($"  {NowStamp()}  {v.F(2)} {cfg.Unit}   {Col(CGrey, info)}");
            }

            if (!cfg.Monitor && cfg.Count > 0 && n >= cfg.Count)
            {
                if (cfg.Count > 1) Console.WriteLine($"\n{Stats.Compute(r.Buf, lost)}");
                return;
            }
            if (ctrlC.Wait(cfg.Interval))
            {
                if (!cfg.Monitor) Console.WriteLine($"\n{Stats.Compute(r.Buf, lost)}");
                Console.WriteLine("\nstopped.");
                return;
            }
        }
    }
}

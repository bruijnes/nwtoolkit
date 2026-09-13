using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using static Nwtoolkit.Util;

namespace Nwtoolkit;

public sealed class TraceOpts
{
    public string Host = "";
    public int MaxHops = 30;
    public int Probes = 3;
    public TimeSpan Timeout = TimeSpan.FromSeconds(2);
    public bool Monitor;
    public TimeSpan Interval = TimeSpan.FromSeconds(3);
    public bool Resolve;
    public bool IPv6;
}

public sealed class HopResult
{
    public int N;
    public IPAddress? Ip;
    public List<double> Rtts = new(); // per probe, -1 = timeout
    public string Name = "";
    public bool Reached;
}

public static class Traceroute
{
    static readonly byte[] payload = Encoding.ASCII.GetBytes("nwtoolkit-traceroute");

    /// <summary>Performs one complete traceroute.</summary>
    public static List<HopResult> RunTrace(Echo echo, IPAddress dst, TraceOpts o, CancellationToken ct = default)
    {
        var hops = new List<HopResult>();
        for (var ttl = 1; ttl <= o.MaxHops && !ct.IsCancellationRequested; ttl++)
        {
            var hr = new HopResult { N = ttl };
            for (var p = 0; p < o.Probes; p++)
            {
                var r = echo.Send(dst, ttl, o.Timeout, payload);
                if (r.NoAnswer)
                {
                    hr.Rtts.Add(-1);
                    continue;
                }
                hr.Ip = r.Peer;
                hr.Rtts.Add(r.Ms);
                if (r.Status == IPStatus.Success) hr.Reached = true;
            }
            if (o.Resolve && hr.Ip != null) hr.Name = ReverseDns.Name(hr.Ip);
            hops.Add(hr);
            if (hr.Reached) break;
        }
        return hops;
    }

    public static void PrintHops(IPAddress dst, string host, List<HopResult> hops)
    {
        var last = hops.Count > 0 ? hops[^1].N : 0;
        Console.WriteLine($"traceroute to {host} ({dst}), max {last} hops   {Col(CGrey, "(all times in ms)")}");
        foreach (var hr in hops)
        {
            var b = new StringBuilder();
            b.Append($" {hr.N,2}  ");
            if (hr.Ip == null)
            {
                b.Append(Col(CGrey, "* * *  (no answer)"));
            }
            else
            {
                foreach (var r in hr.Rtts)
                {
                    if (r < 0)
                    {
                        b.Append(Col(CGrey, "   *    "));
                    }
                    else
                    {
                        var c = CGreen;
                        if (r > 50) c = CYellow;
                        if (r > 150) c = CRed;
                        b.Append(Col(c, r.F(2).PadLeft(6) + "  "));
                    }
                }
                var target = hr.Ip.ToString();
                if (hr.Name != "") target = $"{hr.Name} ({hr.Ip})";
                b.Append(' ').Append(target);
                if (hr.Reached) b.Append(Col(CGreen, "  <== target"));
            }
            Console.WriteLine(b.ToString());
        }
    }

    sealed class Agg
    {
        public IPAddress? Ip;
        public string Name = "";
        public List<double> Samples = new();
        public int Lost, Total;
        public bool Reached;
    }

    public static void Run(TraceOpts o)
    {
        IPAddress dst;
        try { dst = ResolveIP(o.Host, o.IPv6); }
        catch (Exception e) { Die(e.Message); return; }

        using var echo = new Echo();

        if (!o.Monitor)
        {
            var hops = RunTrace(echo, dst, o);
            PrintHops(dst, o.Host, hops);
            return;
        }

        // Continuous mode: repeat every interval, clear the screen, summarising min/avg/max per hop.
        using var ctrlC = new CtrlC();
        var aggs = new Dictionary<int, Agg>();
        var round = 0;

        void Draw()
        {
            Console.Write(ClrScr);
            Console.WriteLine($"{Col(CBold, "nwtoolkit")}  traceroute monitor to {o.Host} ({dst})   round {round}   every {o.Interval.TotalSeconds.F(0)}s   Ctrl+C to stop\n");
            Console.WriteLine($" {"hop",-3} {"address",-32} {"last",8} {"min",8} {"avg",8} {"max",8} {"loss",7}");
            Console.WriteLine($" {"",-3} {"",-32} {"(ms)",8} {"(ms)",8} {"(ms)",8} {"(ms)",8} {"",7}");
            Console.WriteLine(new string('-', 86));
            var maxHop = aggs.Count == 0 ? 0 : aggs.Keys.Max();
            for (var i = 1; i <= maxHop; i++)
            {
                if (!aggs.TryGetValue(i, out var a))
                {
                    Console.WriteLine($" {i,-3} {Col(CGrey, "* (no answer)")}");
                    continue;
                }
                var addr = "*";
                if (a.Ip != null)
                {
                    addr = a.Ip.ToString();
                    if (a.Name != "") addr = a.Name;
                }
                if (addr.Length > 32) addr = addr[..31] + "…";
                var st = Stats.Compute(a.Samples, a.Lost);
                var last = a.Samples.Count > 0 ? a.Samples[^1] : 0.0;
                var lc = CGreen;
                if (st.Loss > 0) lc = CYellow;
                if (st.Loss >= 50) lc = CRed;
                var mark = a.Reached ? Col(CGreen, " ⇐ target") : "";
                Console.WriteLine($" {i,-3} {addr,-32} {last.F(2),8} {st.Min.F(2),8} {st.Avg.F(2),8} {st.Max.F(2),8} {Col(lc, st.Loss.F(0).PadLeft(6) + "%")}{mark}");
            }
        }

        while (true)
        {
            round++;
            var hops = RunTrace(echo, dst, o, ctrlC.Token);
            foreach (var hr in hops)
            {
                if (!aggs.TryGetValue(hr.N, out var a))
                {
                    a = new Agg();
                    aggs[hr.N] = a;
                }
                if (hr.Ip != null)
                {
                    a.Ip = hr.Ip;
                    a.Name = hr.Name;
                }
                if (hr.Reached) a.Reached = true;
                foreach (var r in hr.Rtts)
                {
                    a.Total++;
                    if (r < 0)
                    {
                        a.Lost++;
                    }
                    else
                    {
                        a.Samples.Add(r);
                        if (a.Samples.Count > 300) a.Samples.RemoveRange(0, a.Samples.Count - 300);
                    }
                }
            }
            Draw();

            if (ctrlC.Wait(o.Interval))
            {
                Console.WriteLine("\nstopped.");
                return;
            }
        }
    }

    /// <summary>Plain-text route listing for the GUI.</summary>
    public static string TraceText(string host, string dst, List<HopResult> hops)
    {
        var sb = new StringBuilder();
        sb.Append($"traceroute to {host} ({dst})\r\n\r\n");
        sb.Append($"{"hop",-3}  {"address",-36}  rtt (ms)\r\n");
        sb.Append(new string('-', 62)).Append("\r\n");
        foreach (var hr in hops)
        {
            var addr = "* * *";
            if (hr.Ip != null)
            {
                addr = hr.Ip.ToString();
                if (hr.Name != "") addr = $"{hr.Name} ({hr.Ip})";
            }
            var rtts = hr.Rtts.Select(r => r < 0 ? "*" : r.F(2));
            var mark = hr.Reached ? "   <= target" : "";
            sb.Append($"{hr.N,-3}  {addr,-36}  {string.Join("  ", rtts)}{mark}\r\n");
        }
        return sb.ToString();
    }
}

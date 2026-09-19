using static Nwtoolkit.Util;

namespace Nwtoolkit;

public sealed class DumpOpts
{
    public string Iface = "";          // name, description or IP; empty = the default adapter
    public int Count;                  // stop after n packets; 0 = until Ctrl+C
    public TimeSpan Duration;          // stop after this long; zero = no limit
    public string Host = "";           // only packets from or to this address
    public string SrcHost = "";        // only packets from this address
    public string DstHost = "";        // only packets to this address
    public int Port;                   // only packets from or to this port
    public int SrcPort;                // only packets from this port
    public int DstPort;                // only packets to this port
    public string Proto = "";          // tcp, udp, icmp
    public string File = "";           // also write the packets to this .pcapng
    public bool IPv6;
    public bool List;

    /// <summary>The filter these options describe; the console, the window and the capture all build it the same way.</summary>
    public CaptureFilter Filter() => new()
    {
        Host = Host, SrcHost = SrcHost, DstHost = DstHost,
        Port = Port, SrcPort = SrcPort, DstPort = DstPort,
        Proto = Proto,
    };
}

/// <summary>What one capture run ended up doing, for the closing summary.</summary>
public readonly record struct DumpResult(int Captured, int Seen);

/// <summary>Live packet capture in the style of tcpdump: one line per packet, optional .pcapng.</summary>
public static class Tcpdump
{
    /// <summary>
    /// Captures until the packet count, the duration or the token says stop, handing every
    /// packet that survives the filter to <paramref name="onPacket"/>. <paramref
    /// name="onIdle"/> runs whenever a tick passes with nothing to report, which lets the
    /// window flush its buffered lines on a quiet network.
    /// </summary>
    public static DumpResult Capture(DumpOpts o, NetIface nic, Action<CapturedPacket> onPacket, CancellationToken token, Action? onIdle = null)
    {
        var filter = o.Filter();
        filter.Prepare();
        using var cap = new LiveCapture(nic.Ip);
        using var writer = o.File == "" ? null : new PcapngWriter(o.File, nic.Name);
        var buf = new byte[65536];
        var deadline = o.Duration > TimeSpan.Zero ? DateTime.UtcNow + o.Duration : DateTime.MaxValue;
        int kept = 0, seen = 0;
        while (!token.IsCancellationRequested && DateTime.UtcNow < deadline)
        {
            var len = cap.Receive(buf);
            if (len <= 0)
            {
                onIdle?.Invoke();
                continue;
            }
            seen++;
            var now = DateTime.Now;
            var pkt = PacketDecode.Parse(buf.AsSpan(0, len), now);
            if (pkt == null || !filter.Matches(pkt)) continue;
            writer?.Write(now, buf.AsSpan(0, len));
            onPacket(pkt);
            kept++;
            if (o.Count > 0 && kept >= o.Count) break;
        }
        return new DumpResult(kept, seen);
    }

    public static void Run(DumpOpts o)
    {
        if (o.List)
        {
            var devs = Sniffer.Interfaces(o.IPv6);
            if (devs.Count == 0)
            {
                Console.WriteLine($"no interface with an {(o.IPv6 ? "IPv6" : "IPv4")} address is up.");
                return;
            }
            var def = Sniffer.Default(o.IPv6);
            Console.WriteLine("Interfaces available for capture:");
            foreach (var d in devs)
                Console.WriteLine($"  {d.Name,-28} {d.Ip}{(d.Name == def?.Name ? Col(CGrey, "   (default)") : "")}");
            return;
        }

        NetIface nic;
        try { nic = Sniffer.Select(o.Iface, o.IPv6); }
        catch (Exception e)
        {
            Die(e.Message);
            return;
        }

        var filter = o.Filter().Describe();
        Console.WriteLine($"{Col(CBold, "nwtoolkit")}  capturing on {Col(CCyan, nic.Name)} ({nic.Ip}), {(o.IPv6 ? "IPv6" : "IPv4")}, no link layer");
        if (filter != "") Console.WriteLine(Col(CGrey, "filter: " + filter));
        if (o.File != "") Console.WriteLine(Col(CGrey, "writing to " + o.File));
        Console.WriteLine(Col(CGrey, StopText(o)));

        using var ctrlc = new CtrlC();
        DumpResult res;
        try
        {
            res = Capture(o, nic, p => Console.WriteLine(p.Line(true)), ctrlc.Token);
        }
        catch (Exception e)
        {
            Die(e.Message);
            return;
        }
        Console.WriteLine();
        Console.WriteLine($"{res.Captured} packet(s) captured, {res.Seen} seen on {nic.Name}");
        if (o.File != "" && res.Captured > 0) Console.WriteLine($"written to {o.File} — open it in Wireshark");
    }

    static string StopText(DumpOpts o)
    {
        if (o.Count > 0 && o.Duration > TimeSpan.Zero) return $"stopping after {o.Count} packets or {o.Duration.TotalSeconds.F(0)}s, Ctrl+C to stop sooner";
        if (o.Count > 0) return $"stopping after {o.Count} packets, Ctrl+C to stop sooner";
        if (o.Duration > TimeSpan.Zero) return $"stopping after {o.Duration.TotalSeconds.F(0)}s, Ctrl+C to stop sooner";
        return "Ctrl+C to stop";
    }
}

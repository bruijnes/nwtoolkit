using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace Nwtoolkit;

/// <summary>Chooses how a DHCP measurement is taken.</summary>
public static class DhcpProbe
{
    /// <summary>
    /// Uses nothing but what the OS ships with — no Npcap, no external driver. In order
    /// of preference on Windows:
    ///
    ///  1. Broadcast INFORM from an ephemeral port. Does not collide with the DHCP
    ///     Client service that owns port 68, and works without Administrator.
    ///  2. Broadcast DISCOVER captured with the built-in Packet Monitor (pktmon).
    ///     Sees the frame below the firewall, but requires Administrator.
    ///  3. Broadcast DISCOVER over an ordinary UDP socket on port 68. Only works if
    ///     the firewall passes the incoming answer.
    ///
    /// Elsewhere the same INFORM path comes first, with a plain DISCOVER as last resort.
    /// </summary>
    public static DhcpResult Probe(DhcpOpts o)
    {
        if (o.IPv6) return Dhcp6.Probe(o);
        // The user named a server: measure that one specifically.
        if (o.Server != "")
        {
            var res = Dhcp.ProbeUDP(o);
            if (res.Method == "") res.Method = "INFORM";
            return res;
        }
        // Otherwise always broadcast: ask the network itself, with no prior knowledge.
        return DiscoverBroadcast(o);
    }

    /// <summary>
    /// Does what a bare device does when it is first plugged into an unknown network: it
    /// asks the segment itself, with no prior knowledge of any server. The INFORM path
    /// comes first because it needs no elevation; a real DISCOVER is answered on port 68,
    /// which on Windows belongs to the DHCP Client service and is shielded by the
    /// firewall, so that path needs Packet Monitor and Administrator rights.
    /// </summary>
    static DhcpResult DiscoverBroadcast(DhcpOpts o)
    {
        var b = o.Clone();
        b.Server = ""; // no prior knowledge

        // 1. Broadcast INFORM from an ephemeral port.
        string informErr;
        try { return DhcpBroadcast.Inform(b); }
        catch (Exception e) { informErr = e.Message; }

        // 2. A real DISCOVER, captured with the built-in pktmon. Requires Administrator.
        var d = b.Clone();
        if (d.Port == 0) d.Port = 68;
        var elevated = Elevation.IsElevated();
        Exception? pktErr = null;
        if (OperatingSystem.IsWindows() && elevated)
        {
            try { return DhcpPktmon.Probe(d); }
            catch (Exception e) { pktErr = e; }
        }

        // 3. Last resort: DISCOVER over an ordinary socket on port 68.
        try
        {
            var res = Dhcp.ProbeUDP(d);
            if (res.Method == "") res.Method = "broadcast DISCOVER";
            return res;
        }
        catch { }

        throw new Exception(BroadcastFailure(informErr, pktErr, elevated, o));
    }

    /// <summary>Explains why none of the broadcast paths produced anything.</summary>
    static string BroadcastFailure(string informErr, Exception? pktErr, bool elevated, DhcpOpts o)
    {
        var b = new StringBuilder("no DHCP server answered a broadcast");
        b.Append($"\n  INFORM to 255.255.255.255: {informErr}");
        if (OperatingSystem.IsWindows())
        {
            if (!elevated) b.Append("\n  DISCOVER via pktmon: skipped, that requires Administrator");
            else if (pktErr is PktmonUnsupportedException) b.Append("\n  DISCOVER via pktmon: pktmon is not available on this Windows version");
            else if (pktErr != null) b.Append($"\n  DISCOVER via pktmon: {pktErr.Message}");
        }
        var lease = DhcpLease.For(o.Iface, o.SrcIP);
        if (lease != null)
            b.Append($"\n  The system does hold a lease from {lease.Server} on {lease.Name}; that server ignores our broadcast");
        return b.ToString();
    }
}

/// <summary>
/// The DHCP server an interface currently leases from, as the OS knows it. Readable
/// without Administrator and without a capture driver, which makes it the most reliable
/// way to learn which DHCP server is serving us.
/// </summary>
public sealed record DhcpLease(string Name, IPAddress? Ip, IPAddress Server, bool Up)
{
    public static List<DhcpLease> All()
    {
        var out_ = new List<DhcpLease>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var props = nic.GetIPProperties();
                IPAddress? server = null;
                try
                {
                    server = props.DhcpServerAddresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
                }
                catch { }
                if (server == null) continue;
                var ip = props.UnicastAddresses.Select(u => u.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                out_.Add(new DhcpLease(nic.Name, ip, server, nic.OperationalStatus == OperationalStatus.Up));
            }
        }
        catch { }
        return out_;
    }

    /// <summary>
    /// Picks the lease belonging to the requested interface or source IP. With no
    /// preference, the lease on an active interface wins, so a stale lease from a
    /// disconnected adapter does not get in the way.
    /// </summary>
    public static DhcpLease? For(string ifname, IPAddress? srcIP)
    {
        var leases = All();
        if (leases.Count == 0) return null;
        if (srcIP != null)
            foreach (var l in leases)
                if (l.Ip != null && l.Ip.Equals(srcIP))
                    return l;
        if (ifname != "")
            foreach (var l in leases)
                if (l.Name.Equals(ifname, StringComparison.OrdinalIgnoreCase) || l.Name.Contains(ifname, StringComparison.OrdinalIgnoreCase))
                    return l;
        return leases.FirstOrDefault(l => l.Up) ?? leases[0];
    }
}

/// <summary>
/// Sends a broadcast DISCOVER over an ordinary UDP socket and captures the OFFER or ACK
/// with the built-in Windows Packet Monitor (pktmon), just like the LLDP capture, so
/// entirely with what Windows ships. The OFFER arrives on port 68, owned by the DHCP
/// Client service, but pktmon sees the frame on the wire. Requires Administrator. The
/// response time comes from the pcapng timestamps.
/// </summary>
public static class DhcpPktmon
{
    public const int ToServer = 1; // 68 → 67
    public const int ToClient = 2; // 67 → 68

    public static DhcpResult Probe(DhcpOpts o)
    {
        // The DISCOVER goes out over every usable interface, each from a socket bound to
        // that interface's own address (see DhcpBroadcast for why).
        var targets = DhcpBroadcast.Targets(o);
        if (targets.Count == 0) throw new Exception("no usable IPv4 interface found");
        var where = "pktmon via " + string.Join(", ", targets.Select(t => t.Name));

        var xid = Dhcp.RandomXid();
        var t0 = DateTime.UtcNow;
        string? sendErr = null;
        DhcpResult? fromSocket = null;

        var data = Pktmon.Capture("dhcp", () =>
        {
            Thread.Sleep(Pktmon.SettleDelay);

            var (conns, errs) = SendDiscover(targets, xid);
            if (conns.Count == 0)
            {
                sendErr = "DISCOVER could not be sent anywhere: " + string.Join("; ", errs);
                return false;
            }
            t0 = DateTime.UtcNow;
            var sw = Stopwatch.StartNew();
            try
            {
                // The sockets listen along as well: sometimes the OFFER does get through, and
                // then there is no need to convert and parse the capture at all.
                var first = new TaskCompletionSource<DhcpResult>(TaskCreationOptions.RunContinuationsAsynchronously);
                foreach (var c in conns)
                {
                    var conn = c;
                    Task.Run(() =>
                    {
                        try
                        {
                            var r = Dhcp.CollectAnswers(conn, xid, sw, o.Timeout, false, "");
                            r.Method = "socket";
                            first.TrySetResult(r);
                        }
                        catch { }
                    });
                }
                if (first.Task.Wait(o.Timeout))
                {
                    fromSocket = first.Task.Result;
                    return false;
                }
                return true;
            }
            finally
            {
                foreach (var c in conns) c.Dispose();
            }
        });
        if (sendErr != null) throw new Exception(sendErr);
        if (fromSocket != null) return fromSocket;
        if (data == null) throw new Exception("capture produced no data");

        // The whole capture is scanned rather than stopping at the first answer: on an
        // unknown network you specifically want to know if more than one server responds.
        long reqTS = 0;
        DhcpResult? res = null;
        var frames = Pcapng.ParseWithTimestamps(data);
        int nDHCP = 0, nOurs = 0;
        foreach (var fr in frames)
        {
            if (IsDhcpFrame(fr.Data)) nDHCP++;
            if (!Classify(fr.Data, xid, out var mt, out var yi, out var sid, out var dir)) continue;
            nOurs++;
            if (dir == ToServer && reqTS == 0)
            {
                reqTS = fr.TsNanos;
                continue;
            }
            if (dir != ToClient || (mt != Dhcp.Offer && mt != Dhcp.Ack)) continue;
            if (res == null)
            {
                var baseNs = reqTS != 0 ? reqTS : (t0 - DateTime.UnixEpoch).Ticks * 100;
                var rttNs = fr.TsNanos - baseNs;
                if (rttNs < 0) rttNs = 0;
                res = new DhcpResult { Rtt = TimeSpan.FromTicks(rttNs / 100), Yiaddr = yi, ServerId = sid, MsgType = mt, Method = "pktmon" };
            }
            res.AddServer(sid);
        }
        if (res != null) return res;
        throw new Exception($"no answer within {o.Timeout.TotalSeconds.F(0)}s ({where}) — {CaptureDiag(data.Length, frames.Count, nDHCP, nOurs, reqTS != 0)}");
    }

    /// <summary>
    /// Opens one socket per interface, bound to that interface's own address, and
    /// broadcasts a DISCOVER from each. Returns the sockets that are listening plus a
    /// message for every interface that could not be used.
    /// </summary>
    static (List<Socket> Conns, List<string> Errs) SendDiscover(List<NetIface> targets, uint xid)
    {
        var dst = new IPEndPoint(IPAddress.Broadcast, 67);
        var conns = new List<Socket>();
        var errs = new List<string>();
        foreach (var ifc in targets)
        {
            Socket c;
            try { c = Dhcp.Listen(new IPEndPoint(ifc.Ip, 68), true); }
            catch (Exception e)
            {
                errs.Add($"{ifc.Name}: cannot open port 68 ({e.Message})");
                continue;
            }
            var mac = ifc.Mac is { Length: 6 } ? ifc.Mac : Dhcp.FallbackMac;
            try
            {
                c.SendTo(Dhcp.Build(Dhcp.Discover, xid, mac, IPAddress.Any, true), dst);
            }
            catch (Exception e)
            {
                errs.Add($"{ifc.Name}: sending failed ({e.Message})");
                c.Dispose();
                continue;
            }
            conns.Add(c);
        }
        return (conns, errs);
    }

    /// <summary>
    /// Parses a raw Ethernet frame into a DHCP message and determines its direction;
    /// returns false if it is not a usable DHCP frame carrying our xid.
    /// </summary>
    public static bool Classify(ReadOnlySpan<byte> f, uint xid, out byte msgType, out IPAddress? yiaddr, out IPAddress? serverId, out int dir)
    {
        msgType = 0;
        yiaddr = null;
        serverId = null;
        dir = 0;
        if (f.Length < 14 + 20 + 8 + 240) return false;
        if (f[12] != 0x08 || f[13] != 0x00) return false;
        var ihl = (f[14] & 0x0f) * 4;
        if (ihl < 20 || 14 + ihl + 8 > f.Length || f[14 + 9] != 17) return false;
        var udp = 14 + ihl;
        var src = BinaryPrimitives.ReadUInt16BigEndian(f[udp..]);
        var dstp = BinaryPrimitives.ReadUInt16BigEndian(f[(udp + 2)..]);
        if (src == 68 && dstp == 67) dir = ToServer;
        else if (src == 67 && dstp == 68) dir = ToClient;
        else return false;
        var payload = f[(udp + 8)..];
        if (payload.Length < 240 || BinaryPrimitives.ReadUInt32BigEndian(payload[4..]) != xid)
        {
            dir = 0;
            return false;
        }
        // Our own request is a BOOTREQUEST (op 1); Parse only accepts replies (op 2). The
        // outgoing frame has to be recognised separately here, otherwise it looks as
        // though the request never left the adapter.
        if (payload[0] == 1)
        {
            dir = ToServer;
            return true;
        }
        if (!Dhcp.Parse(payload, out msgType, out yiaddr, out serverId))
        {
            dir = 0;
            return false;
        }
        return true;
    }

    /// <summary>Whether a raw Ethernet frame is UDP traffic on port 67 or 68, regardless of transaction id.</summary>
    public static bool IsDhcpFrame(ReadOnlySpan<byte> f)
    {
        if (f.Length < 14 + 20 + 8 || f[12] != 0x08 || f[13] != 0x00) return false;
        var ihl = (f[14] & 0x0f) * 4;
        if (ihl < 20 || 14 + ihl + 8 > f.Length || f[14 + 9] != 17) return false;
        var src = BinaryPrimitives.ReadUInt16BigEndian(f[(14 + ihl)..]);
        var dst = BinaryPrimitives.ReadUInt16BigEndian(f[(14 + ihl + 2)..]);
        return src == 67 || src == 68 || dst == 67 || dst == 68;
    }

    /// <summary>Says in plain words where the pktmon measurement broke down.</summary>
    public static string CaptureDiag(int bytes, int frames, int dhcp, int ours, bool sawRequest)
    {
        if (bytes == 0) return "the pcapng from pktmon was empty; the capture did not run";
        if (frames == 0) return $"pktmon produced {bytes} bytes of pcapng but the parser found no frames at all; probably a pcapng variant this tool does not read";
        if (dhcp == 0) return $"pktmon captured {frames} frames, but not a single DHCP frame (UDP 67/68); the capture may be on a different network component than the active adapter";
        if (!sawRequest) return $"pktmon captured {frames} frames of which {dhcp} DHCP, but our own DISCOVER was not among them; the request never left the adapter";
        if (ours == 0) return $"pktmon captured {frames} frames of which {dhcp} DHCP, but none with our transaction id";
        return $"pktmon captured {frames} frames, {dhcp} DHCP, {ours} with our transaction id, but no OFFER or ACK; there is no DHCP server on this segment, or it does not answer a broadcast";
    }
}

using System.Diagnostics;
using System.Net;

namespace Nwtoolkit;

/// <summary>
/// Asks the network itself who is serving DHCP, without knowing a single server up
/// front: a DHCP INFORM to 255.255.255.255.
///
/// The difference with a DISCOVER is where the answer comes back. A DISCOVER is
/// answered on port 68, which on Windows belongs to the DHCP Client service and is
/// shielded by the firewall. An INFORM sent from an ephemeral port is answered by DHCP
/// servers on that same port, and that answer belongs to our own outbound traffic, so
/// the firewall lets it through and no elevation is required.
///
/// The request goes out over every usable interface at once, each from a socket bound
/// to that interface's own address. A socket on 0.0.0.0 leaves the choice to the
/// routing table, which sends a limited broadcast to the interface with the lowest
/// metric — on a machine with a VPN or virtual adapter that is often not the cable the
/// switch is on.
///
/// Because the request is a broadcast, every DHCP server on the segment answers. A
/// second answer is therefore an immediate signal of a rogue server. An INFORM also
/// reserves no address, so repeated measurement does not drain the pool.
/// </summary>
public static class DhcpBroadcast
{
    public static DhcpResult Inform(DhcpOpts o)
    {
        var targets = Targets(o);
        if (targets.Count == 0) throw new Exception("no usable IPv4 interface found");

        var tasks = targets.Select(ifc => Task.Run<(DhcpResult? Res, string? Err)>(() =>
        {
            try { return (InformOnIface(ifc, o), null); }
            catch (Exception e) { return (null, e.Message); }
        })).ToArray();
        Task.WaitAll(tasks);

        DhcpResult? best = null;
        var errs = new List<string>();
        foreach (var t in tasks)
        {
            var (res, err) = t.Result;
            if (res == null)
            {
                errs.Add(err ?? "unknown error");
                continue;
            }
            if (best == null || res.Rtt < best.Rtt)
            {
                // the fastest answer wins, but every server seen so far stays listed
                var accumulated = best?.Servers ?? new List<IPAddress>();
                best = res;
                foreach (var s in accumulated) best.AddServer(s);
            }
            else
            {
                foreach (var s in res.Servers) best.AddServer(s);
            }
        }
        if (best != null) return best;
        throw new Exception(string.Join("; ", Util.Dedup(errs)));
    }

    /// <summary>Decides which interfaces the request goes out on: the requested one, or otherwise all usable ones at once.</summary>
    public static List<NetIface> Targets(DhcpOpts o)
    {
        var all = Dhcp.UsableIPv4Ifaces();
        if (o.SrcIP != null)
        {
            foreach (var i in all)
                if (i.Ip.Equals(o.SrcIP))
                    return new List<NetIface> { i };
            return new List<NetIface> { new(o.Iface, o.SrcIP, Dhcp.MacForIP(o.SrcIP)) };
        }
        if (o.Iface != "")
        {
            var sel = all.Where(i => i.Name.Equals(o.Iface, StringComparison.OrdinalIgnoreCase)
                                     || i.Name.Contains(o.Iface, StringComparison.OrdinalIgnoreCase)).ToList();
            if (sel.Count > 0) return sel;
        }
        return all;
    }

    /// <summary>Sends the INFORM from one specific interface and reads the answers that come back within the timeout.</summary>
    static DhcpResult InformOnIface(NetIface ifc, DhcpOpts o)
    {
        var mac = ifc.Mac is { Length: 6 } ? ifc.Mac : Dhcp.FallbackMac;
        var xid = Dhcp.RandomXid();

        // broadcast flag off: the answer may come straight back to us.
        var packet = Dhcp.Build(Dhcp.Inform, xid, mac, ifc.Ip, false);

        System.Net.Sockets.Socket conn;
        try { conn = Dhcp.Listen(new IPEndPoint(ifc.Ip, o.Port), true); }
        catch (Exception e) { throw new Exception($"{ifc.Name}: opening socket: {e.Message}"); }
        using (conn)
        {
            var sw = Stopwatch.StartNew();
            try { conn.SendTo(packet, new IPEndPoint(IPAddress.Broadcast, 67)); }
            catch (Exception e) { throw new Exception($"{ifc.Name}: sending: {e.Message}"); }

            var res = Dhcp.CollectAnswers(conn, xid, sw, o.Timeout, true, ifc.Name);
            res.Method = "broadcast INFORM via " + ifc.Name;
            return res;
        }
    }
}

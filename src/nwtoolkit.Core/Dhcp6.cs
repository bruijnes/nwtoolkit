using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Nwtoolkit;

/// <summary>DHCPv6 INFORMATION-REQUEST probe. Not verified against a live DHCPv6 server.</summary>
public static class Dhcp6
{
    public const byte Advertise = 2, Reply = 7, InfoReq = 11;
    public const string MulticastV = "ff02::1:2"; // All_DHCP_Relay_Agents_and_Servers
    public const int ServerPort = 547;

    /// <summary>Picks an interface (index plus MAC) for DHCPv6.</summary>
    public static (byte[] Mac, int Index, string Name) PickV6Iface(string ifname)
    {
        NetworkInterface[] nics;
        try { nics = NetworkInterface.GetAllNetworkInterfaces(); }
        catch (Exception e) { throw new Exception($"listing interfaces: {e.Message}"); }
        foreach (var nic in nics)
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback || nic.OperationalStatus != OperationalStatus.Up) continue;
            if (ifname != "" && !nic.Name.Equals(ifname, StringComparison.OrdinalIgnoreCase)) continue;
            var props = nic.GetIPProperties();
            var hasV6 = props.UnicastAddresses.Any(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6);
            byte[] mac;
            try { mac = nic.GetPhysicalAddress().GetAddressBytes(); } catch { continue; }
            if (!hasV6 || mac.Length != 6) continue;
            int index;
            try { index = props.GetIPv6Properties().Index; } catch { continue; }
            return (mac, index, nic.Name);
        }
        if (ifname != "") return (Dhcp.FallbackMac, 0, ifname);
        throw new Exception("no IPv6 interface found; pick one with an interface name");
    }

    public static byte[] BuildInform(byte[] xid, byte[] mac)
    {
        var b = new List<byte> { InfoReq, xid[0], xid[1], xid[2] };
        // CLIENTID (1) with DUID-LL (type 3, hwtype 1 ethernet)
        var duid = new byte[] { 0, 3, 0, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] };
        b.AddRange(new byte[] { 0, 1, 0, (byte)duid.Length });
        b.AddRange(duid);
        // ORO (6): request DNS servers (23)
        b.AddRange(new byte[] { 0, 6, 0, 2, 0, 23 });
        // ELAPSED_TIME (8)
        b.AddRange(new byte[] { 0, 8, 0, 2, 0, 0 });
        return b.ToArray();
    }

    /// <summary>Measures the response time of a DHCPv6 server with an INFORMATION-REQUEST.</summary>
    public static DhcpResult Probe(DhcpOpts o)
    {
        var (mac, index, _) = PickV6Iface(o.Iface);

        var xid = new byte[3];
        RandomNumberGenerator.Fill(xid);
        var packet = BuildInform(xid, mac);

        using var conn = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            DnsWire.DisableConnReset(conn);
            conn.Bind(new IPEndPoint(IPAddress.IPv6Any, o.Port)); // 0 = ephemeral
        }
        catch (SocketException e)
        {
            throw new Exception($"cannot open UDPv6 socket: {e.Message}");
        }

        IPEndPoint dst;
        if (o.Server != "")
        {
            IPAddress sip;
            try { sip = Util.ResolveIP(o.Server, true); }
            catch (Exception e) { throw new Exception($"cannot resolve DHCPv6 server {o.Server}: {e.Message}"); }
            if (sip.IsIPv6LinkLocal && sip.ScopeId == 0 && index > 0) sip = new IPAddress(sip.GetAddressBytes(), index);
            dst = new IPEndPoint(sip, ServerPort);
        }
        else
        {
            var m = IPAddress.Parse(MulticastV);
            if (index > 0)
            {
                m = new IPAddress(m.GetAddressBytes(), index);
                try { conn.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, index); } catch { }
            }
            dst = new IPEndPoint(m, ServerPort);
        }

        var sw = Stopwatch.StartNew();
        try { conn.SendTo(packet, dst); }
        catch (SocketException e) { throw new Exception($"sending: {e.Message}"); }

        var buf = new byte[1500];
        EndPoint from = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (true)
        {
            var rest = o.Timeout - sw.Elapsed;
            if (rest <= TimeSpan.Zero) throw new Exception($"no DHCPv6 answer within {o.Timeout.TotalSeconds.F(0)}s");
            conn.ReceiveTimeout = Math.Max(1, (int)rest.TotalMilliseconds);
            int n;
            try { n = conn.ReceiveFrom(buf, ref from); }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
            {
                throw new Exception($"no DHCPv6 answer within {o.Timeout.TotalSeconds.F(0)}s");
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
            {
                continue;
            }
            if (n < 4) continue;
            if (buf[1] != xid[0] || buf[2] != xid[1] || buf[3] != xid[2]) continue; // not our transaction id
            if (buf[0] == Reply || buf[0] == Advertise)
            {
                var mt = buf[0] == Advertise ? "ADVERTISE" : "REPLY";
                return new DhcpResult { Rtt = sw.Elapsed, ServerId = ((IPEndPoint)from).Address, MsgType = 0, Info6 = mt };
            }
        }
    }
}

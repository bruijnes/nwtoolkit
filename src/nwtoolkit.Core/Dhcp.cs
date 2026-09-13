using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using static Nwtoolkit.Util;

namespace Nwtoolkit;

public sealed class DhcpOpts
{
    public string Server = "";   // empty = broadcast; set = unicast INFORM
    public string Iface = "";
    public IPAddress? SrcIP;     // local IPv4 to bind to (selects the outgoing interface); null = the OS picks
    public TimeSpan Timeout = TimeSpan.FromSeconds(3);
    public bool Monitor;
    public TimeSpan Interval = TimeSpan.FromSeconds(5);
    public int Count;
    public int Port;             // local port; 0 = auto (68 for broadcast, ephemeral for inform)
    public bool IPv6;

    public DhcpOpts Clone() => (DhcpOpts)MemberwiseClone();
}

/// <summary>A usable interface for the DHCP interface choice.</summary>
public sealed record NetIface(string Name, IPAddress Ip, byte[]? Mac);

/// <summary>Outcome of one DHCP measurement.</summary>
public sealed class DhcpResult
{
    public TimeSpan Rtt;
    public IPAddress? Yiaddr;
    public IPAddress? ServerId;
    public byte MsgType;
    public string Info6 = "";   // filled for DHCPv6 (e.g. "REPLY")
    public string Method = "";  // which capture method: "INFORM", "pktmon", "socket"
    public List<IPAddress> Servers = new(); // every server that answered within the timeout (broadcast)

    public double Ms => Util.Ms(Rtt);
    public string ServerText => ServerId?.ToString() ?? "unknown";

    /// <summary>The reply type as text: OFFER, ACK, or the DHCPv6 type.</summary>
    public string TypeText => Info6 != "" ? Info6 : MsgType == Dhcp.Ack ? "ACK" : "OFFER";

    public bool HasYiaddr => Yiaddr != null && !Yiaddr.Equals(IPAddress.Any);

    /// <summary>Appends a server to the list, skipping duplicates.</summary>
    public void AddServer(IPAddress? ip)
    {
        if (ip == null) return;
        if (Servers.Any(e => e.Equals(ip))) return;
        Servers.Add(ip);
    }

    /// <summary>
    /// Describes how many servers answered; more than one is a rogue-DHCP signal and
    /// therefore worth reporting. Empty otherwise.
    /// </summary>
    public string ServerSummary()
    {
        if (Servers.Count < 2) return "";
        return $"{Servers.Count} servers answered: {Join(Servers)}";
    }
}

public static class Dhcp
{
    public const byte Discover = 1, Offer = 2, Ack = 5, Inform = 8;
    public const uint MagicCookie = 0x63825363;
    public static readonly byte[] FallbackMac = { 0x02, 0x00, 0x4e, 0x54, 0x00, 0x01 }; // locally administered

    /// <summary>
    /// How long a broadcast probe keeps listening after the first answer. A second
    /// responder means a rogue DHCP server, which is worth catching, but waiting out the
    /// full timeout on every measurement would be pointless.
    /// </summary>
    public static readonly TimeSpan ExtraListenWindow = TimeSpan.FromMilliseconds(400);

    public static bool IsLinkLocalV4(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return b.Length == 4 && b[0] == 169 && b[1] == 254;
    }

    static byte[]? MacOf(NetworkInterface nic)
    {
        try
        {
            var m = nic.GetPhysicalAddress().GetAddressBytes();
            return m.Length == 6 ? m : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>The active, non-loopback interfaces that have an IPv4 address.</summary>
    public static List<NetIface> UsableIPv4Ifaces()
    {
        var out_ = new List<NetIface>();
        NetworkInterface[] nics;
        try { nics = NetworkInterface.GetAllNetworkInterfaces(); }
        catch { return out_; }
        foreach (var nic in nics)
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork || IsLinkLocalV4(ua.Address)) continue;
                out_.Add(new NetIface(nic.Name, ua.Address, MacOf(nic)));
                break;
            }
        }
        return out_;
    }

    /// <summary>The MAC address of the interface holding this IPv4 address.</summary>
    public static byte[]? MacForIP(IPAddress? ip)
    {
        if (ip == null) return null;
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                    if (ua.Address.Equals(ip) && MacOf(nic) is { } mac)
                        return mac;
        }
        catch { }
        return null;
    }

    /// <summary>Determines the local IPv4 and MAC used to reach dst (or the default route).</summary>
    public static (IPAddress LocalIP, byte[] Mac) LocalAddrFor(string dst, string ifname)
    {
        IPAddress target;
        if (dst == "" || dst == "255.255.255.255") target = IPAddress.Parse("8.8.8.8");
        else target = Resolve4(dst);
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        s.Connect(new IPEndPoint(target, 67));
        var localIP = ((IPEndPoint)s.LocalEndPoint!).Address;

        byte[]? mac = null;
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ifname != "" && nic.Name != ifname) continue;
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                    if (ua.Address.Equals(localIP) && MacOf(nic) is { } m)
                        mac = m;
            }
        }
        catch { }
        return (localIP, mac ?? FallbackMac);
    }

    public static byte[] Build(byte msgType, uint xid, byte[] mac, IPAddress? ciaddr, bool broadcast)
    {
        var b = new byte[240 + 3 + 6 + 9 + 1];
        b[0] = 1; // BOOTREQUEST
        b[1] = 1; // ethernet
        b[2] = 6; // hlen
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), xid);
        if (broadcast) BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(10), 0x8000);
        if (ciaddr != null && ciaddr.AddressFamily == AddressFamily.InterNetwork)
            ciaddr.GetAddressBytes().CopyTo(b, 12); // ciaddr
        if (mac.Length != 6) mac = FallbackMac;
        mac.CopyTo(b, 28); // chaddr
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(236), MagicCookie);

        var i = 240;
        b[i++] = 53; b[i++] = 1; b[i++] = msgType;                    // DHCP message type
        b[i++] = 55; b[i++] = 4; b[i++] = 1; b[i++] = 3; b[i++] = 6; b[i++] = 15; // param request list
        b[i++] = 61; b[i++] = 7; b[i++] = 1;                          // client id
        mac.CopyTo(b, i); i += 6;
        b[i] = 255;                                                   // end
        return b;
    }

    /// <summary>Decodes a BOOTREPLY. Returns false when it is not a DHCP reply.</summary>
    public static bool Parse(ReadOnlySpan<byte> b, out byte msgType, out IPAddress? yiaddr, out IPAddress? serverId)
    {
        msgType = 0;
        yiaddr = null;
        serverId = null;
        if (b.Length < 240 || b[0] != 2) return false;
        yiaddr = new IPAddress(b.Slice(16, 4));
        if (BinaryPrimitives.ReadUInt32BigEndian(b[236..]) != MagicCookie) return false;
        var i = 240;
        while (i < b.Length)
        {
            var code = b[i];
            if (code == 255) break;
            if (code == 0)
            {
                i++;
                continue;
            }
            if (i + 1 >= b.Length) break;
            int l = b[i + 1];
            if (i + 2 + l > b.Length) break;
            var val = b.Slice(i + 2, l);
            switch (code)
            {
                case 53:
                    if (l >= 1) msgType = val[0];
                    break;
                case 54:
                    if (l == 4) serverId = new IPAddress(val);
                    break;
            }
            i += 2 + l;
        }
        return true;
    }

    public static uint RandomXid()
    {
        Span<byte> x = stackalloc byte[4];
        RandomNumberGenerator.Fill(x);
        return BinaryPrimitives.ReadUInt32BigEndian(x);
    }

    /// <summary>
    /// Opens a UDP socket for DHCP. SO_REUSEADDR lets port 68 be shared with the Windows
    /// DHCP Client service; SO_BROADCAST is needed to be allowed to send to 255.255.255.255.
    /// </summary>
    public static Socket Listen(IPEndPoint laddr, bool broadcast)
    {
        var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            if (broadcast) s.EnableBroadcast = true;
            DnsWire.DisableConnReset(s);
            s.Bind(laddr);
            return s;
        }
        catch
        {
            s.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Sends a single DISCOVER (broadcast) or INFORM (unicast) over an ordinary UDP socket
    /// and waits for an OFFER or ACK. On Windows this is unreliable because the DHCP
    /// Client service owns port 68, which is why the probe there prefers a unicast INFORM
    /// to a known server, and otherwise the built-in pktmon.
    /// </summary>
    public static DhcpResult ProbeUDP(DhcpOpts o)
    {
        IPAddress localIP;
        byte[] mac;
        try { (localIP, mac) = LocalAddrFor(o.Server, o.Iface); }
        catch (Exception e) { throw new Exception($"determining local address: {e.Message}"); }

        var xid = RandomXid();
        var broadcast = o.Server == "";
        var msg = broadcast ? Discover : Inform;
        var ci = broadcast ? IPAddress.Any : localIP;
        var packet = Build(msg, xid, mac, ci, broadcast);

        var lport = o.Port;
        if (lport == 0) lport = broadcast ? 68 : 0;
        Socket conn;
        try { conn = Listen(new IPEndPoint(IPAddress.Any, lport), broadcast); }
        catch (Exception e)
        {
            if (broadcast)
                throw new Exception($"cannot open port 68 ({e.Message}) — run as Administrator or stop the DHCP Client service, or use -s <ip> for the unicast INFORM method");
            throw;
        }
        using (conn)
        {
            IPEndPoint dst;
            if (broadcast)
            {
                dst = new IPEndPoint(IPAddress.Broadcast, 67);
            }
            else
            {
                IPAddress sip;
                try { sip = Resolve4(o.Server); }
                catch { throw new Exception($"cannot resolve DHCP server {o.Server}"); }
                dst = new IPEndPoint(sip, 67);
            }

            var sw = Stopwatch.StartNew();
            try { conn.SendTo(packet, dst); }
            catch (SocketException e) { throw new Exception($"sending: {e.Message}"); }

            return CollectAnswers(conn, xid, sw, o.Timeout, broadcast, "");
        }
    }

    /// <summary>
    /// Reads DHCP replies on conn until the timeout expires, and returns the first usable
    /// one together with every distinct server that answered.
    ///
    /// A unicast probe returns as soon as one answer arrives, because only one server can
    /// reply. A broadcast probe keeps listening for <see cref="ExtraListenWindow"/> afterwards,
    /// so a second server on the segment still shows up. label prefixes the timeout message
    /// when several interfaces are probed at once and the caller needs to say which one.
    /// </summary>
    public static DhcpResult CollectAnswers(Socket conn, uint xid, Stopwatch sw, TimeSpan timeout, bool broadcast, string label)
    {
        var deadline = sw.Elapsed + timeout;
        var buf = new byte[1500];
        var res = new DhcpResult();
        var got = false;
        EndPoint from = new IPEndPoint(IPAddress.Any, 0);
        while (true)
        {
            var rest = deadline - sw.Elapsed;
            if (rest <= TimeSpan.Zero)
            {
                if (got) return res;
                throw new Exception(label != "" ? $"{label}: no answer within {timeout.TotalSeconds.F(0)}s" : $"no answer within {timeout.TotalSeconds.F(0)}s");
            }
            conn.ReceiveTimeout = Math.Max(1, (int)rest.TotalMilliseconds);
            int n;
            try
            {
                n = conn.ReceiveFrom(buf, ref from);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
            {
                if (got) return res; // deadline of the extra listening window
                throw new Exception(label != "" ? $"{label}: no answer within {timeout.TotalSeconds.F(0)}s" : $"no answer within {timeout.TotalSeconds.F(0)}s");
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
            {
                continue; // ICMP port unreachable from a host that is not a DHCP server
            }
            catch (ObjectDisposedException)
            {
                if (got) return res;
                throw new Exception("socket closed");
            }
            var pkt = buf.AsSpan(0, n);
            if (!Parse(pkt, out var mt, out var yi, out var sid) || BinaryPrimitives.ReadUInt32BigEndian(pkt[4..]) != xid)
                continue; // not a reply, or not our transaction id
            if (mt != Offer && mt != Ack) continue;
            if (got)
            {
                res.AddServer(sid);
                continue;
            }
            got = true;
            res = new DhcpResult { Rtt = sw.Elapsed, Yiaddr = yi, ServerId = sid, MsgType = mt };
            res.AddServer(sid);
            if (!broadcast) return res; // unicast: one answer is all there is
            var extra = ExtraListenWindow;
            var remaining = deadline - sw.Elapsed;
            if (remaining < extra) extra = remaining;
            if (extra <= TimeSpan.Zero) return res;
            deadline = sw.Elapsed + extra;
        }
    }

    public static void Run(DhcpOpts o)
    {
        var method = "broadcast to 255.255.255.255 — with no prior knowledge of any server";
        if (o.IPv6)
        {
            method = "DHCPv6 INFORMATION-REQUEST (multicast ff02::1:2)";
            if (o.Server != "") method = "DHCPv6 INFORMATION-REQUEST to " + o.Server;
        }
        else if (o.Server != "")
        {
            method = "unicast INFORM to " + o.Server;
        }

        if (!o.Monitor && o.Count <= 1)
        {
            Console.WriteLine($"DHCP speed test  method: {method}");
            DhcpResult res;
            try { res = DhcpProbe.Probe(o); }
            catch (Exception e) { Die(e.Message); return; }
            Console.WriteLine($"Answer:     {res.TypeText} from server {res.ServerText}");
            var sum = res.ServerSummary();
            if (sum != "") Console.WriteLine($"Note:       {Col(CYellow, sum)}");
            if (res.HasYiaddr) Console.WriteLine($"Offered:    {res.Yiaddr}");
            Console.WriteLine($"Time:       {Col(CGreen, res.Ms.F(2) + " ms")}");
            return;
        }

        SpeedGraph.Run(new SpeedGraphCfg
        {
            Title = "DHCP speed test  " + method,
            Unit = "ms",
            Interval = o.Interval,
            Count = o.Count,
            Monitor = o.Monitor,
            Measure = () =>
            {
                try
                {
                    var res = DhcpProbe.Probe(o);
                    var info = $"{res.TypeText} from {res.ServerText}";
                    if (res.HasYiaddr) info += " → " + res.Yiaddr;
                    return (res.Ms, info, null);
                }
                catch (Exception e)
                {
                    return (0, "", e.Message);
                }
            },
        });
    }
}

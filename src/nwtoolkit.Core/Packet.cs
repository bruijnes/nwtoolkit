using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;
using static Nwtoolkit.Util;

namespace Nwtoolkit;

/// <summary>
/// One decoded packet: everything the capture needs to print a line and to decide whether
/// a filter keeps it. The raw bytes are not kept; the pcapng writer gets those separately.
/// </summary>
public sealed class CapturedPacket
{
    public DateTime Time;
    public bool IPv6;
    public IPAddress Src = IPAddress.Any;
    public IPAddress Dst = IPAddress.Any;
    public int SrcPort;            // 0 when the protocol has no ports
    public int DstPort;
    public string Proto = "";      // TCP, UDP, ICMP, ICMP6, IGMP, "proto 47", …
    public string Service = "";    // well-known name of either port, "" when unknown
    public string Info = "";       // flags, ICMP type, fragment note
    public int PayloadLength;      // payload above the transport header, tcpdump's "length"

    /// <summary>tcpdump-style summary line; the console asks for colour, the GUI and the log do not.</summary>
    public string Line(bool color = false)
    {
        string C(string c, string s) => color ? Col(c, s) : s;
        var sb = new StringBuilder();
        sb.Append(C(CGrey, Time.ToString("HH:mm:ss.ffffff", CultureInfo.InvariantCulture)));
        sb.Append(IPv6 ? " IP6 " : " IP ");
        sb.Append(Endpoint(Src, SrcPort)).Append(" > ").Append(Endpoint(Dst, DstPort)).Append(": ");
        sb.Append(C(ProtoColor, Proto));
        if (Service != "") sb.Append(" (").Append(Service).Append(')');
        if (Info != "") sb.Append(' ').Append(Info);
        sb.Append(", length ").Append(PayloadLength.ToString(CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    string ProtoColor => Proto switch
    {
        "TCP" => CCyan,
        "UDP" => CGreen,
        "ICMP" or "ICMP6" => CYellow,
        _ => CGrey,
    };

    /// <summary>Address with its port appended the way tcpdump writes it: 10.0.0.5.443.</summary>
    static string Endpoint(IPAddress ip, int port) =>
        port == 0 ? ip.ToString() : ip + "." + port.ToString(CultureInfo.InvariantCulture);
}

/// <summary>
/// Decodes captured bytes that start at the IP header. A raw socket in SIO_RCVALL mode
/// hands over IP packets without the Ethernet frame around them, so there is no link
/// layer to parse here and no ARP: everything starts with the version nibble.
/// </summary>
public static class PacketDecode
{
    public static CapturedPacket? Parse(ReadOnlySpan<byte> p, DateTime time)
    {
        if (p.Length < 1) return null;
        return (p[0] >> 4) switch
        {
            4 => ParseV4(p, time),
            6 => ParseV6(p, time),
            _ => null, // not an IP packet: a headerless IPv6 raw socket, or garbage
        };
    }

    static CapturedPacket? ParseV4(ReadOnlySpan<byte> p, DateTime time)
    {
        if (p.Length < 20) return null;
        var ihl = (p[0] & 0x0f) * 4;
        if (ihl < 20 || p.Length < ihl) return null;
        int total = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
        // Windows hands the total length over in host order on some stacks, and a short
        // capture can leave fewer bytes than the header claims; trust the buffer instead.
        if (total < ihl || total > p.Length) total = p.Length;
        var fragOff = (BinaryPrimitives.ReadUInt16BigEndian(p[6..]) & 0x1fff) * 8;
        var proto = p[9];
        var pkt = new CapturedPacket
        {
            Time = time,
            Src = new IPAddress(p.Slice(12, 4)),
            Dst = new IPAddress(p.Slice(16, 4)),
        };
        var payload = p[ihl..total];
        if (fragOff > 0)
        {
            // A later fragment carries no transport header, so there is nothing to decode.
            pkt.Proto = ProtoName(proto);
            pkt.Info = $"frag offset {fragOff}";
            pkt.PayloadLength = payload.Length;
            return pkt;
        }
        Transport(pkt, proto, payload);
        return pkt;
    }

    static CapturedPacket? ParseV6(ReadOnlySpan<byte> p, DateTime time)
    {
        if (p.Length < 40) return null;
        int payloadLen = BinaryPrimitives.ReadUInt16BigEndian(p[4..]);
        var total = 40 + payloadLen;
        if (total > p.Length) total = p.Length;
        var pkt = new CapturedPacket
        {
            Time = time,
            IPv6 = true,
            Src = new IPAddress(p.Slice(8, 16)),
            Dst = new IPAddress(p.Slice(24, 16)),
        };
        var next = p[6];
        var rest = p[40..total];
        var frag = "";
        // Walk the extension-header chain to the transport header.
        while (rest.Length >= 8)
        {
            if (next == 44) // fragment header: fixed 8 bytes
            {
                var off = BinaryPrimitives.ReadUInt16BigEndian(rest[2..]) & 0xfff8;
                if (off > 0) frag = $"frag offset {off}";
                next = rest[0];
                rest = rest[8..];
                if (frag != "") break;
                continue;
            }
            if (next is not (0 or 43 or 60)) break; // hop-by-hop, routing, destination options
            var len = (rest[1] + 1) * 8;
            if (len > rest.Length) break;
            next = rest[0];
            rest = rest[len..];
        }
        if (frag != "")
        {
            pkt.Proto = ProtoName(next);
            pkt.Info = frag;
            pkt.PayloadLength = rest.Length;
            return pkt;
        }
        Transport(pkt, next, rest);
        return pkt;
    }

    static void Transport(CapturedPacket pkt, byte proto, ReadOnlySpan<byte> payload)
    {
        switch (proto)
        {
            case 6: Tcp(pkt, payload); return;
            case 17: Udp(pkt, payload); return;
            case 1: Icmp4(pkt, payload); return;
            case 58: Icmp6(pkt, payload); return;
            default:
                pkt.Proto = ProtoName(proto);
                pkt.PayloadLength = payload.Length;
                return;
        }
    }

    static void Tcp(CapturedPacket pkt, ReadOnlySpan<byte> p)
    {
        pkt.Proto = "TCP";
        if (p.Length < 20)
        {
            pkt.PayloadLength = p.Length;
            return;
        }
        pkt.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(p);
        pkt.DstPort = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
        pkt.Service = ServiceName(pkt.SrcPort, pkt.DstPort);
        var seq = BinaryPrimitives.ReadUInt32BigEndian(p[4..]);
        var ack = BinaryPrimitives.ReadUInt32BigEndian(p[8..]);
        var doff = (p[12] >> 4) * 4;
        var flags = p[13];
        var win = BinaryPrimitives.ReadUInt16BigEndian(p[14..]);
        if (doff < 20 || doff > p.Length) doff = Math.Min(20, p.Length);
        pkt.PayloadLength = p.Length - doff;
        var sb = new StringBuilder();
        sb.Append('[').Append(TcpFlags(flags)).Append("], seq ").Append(seq.ToString(CultureInfo.InvariantCulture));
        if ((flags & 0x10) != 0) sb.Append(", ack ").Append(ack.ToString(CultureInfo.InvariantCulture));
        sb.Append(", win ").Append(win.ToString(CultureInfo.InvariantCulture));
        pkt.Info = sb.ToString();
    }

    /// <summary>The tcpdump flag letters, in the order tcpdump prints them.</summary>
    public static string TcpFlags(byte f)
    {
        var sb = new StringBuilder();
        if ((f & 0x02) != 0) sb.Append('S'); // SYN
        if ((f & 0x01) != 0) sb.Append('F'); // FIN
        if ((f & 0x04) != 0) sb.Append('R'); // RST
        if ((f & 0x08) != 0) sb.Append('P'); // PSH
        if ((f & 0x20) != 0) sb.Append('U'); // URG
        if ((f & 0x40) != 0) sb.Append('E'); // ECE
        if ((f & 0x80) != 0) sb.Append('W'); // CWR
        if ((f & 0x10) != 0) sb.Append('.'); // ACK
        return sb.Length == 0 ? "none" : sb.ToString();
    }

    static void Udp(CapturedPacket pkt, ReadOnlySpan<byte> p)
    {
        pkt.Proto = "UDP";
        if (p.Length < 8)
        {
            pkt.PayloadLength = p.Length;
            return;
        }
        pkt.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(p);
        pkt.DstPort = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
        pkt.Service = ServiceName(pkt.SrcPort, pkt.DstPort);
        int len = BinaryPrimitives.ReadUInt16BigEndian(p[4..]) - 8;
        if (len < 0 || len > p.Length - 8) len = p.Length - 8;
        pkt.PayloadLength = len;
    }

    static void Icmp4(CapturedPacket pkt, ReadOnlySpan<byte> p)
    {
        pkt.Proto = "ICMP";
        pkt.PayloadLength = p.Length;
        if (p.Length < 4) return;
        int type = p[0], code = p[1];
        var name = type switch
        {
            0 => "echo reply",
            3 => Unreachable4(code),
            5 => "redirect",
            8 => "echo request",
            9 => "router advertisement",
            10 => "router solicitation",
            11 => code == 1 ? "time exceeded in reassembly" : "time exceeded in transit",
            12 => "parameter problem",
            13 => "timestamp request",
            14 => "timestamp reply",
            _ => $"type {type} code {code}",
        };
        pkt.Info = name;
        if ((type == 0 || type == 8) && p.Length >= 8)
            pkt.Info += $", id {BinaryPrimitives.ReadUInt16BigEndian(p[4..])}, seq {BinaryPrimitives.ReadUInt16BigEndian(p[6..])}";
    }

    static string Unreachable4(int code) => code switch
    {
        0 => "net unreachable",
        1 => "host unreachable",
        3 => "port unreachable",
        4 => "fragmentation needed",
        9 or 10 or 13 => "administratively prohibited",
        _ => "destination unreachable",
    };

    static void Icmp6(CapturedPacket pkt, ReadOnlySpan<byte> p)
    {
        pkt.Proto = "ICMP6";
        pkt.PayloadLength = p.Length;
        if (p.Length < 4) return;
        int type = p[0], code = p[1];
        pkt.Info = type switch
        {
            1 => "destination unreachable",
            2 => "packet too big",
            3 => "time exceeded",
            4 => "parameter problem",
            128 => "echo request",
            129 => "echo reply",
            130 => "multicast listener query",
            131 => "multicast listener report",
            133 => "router solicitation",
            134 => "router advertisement",
            135 => "neighbour solicitation",
            136 => "neighbour advertisement",
            137 => "redirect",
            143 => "multicast listener report v2",
            _ => $"type {type} code {code}",
        };
        if ((type == 128 || type == 129) && p.Length >= 8)
            pkt.Info += $", id {BinaryPrimitives.ReadUInt16BigEndian(p[4..])}, seq {BinaryPrimitives.ReadUInt16BigEndian(p[6..])}";
    }

    public static string ProtoName(byte proto) => proto switch
    {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMP6",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        132 => "SCTP",
        _ => "proto " + proto.ToString(CultureInfo.InvariantCulture),
    };

    static readonly Dictionary<int, string> Services = new()
    {
        [20] = "ftp-data", [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp",
        [53] = "domain", [67] = "bootps", [68] = "bootpc", [69] = "tftp", [80] = "http",
        [88] = "kerberos", [110] = "pop3", [119] = "nntp", [123] = "ntp", [135] = "epmap",
        [137] = "netbios-ns", [138] = "netbios-dgm", [139] = "netbios-ssn", [143] = "imap",
        [161] = "snmp", [162] = "snmptrap", [389] = "ldap", [443] = "https", [445] = "smb",
        [465] = "smtps", [500] = "isakmp", [514] = "syslog", [515] = "printer", [520] = "rip",
        [546] = "dhcpv6-client", [547] = "dhcpv6-server", [587] = "submission", [636] = "ldaps",
        [993] = "imaps", [995] = "pop3s", [1433] = "ms-sql", [1701] = "l2tp", [1723] = "pptp",
        [1812] = "radius", [1900] = "ssdp", [3268] = "globalcat", [3306] = "mysql",
        [3389] = "rdp", [4500] = "ipsec-nat-t", [5060] = "sip", [5061] = "sips",
        [5353] = "mdns", [5355] = "llmnr", [5432] = "postgres", [5985] = "winrm",
        [5986] = "winrm-s", [8080] = "http-alt", [8443] = "https-alt",
    };

    /// <summary>
    /// Names the well-known side of a conversation. The lower port is tried first, because
    /// the ephemeral port of the client is always the higher one.
    /// </summary>
    public static string ServiceName(int a, int b)
    {
        if (Services.TryGetValue(Math.Min(a, b), out var lo)) return lo;
        return Services.TryGetValue(Math.Max(a, b), out var hi) ? hi : "";
    }
}

/// <summary>
/// The capture filter: addresses, ports and a protocol, all optional and combined with
/// AND. Each address and port comes in three forms — either direction, source only and
/// destination only — which is what tells "the server answering" apart from "the client
/// asking" without the weight of a BPF expression parser.
/// </summary>
public sealed class CaptureFilter
{
    public string Host = "";       // matches the source or the destination
    public string SrcHost = "";    // matches the source only
    public string DstHost = "";    // matches the destination only
    public int Port;               // matches either port
    public int SrcPort;
    public int DstPort;
    public string Proto = "";

    IPAddress[] any = Array.Empty<IPAddress>(), src = Array.Empty<IPAddress>(), dst = Array.Empty<IPAddress>();
    string proto = "";

    /// <summary>Resolves the names once, so no lookup happens per packet. Throws when a name is unknown.</summary>
    public void Prepare()
    {
        proto = Proto.Trim().ToLowerInvariant();
        any = Resolve(Host);
        src = Resolve(SrcHost);
        dst = Resolve(DstHost);
    }

    /// <summary>
    /// An address stays as it is; a name becomes every address it resolves to, so
    /// "-dst example.com" keeps matching when the site answers from a second address.
    /// </summary>
    static IPAddress[] Resolve(string host)
    {
        var h = host.Trim();
        if (h == "") return Array.Empty<IPAddress>();
        if (IPAddress.TryParse(h, out var ip)) return new[] { ip };
        IPAddress[] ips;
        try
        {
            ips = Dns.GetHostAddresses(h);
        }
        catch (Exception e)
        {
            throw new Exception($"lookup {h}: {e.Message}");
        }
        if (ips.Length == 0) throw new Exception($"no address found for {h}");
        return ips;
    }

    public bool Matches(CapturedPacket p)
    {
        if (Port != 0 && p.SrcPort != Port && p.DstPort != Port) return false;
        if (SrcPort != 0 && p.SrcPort != SrcPort) return false;
        if (DstPort != 0 && p.DstPort != DstPort) return false;
        if (any.Length > 0 && !any.Any(h => h.Equals(p.Src) || h.Equals(p.Dst))) return false;
        if (src.Length > 0 && !src.Any(h => h.Equals(p.Src))) return false;
        if (dst.Length > 0 && !dst.Any(h => h.Equals(p.Dst))) return false;
        if (proto == "") return true;
        // "icmp" is taken to mean both versions; nobody asking for ICMP wants v6 excluded.
        if (proto == "icmp") return p.Proto is "ICMP" or "ICMP6";
        return string.Equals(p.Proto, proto, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Human-readable form for the capture header line; "" when nothing is filtered.</summary>
    public string Describe()
    {
        var parts = new List<string>();
        if (Proto.Trim() != "") parts.Add(Proto.Trim().ToLowerInvariant());
        if (Host.Trim() != "") parts.Add("host " + Host.Trim());
        if (SrcHost.Trim() != "") parts.Add("src host " + SrcHost.Trim());
        if (DstHost.Trim() != "") parts.Add("dst host " + DstHost.Trim());
        if (Port != 0) parts.Add("port " + Port.ToString(CultureInfo.InvariantCulture));
        if (SrcPort != 0) parts.Add("src port " + SrcPort.ToString(CultureInfo.InvariantCulture));
        if (DstPort != 0) parts.Add("dst port " + DstPort.ToString(CultureInfo.InvariantCulture));
        return string.Join(" and ", parts);
    }
}

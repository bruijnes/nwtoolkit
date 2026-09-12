using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Nwtoolkit;

/// <summary>One decoded resource record from an answer.</summary>
public readonly record struct DnsRecord(string Name, ushort Type, uint Ttl, string Data)
{
    public string TypeName => DnsWire.TypeName(Type);
}

public sealed class DnsResponse
{
    public ushort Id;
    public int Rcode;
    public bool Truncated;
    public List<DnsRecord> Answers = new();
}

/// <summary>
/// A minimal DNS wire-format client: builds a query, sends it over UDP (TCP when the
/// answer is truncated) and decodes the answer section into readable text.
/// </summary>
public static class DnsWire
{
    static readonly Dictionary<string, ushort> typeByName = new(StringComparer.OrdinalIgnoreCase)
    {
        ["A"] = 1, ["NS"] = 2, ["CNAME"] = 5, ["SOA"] = 6, ["PTR"] = 12, ["HINFO"] = 13, ["MX"] = 15,
        ["TXT"] = 16, ["AAAA"] = 28, ["SRV"] = 33, ["NAPTR"] = 35, ["DS"] = 43, ["RRSIG"] = 46,
        ["NSEC"] = 47, ["DNSKEY"] = 48, ["TLSA"] = 52, ["SVCB"] = 64, ["HTTPS"] = 65, ["CAA"] = 257, ["ANY"] = 255,
    };
    static readonly Dictionary<ushort, string> nameByType = typeByName.ToDictionary(kv => kv.Value, kv => kv.Key);

    static readonly string[] rcodeNames = { "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE" };

    /// <summary>Record type code for a name such as "MX"; unknown names fall back to A.</summary>
    public static ushort TypeCode(string s)
    {
        s = s.Trim();
        if (typeByName.TryGetValue(s, out var c)) return c;
        if (s.StartsWith("TYPE", StringComparison.OrdinalIgnoreCase) && ushort.TryParse(s.AsSpan(4), out var n)) return n;
        return 1;
    }

    public static string TypeName(ushort t) => nameByType.TryGetValue(t, out var n) ? n : "TYPE" + t;

    public static string RcodeName(int rc) => rc >= 0 && rc < rcodeNames.Length ? rcodeNames[rc] : "RCODE" + rc;

    public static byte[] BuildQuery(ushort id, string name, ushort qtype)
    {
        var b = new List<byte>(64);
        b.Add((byte)(id >> 8)); b.Add((byte)id);
        b.Add(0x01); b.Add(0x00); // flags: recursion desired
        b.Add(0); b.Add(1);       // qdcount
        b.Add(0); b.Add(0);       // ancount
        b.Add(0); b.Add(0);       // nscount
        b.Add(0); b.Add(0);       // arcount
        foreach (var label in name.Trim().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var lb = Encoding.UTF8.GetBytes(label);
            if (lb.Length > 63) throw new ArgumentException($"label too long: {label}");
            b.Add((byte)lb.Length);
            b.AddRange(lb);
        }
        b.Add(0);
        b.Add((byte)(qtype >> 8)); b.Add((byte)qtype);
        b.Add(0); b.Add(1); // class IN
        return b.ToArray();
    }

    /// <summary>Decodes a response message. Throws on malformed input.</summary>
    public static DnsResponse Parse(ReadOnlySpan<byte> m)
    {
        if (m.Length < 12) throw new FormatException("short DNS message");
        var r = new DnsResponse
        {
            Id = BinaryPrimitives.ReadUInt16BigEndian(m),
            Truncated = (m[2] & 0x02) != 0,
            Rcode = m[3] & 0x0f,
        };
        int qd = BinaryPrimitives.ReadUInt16BigEndian(m[4..]);
        int an = BinaryPrimitives.ReadUInt16BigEndian(m[6..]);
        var pos = 12;
        for (var i = 0; i < qd; i++)
        {
            ReadName(m, ref pos);
            pos += 4;
        }
        for (var i = 0; i < an; i++)
        {
            var name = ReadName(m, ref pos);
            if (pos + 10 > m.Length) throw new FormatException("truncated record");
            var type = BinaryPrimitives.ReadUInt16BigEndian(m[pos..]);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(m[(pos + 4)..]);
            int rdlen = BinaryPrimitives.ReadUInt16BigEndian(m[(pos + 8)..]);
            pos += 10;
            if (pos + rdlen > m.Length) throw new FormatException("truncated rdata");
            var data = FormatRdata(m, pos, rdlen, type);
            pos += rdlen;
            r.Answers.Add(new DnsRecord(name, type, ttl, data));
        }
        return r;
    }

    static string ReadName(ReadOnlySpan<byte> m, ref int pos)
    {
        var sb = new StringBuilder();
        var p = pos;
        var jumped = false;
        var hops = 0;
        while (true)
        {
            if (p >= m.Length) throw new FormatException("name runs past the message");
            int len = m[p];
            if (len == 0)
            {
                p++;
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                if (p + 1 >= m.Length) throw new FormatException("bad pointer");
                var ptr = ((len & 0x3F) << 8) | m[p + 1];
                if (!jumped) pos = p + 2;
                jumped = true;
                p = ptr;
                if (++hops > 64) throw new FormatException("pointer loop");
                continue;
            }
            p++;
            if (p + len > m.Length) throw new FormatException("label runs past the message");
            sb.Append(Encoding.ASCII.GetString(m.Slice(p, len))).Append('.');
            p += len;
        }
        if (!jumped) pos = p;
        return sb.Length == 0 ? "." : sb.ToString();
    }

    static string FormatRdata(ReadOnlySpan<byte> m, int pos, int len, ushort type)
    {
        var rd = m.Slice(pos, len);
        switch (type)
        {
            case 1 when len == 4:
            case 28 when len == 16:
                return new IPAddress(rd).ToString();
            case 2: case 5: case 12: // NS, CNAME, PTR
            {
                var p = pos;
                return ReadName(m, ref p);
            }
            case 15: // MX
            {
                if (len < 3) break;
                var pref = BinaryPrimitives.ReadUInt16BigEndian(rd);
                var p = pos + 2;
                return $"{pref} {ReadName(m, ref p)}";
            }
            case 6: // SOA
            {
                var p = pos;
                var mname = ReadName(m, ref p);
                var rname = ReadName(m, ref p);
                if (p + 20 > m.Length) break;
                var serial = BinaryPrimitives.ReadUInt32BigEndian(m[p..]);
                var refresh = BinaryPrimitives.ReadUInt32BigEndian(m[(p + 4)..]);
                var retry = BinaryPrimitives.ReadUInt32BigEndian(m[(p + 8)..]);
                var expire = BinaryPrimitives.ReadUInt32BigEndian(m[(p + 12)..]);
                var minimum = BinaryPrimitives.ReadUInt32BigEndian(m[(p + 16)..]);
                return $"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}";
            }
            case 16: case 13: // TXT, HINFO: one or more character-strings
            {
                var parts = new List<string>();
                var p = 0;
                while (p < rd.Length)
                {
                    int l = rd[p++];
                    if (p + l > rd.Length) break;
                    parts.Add("\"" + Encoding.UTF8.GetString(rd.Slice(p, l)).Replace("\"", "\\\"") + "\"");
                    p += l;
                }
                return string.Join(" ", parts);
            }
            case 33: // SRV
            {
                if (len < 7) break;
                var prio = BinaryPrimitives.ReadUInt16BigEndian(rd);
                var weight = BinaryPrimitives.ReadUInt16BigEndian(rd[2..]);
                var port = BinaryPrimitives.ReadUInt16BigEndian(rd[4..]);
                var p = pos + 6;
                return $"{prio} {weight} {port} {ReadName(m, ref p)}";
            }
            case 257: // CAA
            {
                if (len < 2) break;
                int flags = rd[0];
                int tagLen = rd[1];
                if (2 + tagLen > len) break;
                var tag = Encoding.ASCII.GetString(rd.Slice(2, tagLen));
                var val = Encoding.UTF8.GetString(rd[(2 + tagLen)..]);
                return $"{flags} {tag} \"{val}\"";
            }
        }
        return "\\# " + len + " " + Convert.ToHexString(rd).ToLowerInvariant();
    }

    /// <summary>
    /// Sends one query and returns the response time plus the decoded answers.
    /// Throws with a readable message on timeout, network error, or a non-zero rcode.
    /// </summary>
    public static (TimeSpan Rtt, List<string> Answers) Query(IPEndPoint server, string name, ushort qtype, TimeSpan timeout)
    {
        var id = (ushort)Random.Shared.Next(1, 65535);
        var q = BuildQuery(id, name, qtype);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        DnsResponse resp;
        try
        {
            resp = ExchangeUdp(server, q, id, timeout);
            if (resp.Truncated) resp = ExchangeTcp(server, q, id, timeout);
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
        {
            throw new Exception($"i/o timeout after {timeout.TotalSeconds.F(0)}s");
        }
        catch (SocketException e)
        {
            throw new Exception(e.Message);
        }
        sw.Stop();
        if (resp.Rcode != 0) throw new DnsRcodeException(resp.Rcode, sw.Elapsed);
        var answers = resp.Answers.Select(a => a.Data + " (" + a.TypeName + ")").ToList();
        return (sw.Elapsed, answers);
    }

    static DnsResponse ExchangeUdp(IPEndPoint server, byte[] q, ushort id, TimeSpan timeout)
    {
        using var s = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        DisableConnReset(s);
        s.Connect(server);
        s.Send(q);
        var deadline = DateTime.UtcNow + timeout;
        var buf = new byte[4096];
        while (true)
        {
            var rest = deadline - DateTime.UtcNow;
            if (rest <= TimeSpan.Zero) throw new SocketException((int)SocketError.TimedOut);
            s.ReceiveTimeout = Math.Max(1, (int)rest.TotalMilliseconds);
            var n = s.Receive(buf);
            if (n < 12) continue;
            DnsResponse r;
            try { r = Parse(buf.AsSpan(0, n)); }
            catch (FormatException) { continue; }
            if (r.Id != id) continue; // not our answer
            return r;
        }
    }

    static DnsResponse ExchangeTcp(IPEndPoint server, byte[] q, ushort id, TimeSpan timeout)
    {
        using var s = new Socket(server.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        s.ReceiveTimeout = s.SendTimeout = Math.Max(1, (int)timeout.TotalMilliseconds);
        s.Connect(server);
        var framed = new byte[q.Length + 2];
        framed[0] = (byte)(q.Length >> 8);
        framed[1] = (byte)q.Length;
        q.CopyTo(framed, 2);
        s.Send(framed);
        var hdr = ReadExact(s, 2);
        var len = (hdr[0] << 8) | hdr[1];
        var msg = ReadExact(s, len);
        var r = Parse(msg);
        if (r.Id != id) throw new Exception("mismatched answer id over TCP");
        return r;
    }

    static byte[] ReadExact(Socket s, int len)
    {
        var buf = new byte[len];
        var got = 0;
        while (got < len)
        {
            var n = s.Receive(buf, got, len - got, SocketFlags.None);
            if (n <= 0) throw new Exception("connection closed by the server");
            got += n;
        }
        return buf;
    }

    /// <summary>
    /// On Windows a UDP socket reports an ICMP port-unreachable as a ConnectionReset on the
    /// next receive, which would abort the wait. Switch that off so a timeout is reported instead.
    /// </summary>
    internal static void DisableConnReset(Socket s)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            const int SIO_UDP_CONNRESET = -1744830452;
            s.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
        }
        catch { }
    }
}

public sealed class DnsRcodeException : Exception
{
    public int Rcode { get; }
    public TimeSpan Rtt { get; }
    public DnsRcodeException(int rcode, TimeSpan rtt) : base("rcode " + DnsWire.RcodeName(rcode))
    {
        Rcode = rcode;
        Rtt = rtt;
    }
}

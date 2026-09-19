using System.Buffers.Binary;
using System.Net;
using Xunit;

namespace Nwtoolkit.Tests;

/// <summary>
/// Builds the IP packets a raw capture hands over: no Ethernet frame, straight into the
/// IP header.
/// </summary>
static class Pkt
{
    public static byte[] V4(byte proto, string src, string dst, byte[] payload, int fragOff = 0)
    {
        var b = new byte[20 + payload.Length];
        b[0] = 0x45; // version 4, header length 5 words
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), (ushort)b.Length);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(6), (ushort)(fragOff / 8));
        b[8] = 64; // TTL
        b[9] = proto;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(b, 12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(b, 16);
        payload.CopyTo(b, 20);
        return b;
    }

    public static byte[] V6(byte next, string src, string dst, byte[] payload)
    {
        var b = new byte[40 + payload.Length];
        b[0] = 0x60; // version 6
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4), (ushort)payload.Length);
        b[6] = next;
        b[7] = 64; // hop limit
        IPAddress.Parse(src).GetAddressBytes().CopyTo(b, 8);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(b, 24);
        payload.CopyTo(b, 40);
        return b;
    }

    public static byte[] Tcp(int sport, int dport, byte flags, uint seq = 1, uint ack = 0, int data = 0)
    {
        var b = new byte[20 + data];
        BinaryPrimitives.WriteUInt16BigEndian(b, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(8), ack);
        b[12] = 5 << 4; // data offset: 5 words, no options
        b[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(14), 64240);
        return b;
    }

    public static byte[] Udp(int sport, int dport, int data)
    {
        var b = new byte[8 + data];
        BinaryPrimitives.WriteUInt16BigEndian(b, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4), (ushort)b.Length);
        return b;
    }

    public static byte[] Icmp(byte type, byte code, ushort id = 0, ushort seq = 0, int data = 0)
    {
        var b = new byte[8 + data];
        b[0] = type;
        b[1] = code;
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4), id);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(6), seq);
        return b;
    }

    /// <summary>An IPv6 extension header: next header, length in 8-byte units minus one, padding.</summary>
    public static byte[] Ext(byte next, int units = 1)
    {
        var b = new byte[8 * units];
        b[0] = next;
        b[1] = (byte)(units - 1);
        return b;
    }

    public static CapturedPacket Decode(byte[] raw)
    {
        var p = PacketDecode.Parse(raw, new DateTime(2026, 9, 18, 12, 0, 0));
        Assert.NotNull(p);
        return p!;
    }
}

public class PacketTests
{
    [Fact]
    public void DecodesTcpSyn()
    {
        var p = Pkt.Decode(Pkt.V4(6, "10.0.0.5", "1.1.1.1", Pkt.Tcp(51234, 443, 0x02, seq: 1000)));
        Assert.Equal("TCP", p.Proto);
        Assert.Equal("https", p.Service);
        Assert.Equal(51234, p.SrcPort);
        Assert.Equal(443, p.DstPort);
        Assert.Equal(0, p.PayloadLength);
        Assert.Contains("[S], seq 1000, win 64240", p.Info);
        Assert.DoesNotContain("ack", p.Info); // no ACK flag, so no acknowledgement number
        Assert.Contains("10.0.0.5.51234 > 1.1.1.1.443: TCP (https)", p.Line());
    }

    /// <summary>The payload length is what tells a full segment from a bare acknowledgement.</summary>
    [Fact]
    public void DecodesTcpPayloadLength()
    {
        var p = Pkt.Decode(Pkt.V4(6, "10.0.0.5", "1.1.1.1", Pkt.Tcp(51234, 80, 0x18, ack: 77, data: 120)));
        Assert.Equal(120, p.PayloadLength);
        Assert.Contains("[P.]", p.Info);
        Assert.Contains("ack 77", p.Info);
        Assert.EndsWith(", length 120", p.Line());
    }

    [Theory]
    [InlineData(0x02, "S")]
    [InlineData(0x12, "S.")]
    [InlineData(0x10, ".")]
    [InlineData(0x04, "R")]
    [InlineData(0x11, "F.")]
    [InlineData(0x00, "none")]
    public void TcpFlagLetters(byte flags, string want) => Assert.Equal(want, PacketDecode.TcpFlags(flags));

    [Fact]
    public void DecodesUdpAndNamesTheService()
    {
        var p = Pkt.Decode(Pkt.V4(17, "10.0.0.5", "8.8.8.8", Pkt.Udp(54321, 53, 40)));
        Assert.Equal("UDP", p.Proto);
        Assert.Equal("domain", p.Service);
        Assert.Equal(40, p.PayloadLength);
    }

    [Fact]
    public void DecodesIcmpEcho()
    {
        var p = Pkt.Decode(Pkt.V4(1, "8.8.8.8", "10.0.0.5", Pkt.Icmp(0, 0, id: 1, seq: 4, data: 32)));
        Assert.Equal("ICMP", p.Proto);
        Assert.Equal(0, p.SrcPort);
        Assert.Contains("echo reply, id 1, seq 4", p.Info);
        Assert.Contains("8.8.8.8 > 10.0.0.5: ICMP echo reply", p.Line());
    }

    [Fact]
    public void DecodesIcmpPortUnreachable()
    {
        var p = Pkt.Decode(Pkt.V4(1, "10.0.0.1", "10.0.0.5", Pkt.Icmp(3, 3)));
        Assert.Contains("port unreachable", p.Info);
    }

    /// <summary>A later fragment has no transport header, so ports must not be read out of the payload.</summary>
    [Fact]
    public void LaterFragmentIsNotDecodedAsTransport()
    {
        var p = Pkt.Decode(Pkt.V4(6, "10.0.0.5", "1.1.1.1", Pkt.Tcp(51234, 443, 0x02), fragOff: 1480));
        Assert.Equal("TCP", p.Proto);
        Assert.Equal(0, p.SrcPort);
        Assert.Contains("frag offset 1480", p.Info);
    }

    [Fact]
    public void DecodesIPv6Tcp()
    {
        var p = Pkt.Decode(Pkt.V6(6, "2001:db8::1", "2001:db8::2", Pkt.Tcp(40000, 22, 0x02)));
        Assert.True(p.IPv6);
        Assert.Equal("TCP", p.Proto);
        Assert.Equal("ssh", p.Service);
        Assert.StartsWith("12:00:00.000000 IP6 2001:db8::1.40000 > 2001:db8::2.22:", p.Line());
    }

    /// <summary>Router advertisements arrive behind a hop-by-hop header; skipping it wrong turns every one into garbage.</summary>
    [Fact]
    public void SkipsIPv6ExtensionHeaders()
    {
        var inner = Pkt.Ext(58, units: 2).Concat(Pkt.Icmp(134, 0)).ToArray();
        var p = Pkt.Decode(Pkt.V6(0, "fe80::1", "ff02::1", inner));
        Assert.Equal("ICMP6", p.Proto);
        Assert.Contains("router advertisement", p.Info);
    }

    [Fact]
    public void DecodesUnknownProtocolByNumber()
    {
        var p = Pkt.Decode(Pkt.V4(47, "10.0.0.5", "10.0.0.9", new byte[10]));
        Assert.Equal("GRE", p.Proto);
        Assert.Equal(10, p.PayloadLength);
    }

    [Fact]
    public void RejectsNonIpBytes() => Assert.Null(PacketDecode.Parse(new byte[] { 0x20, 1, 2, 3 }, DateTime.Now));

    [Fact]
    public void ServiceNameTakesTheWellKnownSide()
    {
        Assert.Equal("https", PacketDecode.ServiceName(51234, 443));
        Assert.Equal("https", PacketDecode.ServiceName(443, 51234));
        Assert.Equal("mdns", PacketDecode.ServiceName(5353, 60000)); // known port is the higher one
        Assert.Equal("", PacketDecode.ServiceName(40000, 40001));
    }
}

public class CaptureFilterTests
{
    static CapturedPacket Udp(string src, string dst, int sport, int dport) =>
        Pkt.Decode(Pkt.V4(17, src, dst, Pkt.Udp(sport, dport, 10)));

    static CaptureFilter Made(string host = "", int port = 0, string proto = "",
        string src = "", string dst = "", int sport = 0, int dport = 0)
    {
        var f = new CaptureFilter { Host = host, Port = port, Proto = proto, SrcHost = src, DstHost = dst, SrcPort = sport, DstPort = dport };
        f.Prepare();
        return f;
    }

    [Fact]
    public void EmptyFilterKeepsEverything() => Assert.True(Made().Matches(Udp("10.0.0.5", "8.8.8.8", 1, 2)));

    [Fact]
    public void HostMatchesEitherDirection()
    {
        var f = Made(host: "8.8.8.8");
        Assert.True(f.Matches(Udp("10.0.0.5", "8.8.8.8", 1, 53)));
        Assert.True(f.Matches(Udp("8.8.8.8", "10.0.0.5", 53, 1)));
        Assert.False(f.Matches(Udp("10.0.0.5", "1.1.1.1", 1, 53)));
    }

    [Fact]
    public void PortMatchesEitherEnd()
    {
        var f = Made(port: 53);
        Assert.True(f.Matches(Udp("10.0.0.5", "8.8.8.8", 51234, 53)));
        Assert.False(f.Matches(Udp("10.0.0.5", "8.8.8.8", 51234, 123)));
    }

    /// <summary>Asking for icmp means both versions; a v6-only network would otherwise show nothing.</summary>
    [Fact]
    public void IcmpCoversBothVersions()
    {
        var f = Made(proto: "icmp");
        Assert.True(f.Matches(Pkt.Decode(Pkt.V4(1, "10.0.0.1", "10.0.0.5", Pkt.Icmp(8, 0)))));
        Assert.True(f.Matches(Pkt.Decode(Pkt.V6(58, "2001:db8::1", "2001:db8::2", Pkt.Icmp(128, 0)))));
        Assert.False(f.Matches(Udp("10.0.0.5", "8.8.8.8", 1, 53)));
    }

    [Fact]
    public void ConditionsCombineWithAnd()
    {
        var f = Made(host: "8.8.8.8", port: 53, proto: "udp");
        Assert.True(f.Matches(Udp("10.0.0.5", "8.8.8.8", 51234, 53)));
        Assert.False(f.Matches(Udp("10.0.0.5", "1.1.1.1", 51234, 53)));   // wrong host
        Assert.False(f.Matches(Udp("10.0.0.5", "8.8.8.8", 51234, 123)));  // wrong port
        Assert.False(f.Matches(Pkt.Decode(Pkt.V4(6, "10.0.0.5", "8.8.8.8", Pkt.Tcp(51234, 53, 0x02))))); // wrong protocol
    }

    /// <summary>
    /// The point of the src/dst filters: the request and the answer of the same
    /// conversation have to be separable, which "host" alone cannot do.
    /// </summary>
    [Fact]
    public void SourceAddressMatchesOneDirectionOnly()
    {
        var request = Udp("10.0.0.5", "8.8.8.8", 51234, 53);
        var reply = Udp("8.8.8.8", "10.0.0.5", 53, 51234);
        var f = Made(src: "10.0.0.5");
        Assert.True(f.Matches(request));
        Assert.False(f.Matches(reply));
    }

    [Fact]
    public void DestinationAddressMatchesOneDirectionOnly()
    {
        var f = Made(dst: "8.8.8.8");
        Assert.True(f.Matches(Udp("10.0.0.5", "8.8.8.8", 51234, 53)));
        Assert.False(f.Matches(Udp("8.8.8.8", "10.0.0.5", 53, 51234)));
    }

    [Fact]
    public void SourceAndDestinationPortsAreSeparate()
    {
        Assert.True(Made(dport: 53).Matches(Udp("10.0.0.5", "8.8.8.8", 51234, 53)));
        Assert.False(Made(dport: 53).Matches(Udp("8.8.8.8", "10.0.0.5", 53, 51234)));
        Assert.True(Made(sport: 53).Matches(Udp("8.8.8.8", "10.0.0.5", 53, 51234)));
        Assert.False(Made(sport: 53).Matches(Udp("10.0.0.5", "8.8.8.8", 51234, 53)));
    }

    /// <summary>Address and port of the same side pin down one flow: this host asking that service.</summary>
    [Fact]
    public void SourceAddressAndDestinationPortCombine()
    {
        var f = Made(src: "10.0.0.5", dport: 443);
        Assert.True(f.Matches(Pkt.Decode(Pkt.V4(6, "10.0.0.5", "1.1.1.1", Pkt.Tcp(51234, 443, 0x02)))));
        Assert.False(f.Matches(Pkt.Decode(Pkt.V4(6, "10.0.0.9", "1.1.1.1", Pkt.Tcp(51234, 443, 0x02))))); // another host
        Assert.False(f.Matches(Pkt.Decode(Pkt.V4(6, "1.1.1.1", "10.0.0.5", Pkt.Tcp(443, 51234, 0x12))))); // the answer
    }

    [Fact]
    public void DescribesItselfForTheHeaderLine()
    {
        Assert.Equal("tcp and host 10.0.0.1 and port 443", new CaptureFilter { Proto = "TCP", Host = "10.0.0.1", Port = 443 }.Describe());
        Assert.Equal("src host 10.0.0.5 and dst port 443", new CaptureFilter { SrcHost = "10.0.0.5", DstPort = 443 }.Describe());
    }

    [Fact]
    public void UnknownHostNameFails() =>
        Assert.ThrowsAny<Exception>(() => Made(host: "no-such-host.invalid"));
}

using System.Buffers.Binary;
using System.Net;
using Xunit;

namespace Nwtoolkit.Tests;

public class DhcpTests
{
    static readonly byte[] mac = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

    [Fact]
    public void BuildsDiscover()
    {
        var b = Dhcp.Build(Dhcp.Discover, 0xdeadbeef, mac, IPAddress.Any, true);
        Assert.Equal(1, b[0]);   // BOOTREQUEST
        Assert.Equal(1, b[1]);   // ethernet
        Assert.Equal(6, b[2]);   // hlen
        Assert.Equal(0xdeadbeefu, BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(4)));
        Assert.Equal(0x8000, BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(10))); // broadcast flag
        Assert.Equal(mac, b[28..34]);
        Assert.Equal(Dhcp.MagicCookie, BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(236)));
        Assert.Equal(53, b[240]);
        Assert.Equal(Dhcp.Discover, b[242]);
        Assert.Equal(255, b[^1]);
    }

    [Fact]
    public void InformCarriesClientAddressWithoutBroadcastFlag()
    {
        var b = Dhcp.Build(Dhcp.Inform, 1, mac, IPAddress.Parse("10.0.0.5"), false);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(10)));
        Assert.Equal(new byte[] { 10, 0, 0, 5 }, b[12..16]);
        Assert.Equal(Dhcp.Inform, b[242]);
    }

    static byte[] Reply(byte msgType, uint xid, byte[] yiaddr, byte[] serverId)
    {
        var b = new byte[240 + 3 + 6 + 1];
        b[0] = 2; // BOOTREPLY
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), xid);
        yiaddr.CopyTo(b, 16);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(236), Dhcp.MagicCookie);
        var i = 240;
        b[i++] = 53; b[i++] = 1; b[i++] = msgType;
        b[i++] = 54; b[i++] = 4; serverId.CopyTo(b, i); i += 4;
        b[i] = 255;
        return b;
    }

    [Fact]
    public void ParsesOffer()
    {
        var r = Reply(Dhcp.Offer, 42, new byte[] { 192, 168, 1, 50 }, new byte[] { 192, 168, 1, 1 });
        Assert.True(Dhcp.Parse(r, out var mt, out var yi, out var sid));
        Assert.Equal(Dhcp.Offer, mt);
        Assert.Equal(IPAddress.Parse("192.168.1.50"), yi);
        Assert.Equal(IPAddress.Parse("192.168.1.1"), sid);
    }

    [Fact]
    public void RejectsRequestsAndShortPackets()
    {
        Assert.False(Dhcp.Parse(Dhcp.Build(Dhcp.Discover, 1, mac, IPAddress.Any, true), out _, out _, out _));
        Assert.False(Dhcp.Parse(new byte[100], out _, out _, out _));
    }

    [Fact]
    public void ClassifiesFramesByDirection()
    {
        var xid = 0x01020304u;
        var offer = Reply(Dhcp.Offer, xid, new byte[] { 10, 0, 0, 9 }, new byte[] { 10, 0, 0, 1 });
        var toClient = Frame(67, 68, offer);
        Assert.True(DhcpPktmon.Classify(toClient, xid, out var mt, out var yi, out var sid, out var dir));
        Assert.Equal(DhcpPktmon.ToClient, dir);
        Assert.Equal(Dhcp.Offer, mt);
        Assert.Equal(IPAddress.Parse("10.0.0.9"), yi);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), sid);

        var discover = Dhcp.Build(Dhcp.Discover, xid, mac, IPAddress.Any, true);
        var toServer = Frame(68, 67, discover);
        Assert.True(DhcpPktmon.Classify(toServer, xid, out _, out _, out _, out dir));
        Assert.Equal(DhcpPktmon.ToServer, dir);
        Assert.True(DhcpPktmon.IsDhcpFrame(toServer));

        Assert.False(DhcpPktmon.Classify(toClient, xid + 1, out _, out _, out _, out _)); // other transaction
        Assert.False(DhcpPktmon.Classify(Frame(53, 5353, offer), xid, out _, out _, out _, out _)); // not DHCP ports
        Assert.False(DhcpPktmon.IsDhcpFrame(Frame(53, 5353, offer)));
    }

    /// <summary>Wraps a UDP payload in Ethernet + IPv4 + UDP headers.</summary>
    static byte[] Frame(ushort sport, ushort dport, byte[] payload)
    {
        var f = new byte[14 + 20 + 8 + payload.Length];
        f[12] = 0x08; f[13] = 0x00;      // IPv4
        f[14] = 0x45;                    // IHL 5
        f[14 + 9] = 17;                  // UDP
        BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(34), sport);
        BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(36), dport);
        payload.CopyTo(f, 42);
        return f;
    }

    [Fact]
    public void ServerSummaryOnlyWithSeveralServers()
    {
        var r = new DhcpResult();
        r.AddServer(IPAddress.Parse("10.0.0.1"));
        r.AddServer(IPAddress.Parse("10.0.0.1"));
        Assert.Equal("", r.ServerSummary());
        r.AddServer(IPAddress.Parse("10.0.0.2"));
        Assert.Equal("2 servers answered: 10.0.0.1, 10.0.0.2", r.ServerSummary());
    }

    [Fact]
    public void CaptureDiagExplainsEachStage()
    {
        Assert.Contains("empty", DhcpPktmon.CaptureDiag(0, 0, 0, 0, false));
        Assert.Contains("no frames", DhcpPktmon.CaptureDiag(10, 0, 0, 0, false));
        Assert.Contains("not a single DHCP", DhcpPktmon.CaptureDiag(10, 5, 0, 0, false));
        Assert.Contains("never left", DhcpPktmon.CaptureDiag(10, 5, 2, 0, false));
        Assert.Contains("transaction id", DhcpPktmon.CaptureDiag(10, 5, 2, 0, true));
        Assert.Contains("no OFFER", DhcpPktmon.CaptureDiag(10, 5, 2, 1, true));
    }
}

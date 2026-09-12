using System.Text;
using Xunit;

namespace Nwtoolkit.Tests;

/// <summary>
/// Assembles the minimum pcapng structure the parser needs: a Section Header Block,
/// optional Interface Description Blocks and Enhanced Packet Blocks.
/// </summary>
sealed class PcapngBuilder
{
    readonly List<byte> b = new();
    public byte[] Bytes => b.ToArray();

    static byte[] Le32(uint v) => new[] { (byte)v, (byte)(v >> 8), (byte)(v >> 16), (byte)(v >> 24) };

    public PcapngBuilder Section()
    {
        b.AddRange(Le32(0x0A0D0D0A));
        b.AddRange(Le32(28));
        b.AddRange(Le32(0x1A2B3C4D));
        b.AddRange(new byte[] { 1, 0, 0, 0 });
        b.AddRange(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
        b.AddRange(Le32(28));
        return this;
    }

    /// <summary>Adds an Interface Description Block. A tsresol below zero omits the if_tsresol option.</summary>
    public PcapngBuilder Iface(int tsresol)
    {
        var body = new List<byte> { 1, 0, 0, 0, 0, 0, 4, 0 }; // linktype ethernet, reserved, snaplen
        if (tsresol >= 0)
        {
            body.AddRange(new byte[] { 9, 0, 1, 0, (byte)tsresol, 0, 0, 0 }); // option code 9, len 1, value + padding
            body.AddRange(new byte[] { 0, 0, 0, 0 });                          // opt_endofopt
        }
        var total = (uint)(12 + body.Count);
        b.AddRange(Le32(0x00000001));
        b.AddRange(Le32(total));
        b.AddRange(body);
        b.AddRange(Le32(total));
        return this;
    }

    public PcapngBuilder Packet(uint ifi, uint tsHigh, uint tsLow, byte[] payload)
    {
        var pad = (4 - payload.Length % 4) % 4;
        var body = new List<byte>();
        body.AddRange(Le32(ifi));
        body.AddRange(Le32(tsHigh));
        body.AddRange(Le32(tsLow));
        body.AddRange(Le32((uint)payload.Length));
        body.AddRange(Le32((uint)payload.Length));
        body.AddRange(payload);
        body.AddRange(new byte[pad]);
        var total = (uint)(12 + body.Count);
        b.AddRange(Le32(0x00000006));
        b.AddRange(Le32(total));
        b.AddRange(body);
        b.AddRange(Le32(total));
        return this;
    }
}

public class PcapngTests
{
    static byte[] Frame(string sysname) =>
        LldpTests.LldpFrame(LldpTests.Tlv(5, Encoding.ASCII.GetBytes(sysname)), LldpTests.Tlv(0, Array.Empty<byte>()));

    [Fact]
    public void ParsesEnhancedPacketBlock()
    {
        var frame = Frame("sw-test");
        var data = new PcapngBuilder().Section().Packet(0, 0, 0, frame).Bytes;
        var frames = Pcapng.Parse(data);
        Assert.Single(frames);
        var nb = Lldp.Parse(frames[0]);
        Assert.NotNull(nb);
        Assert.Equal("sw-test", nb!.SysName);
    }

    /// <summary>
    /// The timestamp scaling is what turns a capture into a response time. Getting the
    /// if_tsresol option wrong silently skews every DHCP measurement taken through pktmon.
    /// </summary>
    [Theory]
    [InlineData(9, 123456789u, 123456789L)]        // nanoseconds
    [InlineData(6, 1000u, 1000L * 1000)]           // microseconds
    [InlineData(3, 5u, 5L * 1000000)]              // milliseconds
    [InlineData(-1, 2500u, 2500L * 1000)]          // default is microseconds
    public void TimestampResolution(int tsresol, uint ts, long wantNanos)
    {
        var payload = Frame("sw-test");
        var data = new PcapngBuilder().Section().Iface(tsresol).Packet(0, 0, ts, payload).Bytes;
        var frames = Pcapng.ParseWithTimestamps(data);
        Assert.Single(frames);
        Assert.Equal(wantNanos, frames[0].TsNanos);
        Assert.Equal(payload, frames[0].Data);
    }

    /// <summary>Each packet uses the resolution of its own interface, since pktmon writes several interfaces into one capture.</summary>
    [Fact]
    public void TimestampPerInterface()
    {
        var payload = LldpTests.LldpFrame(LldpTests.Tlv(0, Array.Empty<byte>()));
        var data = new PcapngBuilder().Section().Iface(9).Iface(3).Packet(0, 0, 1000, payload).Packet(1, 0, 1000, payload).Bytes;
        var frames = Pcapng.ParseWithTimestamps(data);
        Assert.Equal(2, frames.Count);
        Assert.Equal(1000L, frames[0].TsNanos);
        Assert.Equal(1000L * 1000000, frames[1].TsNanos);
    }

    [Fact]
    public void StopsAtTruncatedBlock()
    {
        var data = new PcapngBuilder().Section().Packet(0, 0, 0, Frame("a")).Bytes;
        var cut = data[..^5]; // last block is cut short
        Assert.Empty(Pcapng.Parse(cut));
    }
}

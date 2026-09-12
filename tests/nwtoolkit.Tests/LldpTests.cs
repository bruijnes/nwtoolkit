using System.Text;
using Xunit;

namespace Nwtoolkit.Tests;

public class LldpTests
{
    /// <summary>Builds an LLDP frame with the given TLVs, after the 14-byte Ethernet header.</summary>
    internal static byte[] LldpFrame(params byte[][] tlvs)
    {
        var f = new List<byte>(new byte[14]);
        f[12] = 0x88;
        f[13] = 0xcc;
        foreach (var t in tlvs) f.AddRange(t);
        return f.ToArray();
    }

    internal static byte[] Tlv(byte typ, byte[] val)
    {
        var l = val.Length;
        var b = new List<byte> { (byte)((typ << 1) | ((l >> 8) & 1)), (byte)(l & 0xff) };
        b.AddRange(val);
        return b.ToArray();
    }

    static byte[] Cat(byte[] a, byte[] b) => a.Concat(b).ToArray();

    [Fact]
    public void ParsesTypicalFrame()
    {
        var chassis = Tlv(1, Cat(new byte[] { 4 }, new byte[] { 0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc })); // MAC
        var port = Tlv(2, Cat(new byte[] { 5 }, Encoding.ASCII.GetBytes("GigabitEthernet0/1")));       // interface name
        var ttl = Tlv(3, new byte[] { 0, 120 });
        var sysname = Tlv(5, Encoding.ASCII.GetBytes("sw-core-01"));
        var vlan = Tlv(127, new byte[] { 0x00, 0x80, 0xc2, 0x01, 0x00, 0x64 }); // 802.1 Port VLAN ID = 100
        var end = Tlv(0, Array.Empty<byte>());

        var n = Lldp.Parse(LldpFrame(chassis, port, ttl, sysname, vlan, end));
        Assert.NotNull(n);
        Assert.Equal("00:0c:29:aa:bb:cc", n!.ChassisID);
        Assert.Equal("GigabitEthernet0/1", n.PortID);
        Assert.Equal("sw-core-01", n.SysName);
        Assert.Equal(120, n.TTL);
        Assert.Equal(100, n.VLAN);
    }

    [Fact]
    public void DecodesManagementAddressAndCapabilities()
    {
        var mgmt = Tlv(8, new byte[] { 5, 1, 192, 168, 1, 1, 2, 0, 0, 0, 0, 0 }); // len 5, IPv4 subtype, addr; then if-numbering
        var caps = Tlv(7, new byte[] { 0x00, 0x14, 0x00, 0x04 }); // enabled: Bridge
        var n = Lldp.Parse(LldpFrame(Tlv(5, Encoding.ASCII.GetBytes("x")), mgmt, caps, Tlv(0, Array.Empty<byte>())));
        Assert.NotNull(n);
        Assert.Equal("192.168.1.1", n!.MgmtAddr);
        Assert.Equal("Bridge", n.Caps);
    }

    [Fact]
    public void RejectsNonLldp()
    {
        var f = new byte[60];
        f[12] = 0x08;
        f[13] = 0x00; // IPv4
        Assert.Null(Lldp.Parse(f));
    }

    [Fact]
    public void RejectsEmptyLldp()
    {
        Assert.Null(Lldp.Parse(LldpFrame(Tlv(3, new byte[] { 0, 120 }), Tlv(0, Array.Empty<byte>()))));
    }

    [Fact]
    public void FirstLineTruncates()
    {
        Assert.Equal("Cisco IOS …", Lldp.FirstLine("Cisco IOS\nmore"));
        Assert.Equal("short", Lldp.FirstLine("short"));
        Assert.EndsWith(" …", Lldp.FirstLine(new string('a', 200)));
    }
}

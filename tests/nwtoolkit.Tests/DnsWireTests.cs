using Xunit;

namespace Nwtoolkit.Tests;

public class DnsWireTests
{
    [Fact]
    public void BuildsQuery()
    {
        var q = DnsWire.BuildQuery(0x1234, "example.com", 15);
        Assert.Equal(0x12, q[0]);
        Assert.Equal(0x34, q[1]);
        Assert.Equal(0x01, q[2]); // RD
        Assert.Equal(1, q[5]);    // qdcount
        // 7 'example' 3 'com' 0
        Assert.Equal(7, q[12]);
        Assert.Equal((byte)'e', q[13]);
        Assert.Equal(3, q[20]);
        Assert.Equal(0, q[24]);
        Assert.Equal(15, q[26]); // qtype MX
        Assert.Equal(1, q[28]);  // class IN
    }

    [Fact]
    public void ParsesAnswerWithCompression()
    {
        // header: id 0x1234, flags 0x8180 (response, RD, RA), qd 1, an 2
        var m = new List<byte> { 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0 };
        // question: example.com A IN
        m.AddRange(new byte[] { 7 }); m.AddRange("example"u8.ToArray());
        m.AddRange(new byte[] { 3 }); m.AddRange("com"u8.ToArray());
        m.AddRange(new byte[] { 0, 0, 1, 0, 1 });
        // answer 1: pointer to offset 12, type A, ttl 300, rdlen 4, 93.184.216.34
        m.AddRange(new byte[] { 0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 93, 184, 216, 34 });
        // answer 2: pointer, type MX, ttl 60, rdlen: pref 10 + "mail" + pointer to example.com
        m.AddRange(new byte[] { 0xC0, 12, 0, 15, 0, 1, 0, 0, 0, 60, 0, 9, 0, 10, 4 });
        m.AddRange("mail"u8.ToArray());
        m.AddRange(new byte[] { 0xC0, 12 });

        var r = DnsWire.Parse(m.ToArray());
        Assert.Equal(0x1234, r.Id);
        Assert.Equal(0, r.Rcode);
        Assert.False(r.Truncated);
        Assert.Equal(2, r.Answers.Count);
        Assert.Equal("example.com.", r.Answers[0].Name);
        Assert.Equal("93.184.216.34", r.Answers[0].Data);
        Assert.Equal("A", r.Answers[0].TypeName);
        Assert.Equal(300u, r.Answers[0].Ttl);
        Assert.Equal("10 mail.example.com.", r.Answers[1].Data);
        Assert.Equal("MX", r.Answers[1].TypeName);
    }

    [Fact]
    public void ParsesTxtAndRcode()
    {
        var m = new List<byte> { 0, 1, 0x81, 0x83, 0, 0, 0, 1, 0, 0, 0, 0 }; // NXDOMAIN, no question, one answer
        m.AddRange(new byte[] { 0, 0, 16, 0, 1, 0, 0, 0, 1, 0, 6, 5 });
        m.AddRange("hello"u8.ToArray());
        var r = DnsWire.Parse(m.ToArray());
        Assert.Equal(3, r.Rcode);
        Assert.Equal("NXDOMAIN", DnsWire.RcodeName(r.Rcode));
        Assert.Equal("\"hello\"", r.Answers[0].Data);
        Assert.Equal(".", r.Answers[0].Name);
    }

    [Fact]
    public void RejectsPointerLoop()
    {
        var m = new List<byte> { 0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0 };
        m.AddRange(new byte[] { 0xC0, 12, 0, 1, 0, 1 }); // name points to itself
        Assert.Throws<FormatException>(() => DnsWire.Parse(m.ToArray()));
    }

    [Theory]
    [InlineData("A", 1)]
    [InlineData("aaaa", 28)]
    [InlineData("MX", 15)]
    [InlineData("hinfo", 13)]
    [InlineData("TYPE99", 99)]
    [InlineData("bogus", 1)]
    public void TypeCodes(string name, int code)
    {
        Assert.Equal(code, DnsWire.TypeCode(name));
    }

    [Theory]
    [InlineData("1.1.1.1", "1.1.1.1", 53)]
    [InlineData("1.1.1.1:5353", "1.1.1.1", 5353)]
    [InlineData("2606:4700:4700::1111", "2606:4700:4700::1111", 53)]
    [InlineData("[2606:4700:4700::1111]:5353", "2606:4700:4700::1111", 5353)]
    public void ServerAddress(string input, string ip, int port)
    {
        var ep = DnsCmd.ServerAddr(input, false);
        Assert.Equal(System.Net.IPAddress.Parse(ip), ep.Address);
        Assert.Equal(port, ep.Port);
    }
}

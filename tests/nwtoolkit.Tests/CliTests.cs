using Xunit;

namespace Nwtoolkit.Tests;

public class CliTests
{
    [Fact]
    public void SplitArgsKeepsBoolFlagsApart()
    {
        var (pos, flags) = Cli.SplitArgs(new[] { "-s", "1.1.1.1", "example.com", "-1", "-type=MX" }, new HashSet<string> { "1" });
        Assert.Equal(new[] { "example.com" }, pos);
        Assert.Equal(new[] { "-s", "1.1.1.1", "-1", "-type=MX" }, flags);
    }

    [Fact]
    public void SplitArgsFlagsAfterHost()
    {
        var (pos, flags) = Cli.SplitArgs(new[] { "8.8.8.8", "-t", "-i", "0.5" }, new HashSet<string> { "t" });
        Assert.Equal(new[] { "8.8.8.8" }, pos);
        Assert.Equal(new[] { "-t", "-i", "0.5" }, flags);
    }

    [Fact]
    public void SplitArgsDoubleDash()
    {
        var (pos, flags) = Cli.SplitArgs(new[] { "-c", "3", "--", "-weird-host" }, new HashSet<string>());
        Assert.Equal(new[] { "-weird-host" }, pos);
        Assert.Equal(new[] { "-c", "3" }, flags);
    }

    [Fact]
    public void FlagSetParsesTypes()
    {
        var fs = new FlagSet("t");
        var c = fs.Int("c", 4);
        var i = fs.Double("i", 1);
        var t = fs.Bool("t");
        var s = fs.String("s", "");
        var m = fs.Bool("m", true);
        fs.Parse(new[] { "-c", "10", "--i=0.25", "-t", "-s", "1.1.1.1", "-m=false" });
        Assert.Equal(10, c.Value);
        Assert.Equal(0.25, i.Value);
        Assert.True(t.Value);
        Assert.Equal("1.1.1.1", s.Value);
        Assert.False(m.Value);
    }

    [Fact]
    public void StripKeepOpenSetsHold()
    {
        Util.HoldOnExit = false;
        var args = Cli.StripKeepOpen(new[] { "lldp", "-keepopen", "-m" });
        Assert.Equal(new[] { "lldp", "-m" }, args);
        Assert.True(Util.HoldOnExit);
        Util.HoldOnExit = false;
    }

    [Fact]
    public void CommandLineQuotesWhereNeeded()
    {
        Assert.Equal("gui", Elevation.CommandLine(new[] { "gui" }));
        Assert.Equal("lldp -i \"Wi-Fi 2\" \"\"", Elevation.CommandLine(new[] { "lldp", "-i", "Wi-Fi 2", "" }));
        Assert.Equal("\"say \\\"hi\\\"\"", Elevation.CommandLine(new[] { "say \"hi\"" }));
    }

    [Fact]
    public void StatsComputes()
    {
        var s = Stats.Compute(new[] { 1.0, 2.0, 3.0, 4.0 }, 1);
        Assert.Equal(1, s.Min);
        Assert.Equal(4, s.Max);
        Assert.Equal(2.5, s.Avg);
        Assert.Equal(4, s.Last);
        Assert.Equal(20, s.Loss);
        Assert.Equal(4, s.N);
        Assert.Equal(1, s.Lost);
        Assert.Equal("min 1.00 / avg 2.50 / max 4.00 / stddev 1.12 ms   loss 20% (1/5)", s.ToString());

        var empty = Stats.Compute(Array.Empty<double>(), 2);
        Assert.Equal(100, empty.Loss);
    }

    [Fact]
    public void PercentileAndRing()
    {
        Assert.Equal(9, Util.Percentile(Enumerable.Range(1, 10).Select(x => (double)x).ToList(), 90));
        Assert.Equal(0, Util.Percentile(Array.Empty<double>(), 95));
        var r = new Ring(3);
        for (var i = 1; i <= 5; i++) r.Push(i);
        Assert.Equal(new[] { 3.0, 4.0, 5.0 }, r.Buf);
    }

    [Fact]
    public void AsciiGraphDrawsAxisAndLine()
    {
        var g = AsciiGraph.Plot(new[] { 1.0, 2.0, 3.0, 2.0, 1.0 }, 4, 0, "cap");
        var lines = g.Split('\n');
        Assert.True(lines.Length >= 5);
        Assert.Contains("┤", g);
        Assert.Contains("┼", g);
        Assert.Contains("╭", g);
        Assert.Contains("╮", g);
        Assert.EndsWith("cap", g);
        Assert.Contains("3.00", lines[0]);
        // a 100-wide interpolation of two points is a single straight line
        var flat = AsciiGraph.Plot(new[] { 5.0, 5.0 }, 12, 100);
        Assert.Contains("─", flat);
        Assert.DoesNotContain("│", flat);
    }
}

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;

namespace Nwtoolkit;

/// <summary>Small helpers shared by every command: version, colours, resolving, statistics.</summary>
public static class Util
{
    /// <summary>Product version, taken from the assembly so the csproj is the single source of truth.</summary>
    public static readonly string Version = ReadVersion();

    static string ReadVersion()
    {
        var asm = typeof(Util).Assembly;
        var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrEmpty(info))
        {
            var plus = info.IndexOf('+');
            return plus > 0 ? info[..plus] : info;
        }
        return asm.GetName().Version?.ToString(2) ?? "0.0";
    }

    // ANSI colours
    public const string CReset = "\u001b[0m";
    public const string CRed = "\u001b[31m";
    public const string CGreen = "\u001b[32m";
    public const string CYellow = "\u001b[33m";
    public const string CCyan = "\u001b[36m";
    public const string CGrey = "\u001b[90m";
    public const string CBold = "\u001b[1m";
    public const string ClrScr = "\u001b[2J\u001b[H";

    public static bool UseColor = true;

    public static string Col(string c, string s) => UseColor ? c + s + CReset : s;

    /// <summary>Formats with the invariant culture, so "1.25" never becomes "1,25" on a Dutch machine.</summary>
    public static string F(this double v, int decimals) => v.ToString("F" + decimals, CultureInfo.InvariantCulture);

    public static double Ms(TimeSpan d) => d.Ticks / (double)TimeSpan.TicksPerMillisecond;

    public static TimeSpan Dur(double seconds) => TimeSpan.FromTicks((long)(seconds * TimeSpan.TicksPerSecond));

    /// <summary>Resolves a hostname to an IPv4 address.</summary>
    public static IPAddress Resolve4(string host) => ResolveIP(host, false);

    /// <summary>Resolves a hostname to an IPv4 or IPv6 address, depending on <paramref name="v6"/>.</summary>
    public static IPAddress ResolveIP(string host, bool v6)
    {
        host = host.Trim();
        if (host.Length == 0) throw new ArgumentException("no host given");
        if (IPAddress.TryParse(host, out var literal))
            return literal; // a literal IP is explicit; the family follows from the address itself
        var family = v6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        IPAddress[] ips;
        try
        {
            ips = Dns.GetHostAddresses(host);
        }
        catch (SocketException e)
        {
            throw new Exception($"lookup {host}: {e.Message}");
        }
        foreach (var ip in ips)
            if (ip.AddressFamily == family)
                return ip;
        throw new Exception($"no {(v6 ? "IPv6" : "IPv4")} address found for {host}");
    }

    /// <summary>Returns the p-th percentile of the samples.</summary>
    public static double Percentile(IReadOnlyList<double> samples, double p)
    {
        if (samples.Count == 0) return 0;
        var cp = samples.ToArray();
        Array.Sort(cp);
        var idx = (int)Math.Ceiling(p / 100 * cp.Length) - 1;
        if (idx < 0) idx = 0;
        if (idx >= cp.Length) idx = cp.Length - 1;
        return cp[idx];
    }

    public static string NowStamp() => DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    /// <summary>
    /// Set when this process was relaunched with -keepopen, i.e. an elevated copy running in
    /// a fresh console that would otherwise close the instant it finishes.
    /// </summary>
    public static bool HoldOnExit;

    /// <summary>Pauses so the output stays readable before such a window closes.</summary>
    public static void HoldIfNeeded()
    {
        if (!HoldOnExit) return;
        Console.Write("\nPress Enter to close…");
        Console.ReadLine();
    }

    /// <summary>Prints an error and exits the process with code 1.</summary>
    public static void Die(string message)
    {
        Console.Error.WriteLine(Col(CRed, "error: ") + message);
        HoldIfNeeded();
        Environment.Exit(1);
    }

    public static string Join(IEnumerable<IPAddress> ips) => string.Join(", ", ips.Select(i => i.ToString()));

    /// <summary>Preserves order and drops duplicate messages.</summary>
    public static List<string> Dedup(IEnumerable<string> input)
    {
        var seen = new HashSet<string>();
        var out_ = new List<string>();
        foreach (var s in input)
            if (seen.Add(s)) out_.Add(s);
        return out_;
    }
}

/// <summary>min/avg/max/stddev over a series of RTTs in ms.</summary>
public readonly record struct Stats(double Min, double Avg, double Max, double Stddev, double Last, double Loss, int N, int Lost)
{
    public static Stats Compute(IReadOnlyList<double> samples, int lost)
    {
        if (samples.Count == 0)
            return new Stats(0, 0, 0, 0, 0, lost > 0 ? 100 : 0, 0, lost);
        double min = double.MaxValue, max = double.MinValue, sum = 0;
        foreach (var v in samples)
        {
            sum += v;
            if (v < min) min = v;
            if (v > max) max = v;
        }
        var avg = sum / samples.Count;
        double sq = 0;
        foreach (var v in samples) sq += (v - avg) * (v - avg);
        var total = samples.Count + lost;
        var loss = total > 0 ? lost * 100.0 / total : 0;
        return new Stats(min, avg, max, Math.Sqrt(sq / samples.Count), samples[^1], loss, samples.Count, lost);
    }

    public override string ToString() =>
        $"min {Min.F(2)} / avg {Avg.F(2)} / max {Max.F(2)} / stddev {Stddev.F(2)} ms   loss {Loss.F(0)}% ({Lost}/{N + Lost})";
}

/// <summary>Keeps the last n values for the chart.</summary>
public sealed class Ring
{
    readonly int max;
    public readonly List<double> Buf = new();
    public Ring(int max) => this.max = max;

    public void Push(double v)
    {
        Buf.Add(v);
        if (Buf.Count > max) Buf.RemoveRange(0, Buf.Count - max);
    }
}

/// <summary>Turns Ctrl+C into a cancellation token instead of killing the process.</summary>
public sealed class CtrlC : IDisposable
{
    readonly CancellationTokenSource cts = new();
    readonly ConsoleCancelEventHandler handler;

    public CtrlC()
    {
        handler = (_, e) => { e.Cancel = true; cts.Cancel(); };
        try { Console.CancelKeyPress += handler; } catch (IOException) { /* no console */ }
    }

    public CancellationToken Token => cts.Token;

    /// <summary>Waits for the interval; returns true when Ctrl+C was pressed in the meantime.</summary>
    public bool Wait(TimeSpan d)
    {
        if (d <= TimeSpan.Zero) return cts.IsCancellationRequested;
        return cts.Token.WaitHandle.WaitOne(d);
    }

    public void Dispose()
    {
        try { Console.CancelKeyPress -= handler; } catch (IOException) { }
        cts.Dispose();
    }
}

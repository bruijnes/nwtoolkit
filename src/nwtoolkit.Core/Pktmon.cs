using System.Diagnostics;

namespace Nwtoolkit;

/// <summary>No pktmon on this platform or Windows version.</summary>
public sealed class PktmonUnsupportedException : Exception
{
    public PktmonUnsupportedException() : base("pktmon not available on this platform") { }
}

/// <summary>
/// Packet Monitor is the only layer-2 capture Windows ships with. It works in batches
/// rather than as a live stream: start a capture to an ETL file, let traffic happen,
/// stop, convert to pcapng, then parse. Both the LLDP and the DHCP probe need exactly
/// that sequence, so it lives here once.
/// </summary>
public static class Pktmon
{
    /// <summary>
    /// Gives the capture a moment to actually start before the caller transmits. Without
    /// it the outgoing frame can be sent before pktmon is recording.
    /// </summary>
    public static readonly TimeSpan SettleDelay = TimeSpan.FromMilliseconds(150);

    public static string? Path()
    {
        if (!OperatingSystem.IsWindows()) return null;
        var p = System.IO.Path.Combine(Environment.SystemDirectory, "pktmon.exe");
        return File.Exists(p) ? p : null;
    }

    /// <summary>
    /// Runs one Packet Monitor session and returns the raw pcapng bytes.
    ///
    /// <paramref name="during"/> runs while the capture is recording and reports whether
    /// the recorded frames are still wanted. Returning false ends the session without the
    /// pcapng round trip, which the DHCP probe uses when an answer already arrived over
    /// its socket; in that case null is returned.
    ///
    /// Requires Administrator: without it the start fails and the error says so.
    /// </summary>
    public static byte[]? Capture(string name, Func<bool> during)
    {
        var exe = Path() ?? throw new PktmonUnsupportedException();
        var dir = System.IO.Path.GetTempPath();
        var etl = System.IO.Path.Combine(dir, "nwtoolkit_" + name + ".etl");
        var png = System.IO.Path.Combine(dir, "nwtoolkit_" + name + ".pcapng");
        TryDelete(etl);
        TryDelete(png);

        Hidden(exe, "stop"); // clear a session left behind by an earlier run
        var (code, output) = Hidden(exe, "start", "--capture", "--pkt-size", "0", "--file-name", etl);
        if (code != 0) throw new Exception($"pktmon start failed (Administrator required?): {TrimOut(output)}");
        try
        {
            if (!during()) return null;
            Hidden(exe, "stop");

            var (ccode, cout) = Hidden(exe, "pcapng", etl, "-o", png);
            if (ccode != 0) throw new Exception($"pktmon pcapng conversion failed: {TrimOut(cout)}");
            try { return File.ReadAllBytes(png); }
            catch (Exception e) { throw new Exception($"reading pcapng: {e.Message}"); }
        }
        finally
        {
            Hidden(exe, "stop");
            TryDelete(etl);
            TryDelete(png);
        }
    }

    static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { }
    }

    /// <summary>
    /// Runs a command that opens no window of its own. Without this a black console
    /// flashes up whenever the GUI starts pktmon.
    /// </summary>
    public static (int Code, string Output) Hidden(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi) ?? throw new Exception("could not start " + file);
            var stdout = p.StandardOutput.ReadToEndAsync();
            var stderr = p.StandardError.ReadToEndAsync();
            p.WaitForExit();
            return (p.ExitCode, stdout.Result + stderr.Result);
        }
        catch (Exception e)
        {
            return (-1, e.Message);
        }
    }

    /// <summary>Shortens command output so a failure message stays readable.</summary>
    static string TrimOut(string s) => s.Length > 300 ? s[..300] : s;
}

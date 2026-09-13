using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;

namespace Nwtoolkit;

/// <summary>Outcome of one ICMP echo. <see cref="Error"/> is set only on API failures.</summary>
public readonly record struct EchoResult(IPAddress? Peer, TimeSpan Rtt, IPStatus Status, string? Error)
{
    public double Ms => Util.Ms(Rtt);

    /// <summary>True when nobody answered: a timeout, an error, or a reply without a source address.</summary>
    public bool NoAnswer => Error != null || Status == IPStatus.TimedOut || Peer == null
                            || Peer.Equals(IPAddress.Any) || Peer.Equals(IPAddress.IPv6Any);
}

/// <summary>
/// ICMP echo over the platform ping API (IcmpSendEcho2 / Icmp6SendEcho2 on Windows, which
/// needs no Administrator). The RTT is measured with a stopwatch rather than the
/// millisecond counter Windows returns.
/// </summary>
public sealed class Echo : IDisposable
{
    readonly Ping ping = new();

    /// <summary>Sends one echo to <paramref name="dst"/> with the given TTL and timeout.</summary>
    public EchoResult Send(IPAddress dst, int ttl, TimeSpan timeout, byte[] payload)
    {
        var opts = new PingOptions(ttl, false);
        var sw = Stopwatch.StartNew();
        try
        {
            var reply = ping.Send(dst, (int)Math.Max(1, timeout.TotalMilliseconds), payload, opts);
            sw.Stop();
            return new EchoResult(reply.Address, sw.Elapsed, reply.Status, null);
        }
        catch (Exception e) when (!OperatingSystem.IsWindows() && ttl >= 64
                                  && (e is PlatformNotSupportedException || e.InnerException is PlatformNotSupportedException))
        {
            // Unprivileged Linux/macOS: .NET falls back to the ping utility, which only
            // takes its default payload. Good enough for a plain ping; a traceroute needs
            // its TTL and therefore root or cap_net_raw.
            try
            {
                sw.Restart();
                var reply = ping.Send(dst, (int)Math.Max(1, timeout.TotalMilliseconds));
                sw.Stop();
                return new EchoResult(reply.Address, sw.Elapsed, reply.Status, null);
            }
            catch (Exception e2)
            {
                sw.Stop();
                return new EchoResult(null, sw.Elapsed, IPStatus.Unknown, e2 is PingException ? e2.InnerException?.Message ?? e2.Message : (e.InnerException ?? e).Message);
            }
        }
        catch (PingException e)
        {
            sw.Stop();
            return new EchoResult(null, sw.Elapsed, IPStatus.Unknown, e.InnerException?.Message ?? e.Message);
        }
        catch (Exception e)
        {
            sw.Stop();
            return new EchoResult(null, sw.Elapsed, IPStatus.Unknown, e.Message);
        }
    }

    public static string StatusText(IPStatus s) => s switch
    {
        IPStatus.Success => "ok",
        IPStatus.DestinationNetworkUnreachable => "net unreachable",
        IPStatus.DestinationHostUnreachable => "host unreachable",
        IPStatus.DestinationProtocolUnreachable => "protocol unreachable",
        IPStatus.DestinationPortUnreachable => "port unreachable",
        IPStatus.TimedOut => "timeout",
        IPStatus.TtlExpired => "ttl-expired",
        IPStatus.BadDestination => "bad destination",
        IPStatus.BadRoute => "bad route",
        IPStatus.PacketTooBig => "packet too big",
        _ => $"status {s}",
    };

    public void Dispose() => ping.Dispose();
}

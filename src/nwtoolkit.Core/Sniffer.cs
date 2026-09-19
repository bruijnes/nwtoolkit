using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Nwtoolkit;

/// <summary>
/// Picking the adapter to capture on. An interface is identified by its name, its
/// description or the IP address bound to it, because that is what people read off
/// ipconfig; the capture itself only needs the address.
/// </summary>
public static class Sniffer
{
    /// <summary>The adapters that can be captured on: up, not loopback, with an address of the right family.</summary>
    public static List<NetIface> Interfaces(bool v6)
    {
        var out_ = new List<NetIface>();
        NetworkInterface[] nics;
        try { nics = NetworkInterface.GetAllNetworkInterfaces(); }
        catch { return out_; }
        foreach (var nic in nics)
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            if (AddressOf(nic, v6) is { } ip) out_.Add(new NetIface(nic.Name, ip, null));
        }
        return out_;
    }

    /// <summary>
    /// The address to bind to on this adapter. A global address wins from a link-local
    /// one: fe80:: only ever sees the local segment, and an IPv4 169.254 address means
    /// the adapter never got a lease.
    /// </summary>
    static IPAddress? AddressOf(NetworkInterface nic, bool v6)
    {
        IPAddress? fallback = null;
        try
        {
            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                var ip = ua.Address;
                if (v6 != (ip.AddressFamily == AddressFamily.InterNetworkV6)) continue;
                var local = v6 ? ip.IsIPv6LinkLocal : ip.GetAddressBytes() is [169, 254, _, _];
                if (!local) return ip;
                fallback ??= ip;
            }
        }
        catch { }
        return fallback;
    }

    /// <summary>
    /// The adapter of the default route: the one the operating system would send over.
    /// Connecting a UDP socket sends nothing, it only makes the stack pick a source
    /// address, which is exactly the routing decision we want to copy.
    /// </summary>
    public static NetIface? Default(bool v6)
    {
        var all = Interfaces(v6);
        if (all.Count == 0) return null;
        try
        {
            var probe = v6 ? IPAddress.Parse("2001:4860:4860::8888") : IPAddress.Parse("8.8.8.8");
            using var s = new Socket(probe.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            s.Connect(new IPEndPoint(probe, 53));
            var local = ((IPEndPoint)s.LocalEndPoint!).Address;
            foreach (var ic in all)
                if (ic.Ip.Equals(local))
                    return ic;
        }
        catch { }
        return all[0];
    }

    /// <summary>
    /// Resolves what the user asked for to an adapter. An empty name means the default
    /// adapter. The window passes "Name  (address)", so anything from the first bracket on
    /// is ignored.
    /// </summary>
    public static NetIface Select(string want, bool v6)
    {
        want = want.Trim();
        var bracket = want.IndexOf('(');
        if (bracket > 0) want = want[..bracket].Trim();
        var all = Interfaces(v6);
        if (want == "" || want == "(automatic)")
            return Default(v6) ?? throw new Exception($"no interface with an {(v6 ? "IPv6" : "IPv4")} address is up");
        foreach (var ic in all)
            if (string.Equals(ic.Name, want, StringComparison.OrdinalIgnoreCase) || ic.Ip.ToString() == want)
                return ic;
        // a description such as "Intel(R) Ethernet Connection" is what ipconfig shows
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                if (string.Equals(nic.Description, want, StringComparison.OrdinalIgnoreCase) && AddressOf(nic, v6) is { } ip)
                    return new NetIface(nic.Name, ip, null);
        }
        catch { }
        var names = all.Count == 0 ? "(none available)" : string.Join(", ", all.Select(i => i.Name));
        throw new Exception($"unknown interface \"{want}\"; available: {names}");
    }
}

/// <summary>
/// A live capture on one adapter, through a raw socket in SIO_RCVALL mode. That is the
/// only way to see other traffic on Windows without installing a driver such as Npcap,
/// and it is the reason this needs Administrator. It delivers IP packets without the
/// Ethernet frame, so ARP and LLDP are invisible here; the LLDP command uses pktmon for
/// exactly that reason.
/// </summary>
public sealed class LiveCapture : IDisposable
{
    /// <summary>How long Receive waits before it returns empty-handed, so a stop is noticed quickly.</summary>
    const int TickMs = 400;

    readonly Socket sock;

    public LiveCapture(IPAddress local)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("live packet capture is only available on Windows; it uses the raw-socket promiscuous mode (SIO_RCVALL)");
        var v6 = local.AddressFamily == AddressFamily.InterNetworkV6;
        try
        {
            sock = new Socket(local.AddressFamily, SocketType.Raw, v6 ? ProtocolType.IPv6 : ProtocolType.IP);
            sock.Bind(new IPEndPoint(local, 0));
            if (!v6) sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            sock.ReceiveBufferSize = 1 << 20; // a burst must not be dropped while a line is printed
            sock.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), null);
            sock.ReceiveTimeout = TickMs;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.AccessDenied)
        {
            throw new Exception("packet capture needs administrator rights");
        }
        catch (SocketException e)
        {
            throw new Exception($"could not capture on {local}: {e.Message}");
        }
    }

    /// <summary>
    /// Reads the next packet into the buffer and returns its length, or 0 when nothing
    /// arrived within a tick. A packet larger than the buffer is skipped rather than
    /// ending the capture.
    /// </summary>
    public int Receive(byte[] buf)
    {
        try
        {
            return sock.Receive(buf, SocketFlags.None);
        }
        catch (SocketException e) when (e.SocketErrorCode is SocketError.TimedOut or SocketError.MessageSize)
        {
            return 0;
        }
        catch (ObjectDisposedException)
        {
            return 0;
        }
    }

    public void Dispose()
    {
        try { sock.Dispose(); } catch { }
    }
}

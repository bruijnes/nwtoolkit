using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using static Nwtoolkit.Util;

namespace Nwtoolkit;

/// <summary>The decoded fields of one LLDP neighbour (the switch and port on the other end).</summary>
public sealed class LldpNeighbor
{
    public string ChassisID = "";
    public string PortID = "";
    public string PortDesc = "";
    public string SysName = "";
    public string SysDesc = "";
    public int TTL;
    public string MgmtAddr = "";
    public string Caps = "";
    public int VLAN;
    public string LocalIf = "";
    public DateTime LastSeen;

    public string Key => ChassisID + "|" + PortID;

    public void PrintBlock()
    {
        void Line(string label, string val)
        {
            if (val != "") Console.WriteLine($"  {label + ":",-16} {val}");
        }
        Console.WriteLine(Col(CBold, "  LLDP neighbour (connected device):"));
        Line("System name", SysName == "" ? "" : Col(CCyan, SysName));
        Line("Port", PortID == "" ? "" : Col(CGreen, PortID));
        Line("Port descr.", PortDesc);
        if (VLAN > 0) Line("VLAN", VLAN.ToString());
        Line("Chassis ID", ChassisID);
        Line("Mgmt address", MgmtAddr);
        Line("Capabilities", Caps);
        if (TTL > 0) Line("TTL", TTL + " s");
        if (LocalIf != "") Line("Local port", LocalIf);
        if (SysDesc != "") Console.WriteLine($"  {"System info:",-16} {Lldp.FirstLine(SysDesc)}");
    }

    /// <summary>Plain-text block for the GUI.</summary>
    public string Text()
    {
        var sb = new StringBuilder();
        void Add(string k, string v)
        {
            if (v != "") sb.Append($"  {k + ":",-16} {v}\r\n");
        }
        sb.Append("LLDP neighbour (connected device):\r\n");
        Add("System name", SysName);
        Add("Port", PortID);
        Add("Port descr.", PortDesc);
        if (VLAN > 0) Add("VLAN", VLAN.ToString());
        Add("Chassis ID", ChassisID);
        Add("Mgmt address", MgmtAddr);
        Add("Capabilities", Caps);
        if (TTL > 0) Add("TTL", TTL + " s");
        if (SysDesc != "") Add("System info", Lldp.FirstLine(SysDesc));
        return sb.ToString();
    }
}

/// <summary>The platform-specific layer-2 capture (Linux AF_PACKET; Windows uses pktmon instead).</summary>
public interface ICapturer : IDisposable
{
    /// <summary>Returns the next frame, or null when nothing arrived within the timeout.</summary>
    byte[]? Next(TimeSpan timeout);
    string Device { get; }
}

/// <summary>This platform has no live layer-2 capture; the built-in pktmon route is used (Windows only).</summary>
public sealed class NoLiveCaptureException : Exception
{
    public NoLiveCaptureException() : base("this platform has no live layer-2 capture; the built-in pktmon is used (Administrator required)") { }
}

public sealed class LldpOpts
{
    public string Iface = "";
    public TimeSpan Wait = TimeSpan.FromSeconds(35);
    public bool Monitor;
    public bool List;
}

public static class Lldp
{
    public const ushort EtherType = 0x88cc;

    /// <summary>Decodes a complete Ethernet frame, including the 14-byte header, into a neighbour.</summary>
    public static LldpNeighbor? Parse(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 14) return null;
        if (BinaryPrimitives.ReadUInt16BigEndian(frame[12..]) != EtherType) return null;
        var n = new LldpNeighbor();
        var p = frame[14..];
        var i = 0;
        while (i + 2 <= p.Length)
        {
            var t = p[i] >> 1;
            var l = ((p[i] & 1) << 8) | p[i + 1];
            i += 2;
            if (t == 0) break; // End of LLDPDU
            if (i + l > p.Length) break;
            var v = p.Slice(i, l);
            i += l;
            switch (t)
            {
                case 1: n.ChassisID = DecodeChassisID(v); break;
                case 2: n.PortID = DecodePortID(v); break;
                case 3: if (v.Length >= 2) n.TTL = BinaryPrimitives.ReadUInt16BigEndian(v); break;
                case 4: n.PortDesc = Str(v); break;
                case 5: n.SysName = Str(v); break;
                case 6: n.SysDesc = Str(v); break;
                case 7: n.Caps = DecodeCaps(v); break;
                case 8: n.MgmtAddr = DecodeMgmtAddr(v); break;
                case 127: DecodeOrg(v, n); break;
            }
        }
        if (n.ChassisID == "" && n.PortID == "" && n.SysName == "") return null;
        n.LastSeen = DateTime.Now;
        return n;
    }

    static string Str(ReadOnlySpan<byte> v) => Encoding.UTF8.GetString(v).TrimEnd('\0');

    public static string HexColon(ReadOnlySpan<byte> b)
    {
        var parts = new string[b.Length];
        for (var i = 0; i < b.Length; i++) parts[i] = b[i].ToString("x2");
        return string.Join(":", parts);
    }

    static string DecodeMAC(ReadOnlySpan<byte> b) => HexColon(b);

    static string DecodeChassisID(ReadOnlySpan<byte> v)
    {
        if (v.Length < 2) return "";
        var sub = v[0];
        var val = v[1..];
        return sub switch
        {
            4 => DecodeMAC(val),      // MAC address
            5 => DecodeNetAddr(val),  // network address
            _ => Str(val),            // locally assigned and the rest
        };
    }

    static string DecodePortID(ReadOnlySpan<byte> v)
    {
        if (v.Length < 2) return "";
        var sub = v[0];
        var val = v[1..];
        return sub switch
        {
            3 => DecodeMAC(val),      // MAC address
            4 => DecodeNetAddr(val),  // network address
            _ => Str(val),            // alias / port comp / interface name / locally assigned
        };
    }

    static string DecodeNetAddr(ReadOnlySpan<byte> v)
    {
        if (v.Length >= 5 && v[0] == 1) return new IPAddress(v.Slice(1, 4)).ToString();   // IPv4
        if (v.Length >= 17 && v[0] == 2) return new IPAddress(v.Slice(1, 16)).ToString(); // IPv6
        return HexColon(v);
    }

    static string DecodeMgmtAddr(ReadOnlySpan<byte> v)
    {
        if (v.Length < 2) return "";
        int addrLen = v[0];
        if (addrLen < 1 || 1 + addrLen > v.Length) return "";
        var subtype = v[1];
        var addr = v.Slice(2, addrLen - 1);
        switch (subtype)
        {
            case 1: if (addr.Length == 4) return new IPAddress(addr).ToString(); break;
            case 2: if (addr.Length == 16) return new IPAddress(addr).ToString(); break;
        }
        return HexColon(addr);
    }

    static string DecodeCaps(ReadOnlySpan<byte> v)
    {
        if (v.Length < 4) return "";
        var enabled = BinaryPrimitives.ReadUInt16BigEndian(v[2..]);
        var names = new[] { "Other", "Repeater", "Bridge", "WLAN-AP", "Router", "Telephone", "DOCSIS", "Station" };
        var out_ = new List<string>();
        for (var bit = 0; bit < names.Length; bit++)
            if ((enabled & (1 << bit)) != 0)
                out_.Add(names[bit]);
        return string.Join(", ", out_);
    }

    /// <summary>Reads organisation-specific TLVs, notably the IEEE 802.1 Port VLAN ID.</summary>
    static void DecodeOrg(ReadOnlySpan<byte> v, LldpNeighbor n)
    {
        if (v.Length < 4) return;
        var sub = v[3];
        var body = v[4..];
        // IEEE 802.1: OUI 00-80-c2
        if (v[0] == 0x00 && v[1] == 0x80 && v[2] == 0xc2)
        {
            switch (sub)
            {
                case 1: // Port VLAN ID
                    if (body.Length >= 2) n.VLAN = BinaryPrimitives.ReadUInt16BigEndian(body);
                    break;
                case 3: // VLAN name: [vlanid(2)][len(1)][name]
                    if (body.Length >= 3 && n.VLAN == 0) n.VLAN = BinaryPrimitives.ReadUInt16BigEndian(body);
                    break;
            }
        }
    }

    public static string FirstLine(string s)
    {
        var i = s.IndexOfAny(new[] { '\r', '\n' });
        if (i >= 0) return s[..i] + " …";
        if (s.Length > 120) return s[..120] + " …";
        return s;
    }

    public static List<LldpNeighbor> Sorted(Dictionary<string, LldpNeighbor> m) =>
        m.Values.OrderBy(n => n.Key, StringComparer.Ordinal).ToList();

    // ---- capture ----

    /// <summary>
    /// Opens a live capture on the chosen interface. Returns the list of interfaces as
    /// well, for -l. Throws <see cref="NoLiveCaptureException"/> on Windows, which has no
    /// built-in API for live layer-2 capture: pcap-style access requires an external
    /// driver (Npcap/WinPcap) this tool does not want to depend on, so the Windows route
    /// always goes through the built-in Packet Monitor (pktmon).
    /// </summary>
    public static (ICapturer? Cap, List<string> Devs, Exception? Err) Open(string hint)
    {
        if (OperatingSystem.IsLinux())
        {
            try { return LinuxCapture.Open(hint); }
            catch (Exception e) { return (null, LinuxCapture.List(), e); }
        }
        if (OperatingSystem.IsWindows()) return (null, new List<string>(), new NoLiveCaptureException());
        return (null, new List<string>(), new Exception("LLDP capture is not supported on this platform (Linux and Windows only)"));
    }

    /// <summary>
    /// Captures LLDP frames with the built-in Windows Packet Monitor. It simply records
    /// for the whole wait period, because LLDP is announced periodically and there is
    /// nothing to send ourselves.
    /// </summary>
    public static Dictionary<string, LldpNeighbor> PktmonCollect(TimeSpan wait)
    {
        if (wait <= TimeSpan.Zero) wait = TimeSpan.FromSeconds(35);
        var data = Pktmon.Capture("lldp", () =>
        {
            Thread.Sleep(wait);
            return true;
        }) ?? Array.Empty<byte>();
        var neighbors = new Dictionary<string, LldpNeighbor>();
        foreach (var frame in Pcapng.Parse(data))
        {
            if (Parse(frame) is { } nb)
            {
                nb.LocalIf = "pktmon";
                neighbors[nb.Key] = nb;
            }
        }
        return neighbors;
    }

    /// <summary>The console variant of the pktmon route: capture and display, looping with -m.</summary>
    static void TryPktmon(LldpOpts o)
    {
        if (Pktmon.Path() == null) throw new PktmonUnsupportedException();
        Console.WriteLine($"{Col(CBold, "nwtoolkit")}  using the built-in pktmon (Administrator required).");
        while (true)
        {
            Console.WriteLine(Col(CGrey, $"Capturing for {o.Wait.TotalSeconds.F(0)}s…"));
            var neighbors = PktmonCollect(o.Wait);
            if (neighbors.Count == 0)
            {
                Console.WriteLine(Col(CYellow, "No LLDP frames captured."));
                Console.WriteLine(Col(CGrey, "LLDP may be disabled on the switch, or it is an unmanaged switch."));
            }
            else
            {
                if (o.Monitor)
                {
                    Console.Write(ClrScr);
                    Console.WriteLine($"{Col(CBold, "nwtoolkit")}  LLDP monitor (pktmon)   {neighbors.Count} neighbour(s)   Ctrl+C to stop");
                }
                foreach (var n in Sorted(neighbors))
                {
                    Console.WriteLine();
                    n.PrintBlock();
                }
            }
            if (!o.Monitor) return;
        }
    }

    public static void Run(LldpOpts o)
    {
        var (cap, devs, err) = Open(o.Iface);
        if (o.List)
        {
            if (devs.Count == 0) Console.WriteLine("no interfaces found.");
            Console.WriteLine("Available interfaces:");
            foreach (var d in devs) Console.WriteLine("  " + d);
            cap?.Dispose();
            return;
        }
        if (err != null)
        {
            // No live capture? Use the built-in pktmon route (Windows).
            if (err is NoLiveCaptureException)
            {
                try
                {
                    TryPktmon(o);
                    return;
                }
                catch (PktmonUnsupportedException) { }
                catch (Exception e)
                {
                    Die(e.Message);
                    return;
                }
            }
            Die(err.Message);
            return;
        }
        using (cap)
        {
            Console.WriteLine($"{Col(CBold, "nwtoolkit")}  listening on {Col(CCyan, cap!.Device)} for LLDP frames…");
            Console.WriteLine(Col(CGrey, "LLDP is usually sent every 30 s, so this may take a while. Ctrl+C to stop."));

            using var ctrlC = new CtrlC();
            var neighbors = new Dictionary<string, LldpNeighbor>();
            var deadline = DateTime.UtcNow + o.Wait;

            while (true)
            {
                if (ctrlC.Pressed)
                {
                    Console.WriteLine($"\n{neighbors.Count} LLDP neighbour(s) seen.");
                    return;
                }
                if (!o.Monitor && DateTime.UtcNow > deadline && neighbors.Count == 0)
                {
                    Console.WriteLine(Col(CYellow, "\nNo LLDP frames received within the wait time."));
                    Console.WriteLine(Col(CGrey, "LLDP may be disabled on the switch, or it is an unmanaged switch. (On Windows: run as Administrator.)"));
                    return;
                }

                var frame = cap.Next(TimeSpan.FromSeconds(1));
                if (frame == null) continue;
                var nb = Parse(frame);
                if (nb == null) continue;
                nb.LocalIf = cap.Device;
                var existed = neighbors.ContainsKey(nb.Key);
                neighbors[nb.Key] = nb;

                if (o.Monitor)
                {
                    Console.Write(ClrScr);
                    Console.WriteLine($"{Col(CBold, "nwtoolkit")}  LLDP monitor   {neighbors.Count} neighbour(s)   Ctrl+C to stop");
                    foreach (var n in Sorted(neighbors))
                    {
                        Console.WriteLine();
                        n.PrintBlock();
                        Console.WriteLine($"  {"Last seen:",-16} {n.LastSeen:HH:mm:ss}");
                    }
                }
                else if (!existed)
                {
                    Console.WriteLine();
                    nb.PrintBlock();
                    return; // one-shot: stop as soon as we have a neighbour
                }
            }
        }
    }

    /// <summary>
    /// Captures LLDP neighbours until the first one is seen or wait elapses. Used by the
    /// GUI. Returns the neighbours and the device they were seen on.
    /// </summary>
    public static (List<LldpNeighbor> Neighbors, string Device) Once(string hint, TimeSpan wait)
    {
        var (cap, _, err) = Open(hint);
        if (err != null)
        {
            // No live capture? Fall back to the built-in pktmon (Windows, Administrator).
            if (err is NoLiveCaptureException)
            {
                try
                {
                    return (Sorted(PktmonCollect(wait)), "pktmon");
                }
                catch (PktmonUnsupportedException)
                {
                    throw err;
                }
            }
            throw err;
        }
        using (cap)
        {
            var neighbors = new Dictionary<string, LldpNeighbor>();
            var deadline = DateTime.UtcNow + wait;
            while (DateTime.UtcNow < deadline)
            {
                var frame = cap!.Next(TimeSpan.FromSeconds(1));
                if (frame != null && Parse(frame) is { } nb)
                {
                    nb.LocalIf = cap.Device;
                    neighbors[nb.Key] = nb;
                }
                if (neighbors.Count > 0 && DateTime.UtcNow + TimeSpan.FromSeconds(2) > deadline) break;
            }
            return (Sorted(neighbors), cap!.Device);
        }
    }
}

/// <summary>Live LLDP capture on Linux through an AF_PACKET socket bound to one interface (root required).</summary>
[SupportedOSPlatform("linux")]
public static class LinuxCapture
{
    /// <summary>sockaddr_ll for binding a packet socket to an interface.</summary>
    sealed class PacketEndPoint : EndPoint
    {
        readonly int ifIndex;
        readonly ushort protocol;
        public PacketEndPoint(int ifIndex, ushort protocol)
        {
            this.ifIndex = ifIndex;
            this.protocol = protocol;
        }
        public override AddressFamily AddressFamily => AddressFamily.Packet;
        public override SocketAddress Serialize()
        {
            // family(2) protocol(2, network order) ifindex(4, host order) hatype(2) pkttype(1) halen(1) addr(8)
            var sa = new SocketAddress(AddressFamily.Packet, 20);
            sa[2] = (byte)(protocol >> 8);
            sa[3] = (byte)protocol;
            var idx = BitConverter.GetBytes(ifIndex);
            for (var i = 0; i < 4; i++) sa[4 + i] = idx[i];
            return sa;
        }
        public override EndPoint Create(SocketAddress socketAddress) => this;
    }

    sealed class Capturer : ICapturer
    {
        readonly Socket sock;
        public string Device { get; }
        public Capturer(Socket sock, string device)
        {
            this.sock = sock;
            Device = device;
        }
        public byte[]? Next(TimeSpan timeout)
        {
            sock.ReceiveTimeout = Math.Max(1, (int)timeout.TotalMilliseconds);
            var buf = new byte[2048];
            try
            {
                var n = sock.Receive(buf);
                return n > 0 ? buf[..n] : null;
            }
            catch (SocketException)
            {
                return null;
            }
        }
        public void Dispose() => sock.Dispose();
    }

    static int IfIndex(string name)
    {
        try { return int.Parse(File.ReadAllText($"/sys/class/net/{name}/ifindex").Trim()); }
        catch { return -1; }
    }

    public static List<string> List()
    {
        var list = new List<string>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                list.Add(nic.Name + (nic.OperationalStatus == OperationalStatus.Up ? " (up)" : ""));
            }
        }
        catch { }
        return list;
    }

    static (NetworkInterface? Chosen, List<string> List) Pick(string hint)
    {
        var list = new List<string>();
        NetworkInterface? chosen = null;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            var up = nic.OperationalStatus == OperationalStatus.Up;
            list.Add(nic.Name + (up ? " (up)" : ""));
            if (hint != "")
            {
                if (nic.Name == hint) chosen = nic;
                continue;
            }
            if (chosen == null && up && nic.GetIPProperties().UnicastAddresses.Count > 0) chosen = nic;
        }
        return (chosen, list);
    }

    public static (ICapturer? Cap, List<string> Devs, Exception? Err) Open(string hint)
    {
        var (nic, list) = Pick(hint);
        if (nic == null) return (null, list, new Exception("no suitable interface found; pick one with -i <name> (see -l)"));
        var idx = IfIndex(nic.Name);
        if (idx < 0) return (null, list, new Exception($"cannot determine the index of {nic.Name}"));
        var proto = (ushort)(((Lldp.EtherType & 0xff) << 8) | (Lldp.EtherType >> 8)); // htons
        Socket sock;
        try
        {
            sock = new Socket(AddressFamily.Packet, SocketType.Raw, (ProtocolType)proto);
        }
        catch (SocketException e)
        {
            return (null, list, new Exception($"opening raw socket (root required): {e.Message}"));
        }
        try
        {
            sock.Bind(new PacketEndPoint(idx, Lldp.EtherType));
        }
        catch (SocketException e)
        {
            sock.Dispose();
            return (null, list, new Exception($"bind on {nic.Name}: {e.Message}"));
        }
        return (new Capturer(sock, nic.Name), list, null);
    }
}

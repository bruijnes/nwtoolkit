using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
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

public sealed class LldpOpts
{
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

    /// <summary>The network interfaces, for `lldp -l`; pktmon captures on all of them at once.</summary>
    public static List<string> Interfaces()
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

    /// <summary>
    /// Captures LLDP frames with the built-in Windows Packet Monitor. It simply records
    /// for the whole wait period, because LLDP is announced periodically and there is
    /// nothing to send ourselves. Windows has no built-in API for live layer-2 capture
    /// (that needs Npcap or another driver), so pktmon is the only route this tool uses.
    /// </summary>
    public static Dictionary<string, LldpNeighbor> Collect(TimeSpan wait)
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

    public static void Run(LldpOpts o)
    {
        if (o.List)
        {
            var devs = Interfaces();
            Console.WriteLine(devs.Count == 0 ? "no interfaces found." : "Available interfaces:");
            foreach (var d in devs) Console.WriteLine("  " + d);
            return;
        }
        if (Pktmon.Path() == null)
        {
            Die("LLDP capture uses the built-in Packet Monitor (pktmon), which is only available on Windows 10 and later");
            return;
        }
        Console.WriteLine($"{Col(CBold, "nwtoolkit")}  using the built-in pktmon (Administrator required).");
        while (true)
        {
            Console.WriteLine(Col(CGrey, $"Capturing for {o.Wait.TotalSeconds.F(0)}s\u2026"));
            Dictionary<string, LldpNeighbor> neighbors;
            try { neighbors = Collect(o.Wait); }
            catch (Exception e)
            {
                Die(e.Message);
                return;
            }
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

    /// <summary>One capture for the GUI: the neighbours seen within the wait time.</summary>
    public static List<LldpNeighbor> Once(TimeSpan wait)
    {
        if (Pktmon.Path() == null) throw new PktmonUnsupportedException();
        return Sorted(Collect(wait));
    }
}

using System.Buffers.Binary;

namespace Nwtoolkit;

/// <summary>A captured frame with a timestamp in nanoseconds since the epoch.</summary>
public readonly record struct PcapFrame(long TsNanos, byte[] Data);

/// <summary>Reads the pcapng files that pktmon writes: little-endian, Enhanced and Simple Packet Blocks.</summary>
public static class Pcapng
{
    static long Pow10(int n)
    {
        long r = 1;
        for (var i = 0; i < n; i++) r *= 10;
        return r;
    }

    /// <summary>
    /// Extracts frames with per-packet timestamps, honouring the per-interface
    /// if_tsresol option (microseconds by default).
    /// </summary>
    public static List<PcapFrame> ParseWithTimestamps(ReadOnlySpan<byte> data)
    {
        var nanosPerTick = new List<long>(); // per interface index
        var out_ = new List<PcapFrame>();
        var i = 0;
        while (i + 8 <= data.Length)
        {
            var btype = BinaryPrimitives.ReadUInt32LittleEndian(data[i..]);
            var blen = (int)BinaryPrimitives.ReadUInt32LittleEndian(data[(i + 4)..]);
            if (blen < 12 || i + blen > data.Length) break;
            var body = data.Slice(i + 8, blen - 12);
            switch (btype)
            {
                case 0x00000001: // Interface Description Block
                {
                    long npt = 1000; // default: microseconds → 1000 ns/tick
                    if (body.Length >= 8)
                    {
                        var opts = body[8..];
                        while (opts.Length >= 4)
                        {
                            var code = BinaryPrimitives.ReadUInt16LittleEndian(opts);
                            int l = BinaryPrimitives.ReadUInt16LittleEndian(opts[2..]);
                            if (code == 0 || 4 + l > opts.Length) break;
                            if (code == 9 && l >= 1)
                            {
                                var r = opts[4];
                                npt = (r & 0x80) == 0 ? Pow10(9 - r) : 1000000000L >> (r & 0x7f);
                                if (npt < 1) npt = 1;
                            }
                            opts = opts[(4 + ((l + 3) & ~3))..];
                        }
                    }
                    nanosPerTick.Add(npt);
                    break;
                }
                case 0x00000006: // Enhanced Packet Block
                {
                    if (body.Length >= 20)
                    {
                        var ifi = (int)BinaryPrimitives.ReadUInt32LittleEndian(body);
                        var tsHigh = (ulong)BinaryPrimitives.ReadUInt32LittleEndian(body[4..]);
                        var tsLow = (ulong)BinaryPrimitives.ReadUInt32LittleEndian(body[8..]);
                        var capLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(body[12..]);
                        if (capLen >= 0 && 20 + capLen <= body.Length)
                        {
                            long npt = 1000;
                            if (ifi >= 0 && ifi < nanosPerTick.Count) npt = nanosPerTick[ifi];
                            var frame = body.Slice(20, capLen).ToArray();
                            out_.Add(new PcapFrame((long)(tsHigh << 32 | tsLow) * npt, frame));
                        }
                    }
                    break;
                }
            }
            i += blen;
        }
        return out_;
    }

    /// <summary>Link type of the blocks this tool writes: raw IP, no link layer (LINKTYPE_RAW).</summary>
    public const ushort LinkTypeRaw = 101;

    /// <summary>Extracts the raw packet frames from a pcapng file, as pktmon writes it.</summary>
    public static List<byte[]> Parse(ReadOnlySpan<byte> data)
    {
        var frames = new List<byte[]>();
        var i = 0;
        while (i + 8 <= data.Length)
        {
            var btype = BinaryPrimitives.ReadUInt32LittleEndian(data[i..]);
            var blen = (int)BinaryPrimitives.ReadUInt32LittleEndian(data[(i + 4)..]);
            if (blen < 12 || i + blen > data.Length) break;
            var body = data.Slice(i + 8, blen - 12);
            switch (btype)
            {
                case 0x00000006: // Enhanced Packet Block: interface(4) tsHigh(4) tsLow(4) capLen(4) origLen(4) data...
                    if (body.Length >= 20)
                    {
                        var capLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(body[12..]);
                        if (capLen >= 0 && 20 + capLen <= body.Length) frames.Add(body.Slice(20, capLen).ToArray());
                    }
                    break;
                case 0x00000003: // Simple Packet Block: origLen(4) data...
                    if (body.Length >= 4)
                    {
                        var origLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(body);
                        if (origLen >= 0 && 4 + origLen <= body.Length) frames.Add(body.Slice(4, origLen).ToArray());
                    }
                    break;
            }
            i += blen;
        }
        return frames;
    }
}

/// <summary>
/// Writes a pcapng file that Wireshark opens. The capture records raw IP packets without
/// a link layer, so the file declares LINKTYPE_RAW and holds one Enhanced Packet Block per
/// packet, with microsecond timestamps (pcapng's default resolution, so no if_tsresol
/// option is needed).
/// </summary>
public sealed class PcapngWriter : IDisposable
{
    const uint BlockShb = 0x0a0d0d0a, BlockIdb = 1, BlockEpb = 6;
    const int SnapLen = 65535;

    readonly FileStream file;
    readonly byte[] head = new byte[32];

    public PcapngWriter(string path, string ifName)
    {
        file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
        WriteSectionHeader();
        WriteInterfaceDescription(ifName);
    }

    /// <summary>Appends one packet, timestamped in microseconds since the Unix epoch.</summary>
    public void Write(DateTime time, ReadOnlySpan<byte> packet)
    {
        var usec = (ulong)(time.ToUniversalTime() - DateTime.UnixEpoch).Ticks / 10;
        var pad = (4 - (packet.Length & 3)) & 3;
        var total = 32 + packet.Length + pad;
        var h = head.AsSpan();
        Put(h, 0, BlockEpb);
        Put(h, 4, (uint)total);
        Put(h, 8, 0);                          // interface 0
        Put(h, 12, (uint)(usec >> 32));        // timestamp, high half
        Put(h, 16, (uint)usec);                // timestamp, low half
        Put(h, 20, (uint)packet.Length);       // captured length
        Put(h, 24, (uint)packet.Length);       // original length
        file.Write(h[..28]);
        file.Write(packet);
        if (pad > 0) file.Write(stackalloc byte[pad]);
        Put(h, 0, (uint)total);
        file.Write(h[..4]);                    // trailing block length
    }

    void WriteSectionHeader()
    {
        var h = head.AsSpan();
        Put(h, 0, BlockShb);
        Put(h, 4, 28);
        Put(h, 8, 0x1a2b3c4d);                 // byte-order magic: little endian
        Put(h, 12, 1);                         // version: major 1, minor 0 (two 16-bit fields)
        Put(h, 16, 0xffffffff);                // section length: unknown
        Put(h, 20, 0xffffffff);
        Put(h, 24, 28);
        file.Write(h[..28]);
    }

    void WriteInterfaceDescription(string ifName)
    {
        var name = System.Text.Encoding.UTF8.GetBytes(ifName);
        if (name.Length > 250) name = name[..250];
        var pad = (4 - (name.Length & 3)) & 3;
        var total = 16 + 4 + name.Length + pad + 4 + 4; // fixed part, if_name option, opt_endofopt, trailing length
        var h = head.AsSpan();
        Put(h, 0, BlockIdb);
        Put(h, 4, (uint)total);
        Put(h, 8, Pcapng.LinkTypeRaw);         // link type (16 bit) + reserved (16 bit)
        Put(h, 12, SnapLen);
        Put(h, 16, (uint)(name.Length << 16 | 2)); // option if_name (code 2) and its length
        file.Write(h[..20]);
        file.Write(name);
        if (pad > 0) file.Write(stackalloc byte[pad]);
        Put(h, 0, 0);                          // opt_endofopt
        Put(h, 4, (uint)total);
        file.Write(h[..8]);
    }

    static void Put(Span<byte> b, int off, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b[off..], v);

    public void Dispose() => file.Dispose();
}

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
